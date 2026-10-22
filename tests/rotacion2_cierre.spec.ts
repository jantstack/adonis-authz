/**
 * **Cierre de la rotación 2 de M4** (perspectiva «multi-tenant hostil»; `rotacion-2-auditor.md`, firmas del dueño
 * 2026-10-22 «(rotación 2 · cierre)»). Cada repro de `.claude/reproducciones/rotacion-2.spec.ts` —que afirmaba el
 * DEFECTO publicado en 2.5.0-alpha.4— pasa aquí a TEST del comportamiento CORRECTO; la versión «defecto» es el rojo
 * que demostró cada arreglo (informe `rotacion-2-cierre-informe.md`).
 *
 * Los casos de motor (MySQL R2-01, PG control) solo se REGISTRAN en su motor y sueltan todo cerrojo en `finally`:
 * la repro R2-01a original se colgaba en pg (un lease que nadie soltaba retenía una conexión y el `teardown` no podía
 * borrar la base).
 *
 * Los casos «límite declarado rotación 2 · …: se voltea en 2.6» caracterizan lo que se DECLARA y no se arregla en
 * 2.5.x (README «Limits»): si alguien lo arregla sin reescribir la fila, el caso se pone rojo.
 *
 * **Cierre 2** (firmas «(rotación 2 · cierre 2)», `rotacion-2-cierre-{auditor,tester}.md`, informe
 * `rotacion-2-cierre2-informe.md`): los casos `T-0N` del tester (los tres que dejó escritos van marcados `TESTER`) y
 * la repro del auditor del cierre (`.claude/reproducciones/rotacion-2-cierre-auditor.spec.ts`) pasada a test — A
 * (RC2-A) y B (RC2-B) afirman lo correcto; C (RC2-C) y D (RC2-D = T-08) caracterizan los huecos declarados.
 */
import { test } from '@japa/runner'
import { readFileSync } from 'node:fs'
import db from '@adonisjs/lucid/services/db'
import { v7 as uuidv7 } from 'uuid'
import { aceFor } from './helpers/ace.js'
import { openScratchDatabase, testEngine } from './helpers/app.js'
import { cleanAuthzTables, cleanScopeOutbox } from './helpers/schema.js'
import authorization from '../services/main.js'
import { AuthorizationManager } from '../src/manager.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { syncAuthzCatalog } from '../src/catalog/catalog.js'
import { CatalogCache, withAuthzCatalogWrite } from '../src/catalog/catalog_cache.js'
import {
  SCOPE_OUTBOX_TAKES_UNSCOPED_LOCK,
  SCOPE_OUTBOX_UNSCOPED_LOCK_RETIRED_IN,
  scopeOutboxLockNames,
  sqlScopeOutbox,
} from '../src/scope_outbox.js'
import { diffAuthzCatalog } from '../src/catalog/catalog.js'
import { descendantsFrom, memoryScopeTree, resolveChainFrom } from '../src/testing/main.js'
import type { ContractScopeTree } from '../src/testing/main.js'
import { APP_SCOPE } from '../src/types.js'
import type { ScopeRef } from '../src/types.js'
import AuthzScopesRelay from '../commands/authz_scopes_relay.js'
import { requeueLines } from '../commands/authz_scopes_requeue.js'
import AuthzCatalogPruneOrphans, { massPurgeLetter } from '../commands/authz_catalog_prune_orphans.js'

const ROOT = new URL('../', import.meta.url)
const read = (file: string) => readFileSync(new URL(file, ROOT), 'utf8')

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

async function caught(fn: () => Promise<unknown>): Promise<any> {
  try {
    await fn()
  } catch (error) {
    return error
  }
  return undefined
}

/** `a < b` para versiones `x.y.z[-pre.n]` (lo justo para atar la transición a la versión). */
function isVersionBefore(a: string, b: string): boolean {
  const parse = (v: string) => {
    const [base, pre] = v.split('-')
    const nums = base.split('.').map(Number)
    return [...nums, pre ? Number(pre.replace(/^[a-z]+\./, '')) : Number.POSITIVE_INFINITY]
  }
  const [x, y] = [parse(a), parse(b)]
  for (let i = 0; i < 4; i++) if (x[i] !== y[i]) return x[i] < y[i]
  return false
}

const DELEGABLE = ['docs:read', 'docs:write']

const CATALOG = {
  permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }],
  roles: [
    { slug: 'org-admin', scopeType: 'organization', rank: 50, permissions: DELEGABLE },
    { slug: 'unit-editor', scopeType: 'unit', permissions: ['docs:write'] },
    { slug: 'superadmin', scopeType: 'app', rank: 100, permissions: DELEGABLE },
  ],
}

/**
 * El nombre del lease de MySQL que calculaba **2.5.0-alpha.4** (`git show dcf41f5:src/scope_outbox.ts`, `current` =
 * `'authz_scope_outbox:' + sha1('authz_scope_outbox:default:authz_scope_outbox')`) con la conexión por defecto y la tabla
 * del stub — LITERAL, no derivado de la función actual (cierre 2 · T-01: derivarlo dejaba vivo el mutante que cambia el
 * nombre viejo, y con él un despliegue rodante desde alpha.4 tendría DOS escritores).
 */
const ALPHA4_DEFAULT_LOCK = 'authz_scope_outbox:7f6b667c94d593fb9bf52aed99b54cceb9691f70'

/** Tres tenants (organizations) bajo `app`, cada uno con su org-admin (la siembra de la repro). */
async function threeTenants() {
  await cleanAuthzTables()
  await syncAuthzCatalog(CATALOG as any)
  const orgA: ScopeRef = { type: 'organization', uuid: uuidv7() }
  const orgB: ScopeRef = { type: 'organization', uuid: uuidv7() }
  const orgC: ScopeRef = { type: 'organization', uuid: uuidv7() }
  const unitA1: ScopeRef = { type: 'unit', uuid: uuidv7() }
  const unitB1: ScopeRef = { type: 'unit', uuid: uuidv7() }
  const unitB1x: ScopeRef = { type: 'unit', uuid: uuidv7() }
  const tree: ContractScopeTree = memoryScopeTree()
  await tree.attach(orgA, APP_SCOPE)
  await tree.attach(orgB, APP_SCOPE)
  await tree.attach(orgC, APP_SCOPE)
  await tree.attach(unitA1, orgA)
  await tree.attach(unitB1, orgB)
  await tree.attach(unitB1x, unitB1)
  const adminA = { type: 'users', uuid: uuidv7() }
  const adminB = { type: 'users', uuid: uuidv7() }
  const adminC = { type: 'users', uuid: uuidv7() }
  const seed = new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) })
  await seed.grant(adminA, 'org-admin', orgA)
  await seed.grant(adminB, 'org-admin', orgB)
  await seed.grant(adminC, 'org-admin', orgC)
  return { orgA, orgB, orgC, unitA1, unitB1, unitB1x, tree, adminA, adminB, adminC }
}

function managerOver(
  resolveChain: (scope: ScopeRef) => Promise<ScopeRef[] | null>,
  descendantsOf: any,
  extra: Record<string, unknown> = {},
  driverPatch?: (driver: any) => void
) {
  return new AuthorizationManager({
    default: 'database',
    drivers: {
      database: () => {
        const driver: any = new DatabaseAuthorizationDriver({ resolveChain })
        driverPatch?.(driver)
        return driver
      },
    },
    scopes: { resolveChain, descendantsOf },
    delegablePermissions: DELEGABLE,
    warnOnOptInSecurity: false,
    ...extra,
  } as any)
}

/** Inserta roles locales «a mano» por la vía de escritura publicada (sube la versión del catálogo). */
async function insertLocalRoles(owner: ScopeRef, slugs: string[]): Promise<string[]> {
  const uuids: string[] = []
  await withAuthzCatalogWrite(async (trx) => {
    const perm: any = (await trx.from('authz_permissions').where('slug', 'docs:read').select('uuid'))[0]
    const now = new Date()
    for (const slug of slugs) {
      const uuid = uuidv7()
      uuids.push(uuid)
      await trx.table('authz_roles').insert({
        uuid, slug, name: slug, scope_type: 'organization', rank: 1,
        owner_scope_key: `${owner.type}|${owner.uuid}`, created_at: now, updated_at: now,
      })
      await trx.table('authz_role_permissions').insert({ uuid: uuidv7(), role_uuid: uuid, permission_uuid: perm.uuid, created_at: now })
    }
  })
  return uuids
}

// ---------------------------------------------------------------------------------------------------------------------
// R2-01 · el lease del relay lleva la identidad de la BASE (MySQL); transición con el nombre viejo en 2.5.x.
// ---------------------------------------------------------------------------------------------------------------------
test.group('rotación 2 · R2-01 · el lease del relay lleva la base (compartido: relay/outbox)', (group) => {
  const restores: Array<() => void> = []
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
    return async () => {
      while (restores.length) restores.pop()!()
      await cleanScopeOutbox(db)
    }
  })

  test('R2-01a · el nombre NUEVO separa bases (y no separa la misma base escrita con otras mayúsculas); el viejo, sin base, es el de 2.5.0-alpha.4; los dos caben en 64', ({ assert }) => {
    const a = scopeOutboxLockNames('mysql', 'authz_scope_outbox', 'app_a')
    const b = scopeOutboxLockNames('mysql', 'authz_scope_outbox', 'app_b')
    assert.notEqual(a.current, b.current, 'dos despliegues en BASES distintas del mismo servidor: dos nombres')
    assert.equal(a.unscoped, b.unscoped, 'el nombre de transición (sin base) es común: es el precio declarado de 2.5.x')
    assert.notEqual(a.current, a.unscoped)
    assert.equal(a.current, scopeOutboxLockNames('mysql', 'authz_scope_outbox', 'APP_A').current, 'minúsculas: el error barato (compartir) y no el caro (dos escritores)')
    assert.equal(a.unscoped, scopeOutboxLockNames('mysql', 'authz_scope_outbox').current, 'sin base, `current` es el nombre de 2.4.0-alpha.5..2.5.0-alpha.4')
    assert.equal(scopeOutboxLockNames('mysql', 'authz_scope_outbox', null).current, scopeOutboxLockNames('mysql', 'authz_scope_outbox', null).current, 'DATABASE() NULL es estable')
    assert.notEqual(scopeOutboxLockNames('mysql', 'authz_scope_outbox', null).current, a.unscoped)
    for (const name of [a.current, a.unscoped]) assert.isAtMost(name.length, 64)
    // TESTER (T-01): el literal de 2.5.0-alpha.4 (dcf41f5), no derivado; sea cual sea la base de la sesión.
    assert.equal(scopeOutboxLockNames(undefined, 'authz_scope_outbox', 'cualquiera').unscoped, ALPHA4_DEFAULT_LOCK, 'TESTER: el literal de 2.5.0-alpha.4 (dcf41f5), no derivado')
    assert.equal(scopeOutboxLockNames(undefined, 'authz_scope_outbox', null).unscoped, ALPHA4_DEFAULT_LOCK)
  })

  test('R2-01 · la transición está atada a la versión: SCOPE_OUTBOX_TAKES_UNSCOPED_LOCK vale exactamente «package.json < SCOPE_OUTBOX_UNSCOPED_LOCK_RETIRED_IN» (2.6.0-alpha.0: toda 2.6)', ({ assert }) => {
    const { version } = JSON.parse(read('package.json'))
    const transition = isVersionBefore(version, SCOPE_OUTBOX_UNSCOPED_LOCK_RETIRED_IN)
    assert.equal(
      SCOPE_OUTBOX_TAKES_UNSCOPED_LOCK,
      transition,
      transition
        ? `package.json es ${version} < ${SCOPE_OUTBOX_UNSCOPED_LOCK_RETIRED_IN}: en 2.5.x se toman el nombre viejo Y el nuevo.`
        : `package.json es ${version}: la transición terminó. Pon SCOPE_OUTBOX_TAKES_UNSCOPED_LOCK = false, voltea la fila R2-01 de Limits y el caso MySQL «límite declarado rotación 2 · R2-01 …», y anótalo en el CHANGELOG.`
    )
    // Toda 2.6 la retira, sus prereleases incluidas.
    assert.equal(SCOPE_OUTBOX_UNSCOPED_LOCK_RETIRED_IN, '2.6.0-alpha.0')
    assert.isTrue(isVersionBefore('2.5.0-alpha.4', SCOPE_OUTBOX_UNSCOPED_LOCK_RETIRED_IN))
    assert.isTrue(isVersionBefore('2.5.0-rc.1', SCOPE_OUTBOX_UNSCOPED_LOCK_RETIRED_IN))
    assert.isTrue(isVersionBefore('2.5.9', SCOPE_OUTBOX_UNSCOPED_LOCK_RETIRED_IN))
    assert.isFalse(isVersionBefore('2.6.0-alpha.0', SCOPE_OUTBOX_UNSCOPED_LOCK_RETIRED_IN))
    assert.isFalse(isVersionBefore('2.6.0-alpha.1', SCOPE_OUTBOX_UNSCOPED_LOCK_RETIRED_IN))
    assert.isFalse(isVersionBefore('2.6.0', SCOPE_OUTBOX_UNSCOPED_LOCK_RETIRED_IN))
  })

  test('R2-01b · `authz:scopes:relay` con el lease tomado por OTRO sigue saliendo 0 (respuesta del dueño, cierre 2) y la línea DICE que puede ser otro despliegue del mismo servidor y nombra --max-age', async ({ assert }) => {
    const tree = memoryScopeTree()
    const unit: ScopeRef = { type: 'unit', uuid: uuidv7() }
    await tree.attach(unit, APP_SCOPE)
    const outbox = sqlScopeOutbox({ requireTransaction: false })
    let purges = 0
    const manager = new AuthorizationManager({
      default: 'spy',
      drivers: { spy: () => ({ authorize: async () => false, purgeScope: async () => void purges++ }) as any },
      scopes: { resolveChain: resolveChainFrom(tree), outbox },
      warnOnOptInSecurity: false,
    } as any)
    await outbox.enqueue({ op: 'detached', child: unit }, {} as any)
    const foreign = await outbox.acquire!()
    try {
      restores.push(patchManager('relayScopeChanges', (o: any) => manager.relayScopeChanges(o)))
      const run = await (await aceFor(AuthzScopesRelay)).exec([])
      assert.isUndefined(run.error, String(run.error?.message))
      // T-05 (cierre 2): «sale 0» es lo que dicen la fila de Limits y el CHANGELOG, y lo que el dueño respondió (la línea +
      // `--max-age`); `notEqual(…, 1)` dejaba vivo un exit 2. Si algún día cambia, ESTE es el caso que se voltea.
      assert.oneOf(run.exitCode, [undefined, 0], 'exit de `busy`: 0 (respuesta del dueño, cierre 2)')
      assert.equal(purges, 0)
      const line = run.logs.find((l) => l.includes('Otra pasada del relay tiene el lease'))
      assert.exists(line, JSON.stringify(run.logs))
      assert.include(line!, 'OTRO despliegue del mismo servidor')
      assert.include(line!, '--max-age')
    } finally {
      await foreign?.release()
    }
    // Gemelo: `requeue --apply` con `busy` (exit ≠ 0 desde alpha.8) dice lo mismo.
    const requeue = requeueLines({ report: { relay: { busy: true } } as any })
    assert.isFalse(requeue.clean)
    assert.include(requeue.lines.map((l) => l.message).join('\n'), 'OTRO despliegue del mismo servidor')
  })

  if (testEngine() === 'mysql') {
    const firstValue = (result: any, column: string) => {
      const rows = Array.isArray(result) ? result[0] : (result?.rows ?? result)
      const row = Array.isArray(rows) ? rows[0] : rows
      return row?.[column]
    }
    const holderOf = async (name: string) => firstValue(await db.rawQuery('select is_used_lock(?) as holder', [name]), 'holder')
    const ourDatabase = async () => String(firstValue(await db.rawQuery('select database() as db'), 'db'))
    /** Una sesión propia que toma `names` con GET_LOCK y los suelta al final (pase lo que pase). */
    const withSession = async (client: any, names: string[], body: () => Promise<void>) => {
      const trx = await client.transaction()
      const taken: string[] = []
      try {
        for (const name of names) {
          if (Number(firstValue(await trx.rawQuery('select get_lock(?, 0) as taken', [name]), 'taken')) === 1) taken.push(name)
        }
        must(taken.length === names.length, 'la sesión de prueba no pudo tomar sus cerrojos')
        await body()
      } finally {
        for (const name of taken.reverse()) await trx.rawQuery('select release_lock(?)', [name]).catch(() => {})
        await trx.rollback().catch(() => {})
      }
    }
    function must(condition: boolean, message: string): asserts condition {
      if (!condition) throw new Error(message)
    }

    test('MySQL · acquire() toma el nombre VIEJO (sin base) y el NUEVO (con DATABASE()) y suelta los dos', async ({ assert }) => {
      const names = scopeOutboxLockNames(undefined, 'authz_scope_outbox', await ourDatabase())
      const outbox = sqlScopeOutbox({ requireTransaction: false })
      const lease = await outbox.acquire!()
      try {
        assert.isNotNull(lease)
        assert.isNotNull(await holderOf(names.unscoped), 'el viejo (transición 2.5.x)')
        assert.isNotNull(await holderOf(names.current), 'el nuevo, con la base')
        assert.isNull(await holderOf(names.legacy), 'el recortado de ≤ alpha.4 sigue retirado')
        assert.isNull(await outbox.acquire!(), 'una segunda pasada es busy')
      } finally {
        await lease?.release()
      }
      assert.isNull(await holderOf(names.unscoped), 'soltado')
      assert.isNull(await holderOf(names.current), 'soltado')
    })

    test('MySQL · un proceso de 2.5.0-alpha.4 (solo el nombre viejo) sigue excluyendo al nuevo, y el nuevo no se queda con medio lease', async ({ assert }) => {
      const names = scopeOutboxLockNames(undefined, 'authz_scope_outbox', await ourDatabase())
      const outbox = sqlScopeOutbox({ requireTransaction: false })
      // T-01 (cierre 2): el proceso de alpha.4 toma el nombre LITERAL que calculaba alpha.4, no el que calcula hoy la función.
      await withSession(db, [ALPHA4_DEFAULT_LOCK], async () => {
        const lease = await outbox.acquire!()
        try {
          assert.isNull(lease, 'busy: el alpha.4 tiene el viejo')
        } finally {
          await lease?.release()
        }
        assert.isNull(await holderOf(names.current), 'no tomó el nuevo')
      })
    })

    test('MySQL · si el NUEVO está tomado, acquire() suelta el viejo que ya tenía (sin fugas de cerrojo)', async ({ assert }) => {
      const names = scopeOutboxLockNames(undefined, 'authz_scope_outbox', await ourDatabase())
      const outbox = sqlScopeOutbox({ requireTransaction: false })
      await withSession(db, [names.current], async () => {
        const lease = await outbox.acquire!()
        try {
          assert.isNull(lease)
        } finally {
          await lease?.release()
        }
        assert.isNull(await holderOf(names.unscoped), 'el viejo se soltó al fallar el segundo')
      })
      const after = await outbox.acquire!()
      try {
        assert.isNotNull(after, 'nada quedó colgado: la siguiente pasada entra')
      } finally {
        await after?.release()
      }
    })

    /**
     * T-04 (cierre 2): «un error a mitad suelta lo tomado». No hay forma limpia de hacer fallar un `GET_LOCK` en un MySQL
     * real, así que la sesión es REAL y solo la consulta se dobla: `acquire()` recibe un `db` cuyo `transaction()` abre la
     * transacción de verdad (la sesión que sostiene el cerrojo) y devuelve un Proxy cuyo `rawQuery` lanza en el SEGUNDO
     * `get_lock`. Lo observable es del servidor: tras el rechazo, `IS_USED_LOCK` del nombre viejo (el primero tomado) es
     * NULL. Mutante M8 (el `catch` no llama a `releaseAll`) ⇒ el cerrojo queda en la sesión ⇒ rojo. Todo se suelta en
     * `finally` pase lo que pase (`GET_LOCK` es de sesión: un caso que fallara no puede dejar la base colgada).
     */
    test('MySQL · T-04 · un error entre los dos GET_LOCK suelta lo ya tomado (la conexión no vuelve al pool con el cerrojo)', async ({ assert }) => {
      const names = scopeOutboxLockNames(undefined, 'authz_scope_outbox', await ourDatabase())
      const primary: any = (db as any).connection()
      let realTrx: any
      let getLocks = 0
      const fakeDb: any = {
        dialect: primary.dialect,
        transaction: async () => {
          realTrx = await primary.transaction()
          return new Proxy(realTrx, {
            get(target, prop, receiver) {
              if (prop === 'rawQuery') {
                return (sql: string, bindings?: unknown[]) => {
                  if (/get_lock/i.test(sql) && ++getLocks === 2) return Promise.reject(new Error('T-04: la red se cae entre los dos GET_LOCK'))
                  return target.rawQuery(sql, bindings)
                }
              }
              const value = Reflect.get(target, prop, receiver)
              return typeof value === 'function' ? value.bind(target) : value
            },
          })
        },
      }
      try {
        const error = await caught(() => sqlScopeOutbox({ requireTransaction: false }, fakeDb).acquire!())
        assert.exists(error, 'acquire() propaga el fallo (no devuelve un lease de mentira)')
        assert.equal(getLocks, 2, 'el fallo fue en el SEGUNDO GET_LOCK, con el primero ya tomado')
        assert.isNull(await holderOf(names.unscoped), 'el primero se soltó')
        assert.isNull(await holderOf(names.current))
      } finally {
        for (const name of [names.unscoped, names.current]) await realTrx?.rawQuery('select release_lock(?)', [name]).catch(() => {})
        await realTrx?.rollback().catch(() => {})
        // Si el caso FALLA (el defecto: la trx se revirtió y la conexión volvió al pool con el cerrojo), ya no hay sesión
        // propia desde la que soltarlo: se mata la conexión que lo sostiene para no contaminar los casos siguientes.
        for (const name of [names.unscoped, names.current]) {
          const holder = await holderOf(name)
          if (holder !== null && holder !== undefined) await db.rawQuery(`kill ${Number(holder)}`).catch(() => {})
        }
      }
      const after = await sqlScopeOutbox({ requireTransaction: false }).acquire!()
      try {
        assert.isNotNull(after, 'nada quedó colgado: la siguiente pasada entra')
      } finally {
        await after?.release()
      }
    })

    test('MySQL · R2-01c invertido: el nombre NUEVO de un despliegue en OTRA base del mismo servidor no bloquea el nuestro', async ({ assert }) => {
      const scratch = await openScratchDatabase()
      try {
        const neighbour = scopeOutboxLockNames(undefined, 'authz_scope_outbox', scratch.database)
        const ours = scopeOutboxLockNames(undefined, 'authz_scope_outbox', await ourDatabase())
        assert.notEqual(neighbour.current, ours.current)
        await withSession(scratch.db as any, [neighbour.current], async () => {
          const lease = await sqlScopeOutbox({ requireTransaction: false }).acquire!()
          try {
            assert.isNotNull(lease, 'solo el nombre con base del vecino: no nos toca')
          } finally {
            await lease?.release()
          }
        })
      } finally {
        await scratch.drop()
      }
    })

    test('límite declarado rotación 2 · R2-01 MySQL: el nombre de transición sigue excluyendo a dos bases del mismo servidor; se voltea en 2.6', async ({ assert }) => {
      const scratch = await openScratchDatabase()
      try {
        const neighbour = sqlScopeOutbox({ requireTransaction: false }, scratch.db as any)
        const held = await neighbour.acquire!()
        try {
          assert.isNotNull(held, 'el vecino toma SU lease, sobre SU base')
          const ours = await sqlScopeOutbox({ requireTransaction: false }).acquire!()
          try {
            assert.isNull(ours, 'PRECIO DECLARADO (2.5.x): los dos toman el nombre viejo, sin base ⇒ busy')
          } finally {
            await ours?.release()
          }
        } finally {
          await held?.release()
        }
        const after = await sqlScopeOutbox({ requireTransaction: false }).acquire!()
        try {
          assert.isNotNull(after, 'control: suelto el del vecino, entra')
        } finally {
          await after?.release()
        }
      } finally {
        await scratch.drop()
      }
    })
  }

  if (testEngine() === 'pg') {
    test('PG · R2-01d control: el advisory lock es POR BASE: un despliegue en otra base no bloquea el nuestro (no cambia)', async ({ assert }) => {
      const scratch = await openScratchDatabase()
      try {
        const held = await sqlScopeOutbox({ requireTransaction: false }, scratch.db as any).acquire!()
        try {
          assert.isNotNull(held)
          const mine = await sqlScopeOutbox({ requireTransaction: false }).acquire!()
          try {
            assert.isNotNull(mine, 'en PG dos bases no comparten advisory lock')
          } finally {
            await mine?.release()
          }
        } finally {
          await held?.release()
        }
      } finally {
        await scratch.drop()
      }
    })
  }
})

// ---------------------------------------------------------------------------------------------------------------------
// R2-02 · prune-orphans: tercer disparador del seguro (más de un owner y alguno concede o no se sabe).
// ---------------------------------------------------------------------------------------------------------------------
test.group('rotación 2 · R2-02 · prune-orphans: huérfanos de > 1 owner que conceden (compartido: manager/catálogo)', () => {
  test('R2-02 · resolutor filtrado al tenant A + A con > 50 % de los roles locales ⇒ el dry-run lo MARCA (granting-across-owners), --force es 500 sin borrar nada y sin uuids ajenos; con allowMassPurge purga', async ({ assert }) => {
    const t = await threeTenants()
    const full = resolveChainFrom(t.tree)
    const normal = managerOver(full, descendantsFrom(t.tree))
    const spec = (slug: string) => ({ slug, scopeType: 'organization', rank: 10, permissions: ['docs:read'] })
    const b1 = await normal.defineScopedRole(t.adminB, t.orgB, spec('b-lead'), { within: t.orgB })
    await normal.defineScopedRole(t.adminC, t.orgC, spec('c-lead'), { within: t.orgC })
    await normal.defineScopedRole(t.adminA, t.orgA, spec('a-1'), { within: t.orgA })
    const bob = { type: 'users', uuid: uuidv7() }
    await normal.grant(bob, { uuid: b1.uuid }, t.orgB, { within: t.orgB, actor: t.adminB })
    assert.isTrue(await normal.authorize(bob, 'docs:read', t.orgB))
    const filteredToA = async (scope: ScopeRef) => {
      const chain = await full(scope)
      if (!chain || scope.type === 'app') return chain
      return chain.some((s) => s.type === 'organization' && s.uuid === t.orgA.uuid) ? chain : null
    }
    const platform = managerOver(filteredToA, descendantsFrom(t.tree))
    await normal.defineScopedRole(t.adminA, t.orgA, spec('a-2'), { within: t.orgA })
    await normal.defineScopedRole(t.adminA, t.orgA, spec('a-3'), { within: t.orgA })

    const dry = await platform.pruneOrphanRoles()
    assert.deepEqual(dry.orphans.map((o) => o.role.slug).sort(), ['b-lead', 'c-lead'])
    assert.isTrue(dry.massPurge, 'el dry-run no lanza: lo MARCA')
    assert.deepEqual(dry.massPurgeReasons, ['granting-across-owners'], '2 de 5 (≤ 50 %) y no todos los owners: solo el disparador nuevo')
    const refused = await caught(() => platform.pruneOrphanRoles({ force: true }))
    assert.equal(refused?.status, 500)
    assert.equal(refused?.code, 'E_AUTHZ_MASS_PURGE_REFUSED')
    for (const foreign of [t.orgB.uuid!, t.orgC.uuid!, b1.uuid]) assert.notInclude(String(refused?.message), foreign, 'el mensaje solo lleva cuentas')
    assert.include(String(refused?.message), 'TODAVÍA conceden')
    assert.isTrue(await normal.authorize(bob, 'docs:read', t.orgB), 'bob conserva su permiso: nada borrado')
    assert.lengthOf((await platform.pruneOrphanRoles()).orphans, 2, 'los dos huérfanos siguen ahí')

    const forced = await platform.pruneOrphanRoles({ force: true, allowMassPurge: true })
    assert.deepEqual(forced.purged.map((r) => r.slug).sort(), ['b-lead', 'c-lead'], 'la salida humana existe')
    assert.deepEqual(forced.massPurgeReasons, ['granting-across-owners'])
  })

  /**
   * **Tabla de verdad** (CLAUDE.md punto 5.b): owners huérfanos {1, 2} × `stillGranting` {true, false, undefined} ×
   * modo {dry-run, force, force + allowMassPurge}. La siembra aísla el disparador NUEVO: un tenant VIVO con 6 roles
   * locales (los huérfanos nunca pasan del 50 % y nunca son todos los owners). `undefined` = driver sin
   * `countRoleAssignments` (todos los huérfanos). Salida: `massPurge`/`massPurgeReasons`, lanza o no, qué se purga.
   */
  const OWNERS = [1, 2] as const
  const GRANTING = [true, false, undefined] as const
  const MODES = ['dry-run', 'force', 'force+allow'] as const
  for (const owners of OWNERS) {
    for (const granting of GRANTING) {
      for (const mode of MODES) {
        const flagged = owners > 1 && granting !== false
        const throws = flagged && mode === 'force'
        test(`R2-02 · tabla · owners=${owners} stillGranting=${String(granting)} ${mode} ⇒ massPurge=${flagged}${throws ? ', 500 sin borrar' : mode === 'dry-run' ? ', no escribe' : ', purga'}`, async ({ assert }) => {
          const t = await threeTenants()
          await insertLocalRoles(t.orgA, ['vivo-1', 'vivo-2', 'vivo-3', 'vivo-4', 'vivo-5', 'vivo-6'])
          const [bRole] = await insertLocalRoles(t.orgB, ['huerfano-b'])
          const cRoles = owners > 1 ? await insertLocalRoles(t.orgC, ['huerfano-c']) : []
          if (granting === true) {
            await new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(t.tree) }).grant({ type: 'users', uuid: uuidv7() }, { uuid: bRole }, t.orgB)
          }
          await t.tree.detach(t.orgB)
          if (owners > 1) await t.tree.detach(t.orgC)
          const manager = managerOver(resolveChainFrom(t.tree), descendantsFrom(t.tree), {}, granting === undefined ? (d) => void (d.countRoleAssignments = undefined) : undefined)
          const expectedOrphans = owners > 1 ? ['huerfano-b', 'huerfano-c'] : ['huerfano-b']
          const options = mode === 'dry-run' ? {} : { force: true, allowMassPurge: mode === 'force+allow' }
          const outcome = await caught(async () => {
            const report = await manager.pruneOrphanRoles(options)
            assert.equal(report.massPurge, flagged)
            assert.deepEqual(report.massPurgeReasons, flagged ? ['granting-across-owners'] : [])
            assert.deepEqual(report.orphans.map((o) => o.role.slug).sort(), expectedOrphans)
            assert.deepEqual(new Set(report.orphans.map((o) => o.stillGranting)).has(granting), true)
            assert.deepEqual(report.purged.map((r) => r.slug).sort(), mode === 'dry-run' ? [] : expectedOrphans)
          })
          if (throws) {
            assert.equal(outcome?.code, 'E_AUTHZ_MASS_PURGE_REFUSED', String(outcome?.message))
            const left = (await db.from('authz_roles').whereIn('uuid', [bRole, ...cRoles]).count('* as n')) as any[]
            assert.equal(Number(left[0].n), 1 + cRoles.length, 'nada borrado')
          } else if (outcome !== undefined) {
            throw outcome
          }
        })
      }
    }
  }

  test('TESTER · R2-02 · resolutor ciego clásico (todos los owners, nadie concede) ⇒ massPurgeReasons = [all-owners, proportion] y el 500 lo dice', async ({ assert }) => {
    // T-03 (cierre 2): `'all-owners'` lo publica el tipo y ningún caso lo observaba (mutante M6 vivo). Nota de diseño
    // (⚪ del tester): el huérfano se decide POR OWNER, así que «todos los owners» implica «todos los roles» ⇒ siempre
    // va con `'proportion'`; el caso fija además el ORDEN de los motivos en el manager.
    const t = await threeTenants()
    await insertLocalRoles(t.orgB, ['hb'])
    await insertLocalRoles(t.orgC, ['hc'])
    await t.tree.detach(t.orgB)
    await t.tree.detach(t.orgC)
    const manager = managerOver(resolveChainFrom(t.tree), descendantsFrom(t.tree))
    assert.deepEqual((await manager.pruneOrphanRoles()).massPurgeReasons, ['all-owners', 'proportion'])
    const error = await caught(() => manager.pruneOrphanRoles({ force: true }))
    assert.include(String(error?.message), 'todos los owners distintos (2 de 2) salen huérfanos')
  })

  /**
   * T-09 (cierre 2; regla 7): la rama `--force` RECHAZADA por el disparador nuevo, por el KERNEL y contra un manager
   * real (el singleton delega en uno sobre el árbol del caso): exit ≠ 0, la línea con el prefijo estable
   * `pruneOrphanRoles:` y la causa, cero roles borrados; y la salida humana `--allow-mass-purge` purga.
   */
  test('rotación 2 · T-09 · `prune-orphans --force` rechazado por granting-across-owners: por el kernel, error con prefijo estable, exit ≠ 0 y nada borrado; con --allow-mass-purge purga', async ({ assert }) => {
    const t = await threeTenants()
    await insertLocalRoles(t.orgA, ['vivo-1', 'vivo-2', 'vivo-3', 'vivo-4', 'vivo-5', 'vivo-6'])
    const [bRole] = await insertLocalRoles(t.orgB, ['huerfano-b'])
    const [cRole] = await insertLocalRoles(t.orgC, ['huerfano-c'])
    await new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(t.tree) }).grant({ type: 'users', uuid: uuidv7() }, { uuid: bRole }, t.orgB)
    await t.tree.detach(t.orgB)
    await t.tree.detach(t.orgC)
    const manager = managerOver(resolveChainFrom(t.tree), descendantsFrom(t.tree))
    const restore = patchManager('pruneOrphanRoles', (o: any) => manager.pruneOrphanRoles(o))
    try {
      const refused = await (await aceFor(AuthzCatalogPruneOrphans)).exec(['--force'])
      assert.equal(refused.error?.code, 'E_AUTHZ_MASS_PURGE_REFUSED', String(refused.error?.message))
      assert.notEqual(refused.exitCode ?? 0, 0, 'exit ≠ 0')
      assert.match(String(refused.error?.message), /^pruneOrphanRoles: /, 'prefijo estable de la rama')
      assert.include(String(refused.error?.message), 'TODAVÍA conceden')
      const left = (await db.from('authz_roles').whereIn('uuid', [bRole, cRole]).count('* as n')) as any[]
      assert.equal(Number(left[0].n), 2, 'nada borrado')
      assert.isFalse(refused.logs.some((l: string) => l.includes('purgado')), JSON.stringify(refused.logs))

      const allowed = await (await aceFor(AuthzCatalogPruneOrphans)).exec(['--force', '--allow-mass-purge'])
      assert.isUndefined(allowed.error, String(allowed.error?.message))
      assert.exists(allowed.logs.find((l: string) => l.includes('2 rol(es) local(es) huérfano(s) purgado(s).')), JSON.stringify(allowed.logs))
    } finally {
      restore()
    }
  })

  /**
   * RC2-C (cierre 2, firmado: DECLARAR): el tercer disparador pide MÁS DE UN owner huérfano. Con el contexto de UN tenant
   * colado en el resolutor y una sola víctima (un único owner ajeno con roles locales) no salta ninguno: `--force` purga
   * un rol que concede. Es el límite de la firma, declarado en README («Two safeties» y Limits); la receta es leer el
   * `--dry-run` (que SÍ marca `stillGranting: true`) y correr la pasada con un resolutor sin contexto de tenant. Si alguien
   * lo cierra (p. ej. exigir `allowMassPurge` para todo `stillGranting !== false`), este caso se pone rojo y la fila cae.
   */
  test('límite declarado rotación 2 · RC2-C una sola víctima: el resolutor con el contexto de A colado y UN owner ajeno ⇒ ningún disparador y --force purga un rol que concede; se voltea si se cierra', async ({ assert }) => {
    const t = await threeTenants()
    const full = resolveChainFrom(t.tree)
    const normal = managerOver(full, descendantsFrom(t.tree))
    const spec = (slug: string) => ({ slug, scopeType: 'organization', rank: 10, permissions: ['docs:read'] })
    const b1 = await normal.defineScopedRole(t.adminB, t.orgB, spec('b-lead'), { within: t.orgB })
    await normal.defineScopedRole(t.adminA, t.orgA, spec('a-1'), { within: t.orgA })
    await normal.defineScopedRole(t.adminA, t.orgA, spec('a-2'), { within: t.orgA })
    const bob = { type: 'users', uuid: uuidv7() }
    await normal.grant(bob, { uuid: b1.uuid }, t.orgB, { within: t.orgB, actor: t.adminB })
    assert.isTrue(await normal.authorize(bob, 'docs:read', t.orgB))
    const filteredToA = async (scope: ScopeRef) => {
      const chain = await full(scope)
      if (!chain || scope.type === 'app') return chain
      return chain.some((s) => s.type === 'organization' && s.uuid === t.orgA.uuid) ? chain : null
    }
    const platform = managerOver(filteredToA, descendantsFrom(t.tree))
    const dry = await platform.pruneOrphanRoles()
    assert.deepEqual(dry.orphans.map((o) => o.role.slug), ['b-lead'])
    assert.isTrue(dry.orphans[0].stillGranting, 'la receta: el dry-run SÍ dice que concede')
    assert.isFalse(dry.massPurge, 'LÍMITE: ningún disparador (1 owner huérfano, 1 de 3, no todos los owners)')
    assert.deepEqual(dry.massPurgeReasons, [])
    const forced = await platform.pruneOrphanRoles({ force: true })
    assert.deepEqual(forced.purged.map((r) => r.slug), ['b-lead'])
    assert.isFalse(await normal.authorize(bob, 'docs:read', t.orgB), 'bob (tenant B, árbol INTACTO) pierde un permiso vivo')
  })

  test('R2-02 · la letra del comando en --dry-run nombra el disparador (función pura, todos los motivos en orden)', ({ assert }) => {
    assert.equal(massPurgeLetter(['granting-across-owners']), 'huérfanos de más de un owner y alguno TODAVÍA concede o no se sabe')
    assert.equal(
      massPurgeLetter(['all-owners', 'proportion', 'granting-across-owners']),
      'todos los owners salen huérfanos; más del 50 % de los roles locales; huérfanos de más de un owner y alguno TODAVÍA concede o no se sabe'
    )
    assert.equal(massPurgeLetter([]), 'sin motivo reportado')
  })
})

// ---------------------------------------------------------------------------------------------------------------------
// R2-03 · E_AUTHZ_NOT_WITHIN no imprime la cadena del scope ajeno; el oráculo de existencia queda DECLARADO.
// ---------------------------------------------------------------------------------------------------------------------
test.group('rotación 2 · R2-03 · el 422 de contención no enseña el árbol de otro tenant (compartido: manager)', () => {
  test('R2-03 · grant, scopes.moved (origen) y defineScopedRole con within: orgA sobre un scope de B ⇒ NOT_WITHIN cuyo message y JSON.stringify NO llevan los uuids de B; la cadena va a error.details (no enumerable)', async ({ assert }) => {
    const t = await threeTenants()
    const manager = managerOver(resolveChainFrom(t.tree), descendantsFrom(t.tree))
    const victim = { type: 'users', uuid: uuidv7() }
    const routes = [
      await caught(() => manager.grant(victim, 'unit-editor', t.unitB1x, { within: t.orgA, actor: t.adminA })),
      await caught(() => manager.scopes.moved(t.unitB1x, t.unitA1, { within: t.orgA, actor: t.adminA })),
      await caught(() =>
        manager.defineScopedRole(t.adminA, t.unitB1, { slug: 'x', scopeType: 'unit', rank: 5, permissions: ['docs:read'] }, { within: t.orgA })
      ),
    ]
    for (const error of routes) {
      assert.equal(error?.status, 422)
      assert.equal(error?.code, 'E_AUTHZ_NOT_WITHIN', 'el CÓDIGO no cambia (firma)')
      const serialized = JSON.stringify(error)
      for (const foreign of [t.orgB.uuid!]) {
        assert.notInclude(String(error?.message), foreign, `message: ${error?.message}`)
        assert.notInclude(serialized, foreign, `JSON.stringify: ${serialized}`)
      }
      assert.include(String(error?.message), t.orgA.uuid!, 'nombra el within del llamante')
      assert.notInclude(Object.keys(error), 'details', 'details NO es enumerable')
      assert.isTrue(error.details.chain.some((s: any) => s.uuid === t.orgB.uuid), 'para el log del servidor')
    }
    // El nodo intermedio de B (unitB1) solo aparecía en la cadena del grant/moved de unitB1x.
    for (const error of routes.slice(0, 2)) {
      assert.notInclude(String(error?.message), t.unitB1.uuid!)
      assert.notInclude(JSON.stringify(error), t.unitB1.uuid!)
    }
  })

  /**
   * RC2-A (cierre 2; repro A del auditor del cierre, que afirmaba el defecto): en `updateScopedRole`/`deleteScopedRole`
   * el scope contrastado es el OWNER del rol, que el llamante NO pasó (solo el uuid del rol). El `message` nombra el rol
   * tal como llegó; el owner va a `details` no enumerable. Rama dormida (owner fuera del árbol) ⇒ UNKNOWN_SCOPE, también
   * sin el owner. Los códigos no cambian (firma).
   */
  test('RC2-A · updateScopedRole y deleteScopedRole con within: orgA sobre el uuid de un rol de B ⇒ NOT_WITHIN (y UNKNOWN_SCOPE con el owner dormido) cuyo message nombra el ROL y no su owner; el owner va a details (no enumerable)', async ({ assert }) => {
    const t = await threeTenants()
    const manager = managerOver(resolveChainFrom(t.tree), descendantsFrom(t.tree))
    const bRole = await manager.defineScopedRole(t.adminB, t.unitB1, { slug: 'b-unit-lead', scopeType: 'unit', rank: 10, permissions: ['docs:read'] }, { within: t.orgB })
    const upd = await caught(() => manager.updateScopedRole(t.adminA, bRole.uuid, { name: 'x' }, { within: t.orgA }))
    const del = await caught(() => manager.deleteScopedRole(t.adminA, bRole.uuid, { within: t.orgA }))
    for (const error of [upd, del]) {
      assert.equal(error?.status, 422)
      assert.equal(error?.code, 'E_AUTHZ_NOT_WITHIN', 'el CÓDIGO no cambia (firma)')
      for (const foreign of [t.unitB1.uuid!, t.orgB.uuid!]) {
        assert.notInclude(String(error?.message), foreign, `message: ${error?.message}`)
        assert.notInclude(JSON.stringify(error), foreign)
      }
      assert.include(String(error?.message), `el rol ${bRole.uuid}`, 'nombra lo que el llamante PASÓ')
      assert.include(String(error?.message), t.orgA.uuid!, 'y su within')
      assert.notInclude(Object.keys(error), 'details')
      assert.equal(error.details.chain[0].uuid, t.unitB1.uuid, 'el owner, para el log del servidor')
    }
    assert.isDefined(await manager.listRoles(t.adminB, t.orgB), 'nada se tocó')
    // Rama dormida: el owner fuera del árbol.
    await t.tree.detach(t.unitB1x)
    await t.tree.detach(t.unitB1)
    for (const dormant of [
      await caught(() => manager.deleteScopedRole(t.adminA, bRole.uuid, { within: t.orgA })),
      await caught(() => manager.updateScopedRole(t.adminA, bRole.uuid, { name: 'x' }, { within: t.orgA })),
      await caught(() => manager.deleteScopedRole(t.adminB, bRole.uuid)),
    ]) {
      assert.equal(dormant?.code, 'E_AUTHZ_UNKNOWN_SCOPE', String(dormant?.message))
      assert.notInclude(String(dormant?.message), t.unitB1.uuid!, String(dormant?.message))
      assert.notInclude(JSON.stringify(dormant), t.unitB1.uuid!)
      assert.include(String(dormant?.message), bRole.uuid)
      assert.notInclude(Object.keys(dormant), 'details')
      assert.deepEqual(dormant.details.owner, { type: 'unit', uuid: t.unitB1.uuid })
    }
  })

  /**
   * RC2-B (cierre 2, firmado: REORDENAR; repro B1/B2 del auditor del cierre, que afirmaba el defecto): en `scopes.moved`/
   * `scopes.attached` `within` (destino Y origen) se decide ANTES que el anti-ciclos y el techo. Antes la org candidata
   * correcta daba SCOPE_CYCLE y las demás NOT_WITHIN (A aprendía de qué org de B cuelga una unit de B), y con
   * `maxDepth` el 422 decía la profundidad del scope ajeno.
   */
  test('RC2-B · B1 · scopes.moved(<org candidata>, <unit de B>, within: orgA) ⇒ NOT_WITHIN sea o no la org de la que cuelga: ya no hay oráculo de estructura', async ({ assert }) => {
    const t = await threeTenants()
    const manager = managerOver(resolveChainFrom(t.tree), descendantsFrom(t.tree))
    const opts = { within: t.orgA, actor: t.adminA }
    const hit = await caught(() => manager.scopes.moved(t.orgB, t.unitB1x, opts))
    const miss = await caught(() => manager.scopes.moved(t.orgC, t.unitB1x, opts))
    assert.equal(hit?.code, 'E_AUTHZ_NOT_WITHIN', String(hit?.message))
    assert.equal(miss?.code, 'E_AUTHZ_NOT_WITHIN', String(miss?.message))
    assert.equal(String(hit.message).replace(t.orgB.uuid!, '<child>'), String(miss.message).replace(t.orgC.uuid!, '<child>').replace(t.orgB.uuid!, '<child>'))
  })

  test('RC2-B · B2 · con scopes.maxDepth, scopes.attached(<nuevo>, <unit de B>, within: orgA) ⇒ NOT_WITHIN a cualquier profundidad (el 422 ya no dice la profundidad del scope ajeno)', async ({ assert }) => {
    const t = await threeTenants()
    const resolveChain = resolveChainFrom(t.tree)
    const manager = new AuthorizationManager({
      default: 'database',
      drivers: { database: () => new DatabaseAuthorizationDriver({ resolveChain }) },
      scopes: { resolveChain, descendantsOf: descendantsFrom(t.tree), maxDepth: 3 },
      delegablePermissions: DELEGABLE,
      warnOnOptInSecurity: false,
    } as any)
    const opts = { within: t.orgA, actor: t.adminA }
    const deep = await caught(() => manager.scopes.attached({ type: 'unit', uuid: uuidv7() }, t.unitB1x, opts))
    const shallow = await caught(() => manager.scopes.attached({ type: 'unit', uuid: uuidv7() }, t.unitB1, opts))
    assert.equal(deep?.code, 'E_AUTHZ_NOT_WITHIN', String(deep?.message))
    assert.notInclude(String(deep?.message), 'saltos')
    assert.equal(shallow?.code, 'E_AUTHZ_NOT_WITHIN', String(shallow?.message))
    // Control: el techo sigue vivo dentro del propio tenant (within que pasa ⇒ el orden de siempre).
    const unitA1x: ScopeRef = { type: 'unit', uuid: uuidv7() }
    await t.tree.attach(unitA1x, t.unitA1)
    const own = await caught(() => manager.scopes.attached({ type: 'unit', uuid: uuidv7() }, unitA1x, opts))
    assert.equal(own?.code, 'E_AUTHZ_SCOPE_DEPTH_LIMIT', String(own?.message))
  })

  /**
   * **Tabla de verdad de RC2-B** (CLAUDE.md punto 5.b): operación {moved, attached de un hijo existente} × `within`
   * {ausente, pasa, falla el destino, falla el origen} × arista {ok, ciclo, demasiado profunda} × outbox {sí, no} = 48
   * filas, más `requireWithin: true` sin `within` × arista × operación × outbox (12 filas): 60. `scopes.maxDepth = 3` en todas (la cadena del padre
   * de más de 3 nodos es «demasiado profunda»). Esperado: `within` que falla ⇒ NOT_WITHIN en las tres aristas (antes: el
   * ciclo y la profundidad salían primero); ausente o que pasa ⇒ el orden de siempre (ok / SCOPE_CYCLE / DEPTH_LIMIT);
   * `requireWithin` sin `within` ⇒ WITHIN_REQUIRED en las tres (decisión de este cierre: el bloque de contención es uno —
   * exigido, raíz prohibida, destino, origen— y va entero antes de la arista; antes WITHIN_REQUIRED salía DESPUÉS del
   * ciclo y del techo). Con error, NADA encolado y el driver no se llama; con éxito, encolado (outbox) o el driver llamado
   * (sin outbox). Las filas «falla el origen + ciclo» usan `within: unitA1` (con `within: orgA` no son construibles: un
   * padre dentro de A que desciende de un hijo fuera de A no existe).
   */
  const RC2B_OPS = ['moved', 'attached'] as const
  const RC2B_WITHIN = ['ausente', 'pasa', 'falla-destino', 'falla-origen', 'requireWithin-sin-within'] as const
  const RC2B_EDGE = ['ok', 'ciclo', 'profunda'] as const
  for (const op of RC2B_OPS) {
    for (const within of RC2B_WITHIN) {
      for (const edge of RC2B_EDGE) {
        for (const outbox of [true, false]) {
          const expected =
            within === 'requireWithin-sin-within'
              ? 'E_AUTHZ_WITHIN_REQUIRED'
              : within === 'falla-destino' || within === 'falla-origen'
                ? 'E_AUTHZ_NOT_WITHIN'
                : edge === 'ciclo'
                  ? 'E_AUTHZ_SCOPE_CYCLE'
                  : edge === 'profunda'
                    ? 'E_AUTHZ_SCOPE_DEPTH_LIMIT'
                    : 'ok'
          test(`RC2-B · tabla · ${op} within=${within} arista=${edge} outbox=${outbox} ⇒ ${expected}`, async ({ assert }) => {
            const t = await threeTenants()
            const unitA2: ScopeRef = { type: 'unit', uuid: uuidv7() }
            const unitA1x: ScopeRef = { type: 'unit', uuid: uuidv7() }
            await t.tree.attach(unitA2, t.orgA)
            await t.tree.attach(unitA1x, t.unitA1)
            // [hijo, padre, within] por (within, arista). Cadenas: unitA1 = 3 nodos (ok), unitA1x / unitB1x = 4 (> maxDepth 3).
            const cases: Record<string, [ScopeRef, ScopeRef, ScopeRef | undefined]> = {
              'ausente/ok': [unitA2, t.unitA1, undefined],
              'ausente/ciclo': [t.unitA1, unitA1x, undefined],
              'ausente/profunda': [unitA2, unitA1x, undefined],
              'pasa/ok': [unitA2, t.unitA1, t.orgA],
              'pasa/ciclo': [t.unitA1, unitA1x, t.orgA],
              'pasa/profunda': [unitA2, unitA1x, t.orgA],
              'falla-destino/ok': [unitA2, t.unitB1, t.orgA],
              'falla-destino/ciclo': [t.orgB, t.unitB1x, t.orgA],
              'falla-destino/profunda': [unitA2, t.unitB1x, t.orgA],
              'falla-origen/ok': [t.unitB1, t.unitA1, t.orgA],
              'falla-origen/ciclo': [t.orgA, unitA1x, t.unitA1],
              'falla-origen/profunda': [t.unitB1, unitA1x, t.orgA],
              'requireWithin-sin-within/ok': [unitA2, t.unitA1, undefined],
              'requireWithin-sin-within/ciclo': [t.unitA1, unitA1x, undefined],
              'requireWithin-sin-within/profunda': [unitA2, unitA1x, undefined],
            }
            const [child, parent, withinScope] = cases[`${within}/${edge}`]
            const queued: unknown[] = []
            const driverCalls: string[] = []
            const resolveChain = resolveChainFrom(t.tree)
            const manager = new AuthorizationManager({
              default: 'database',
              drivers: {
                database: () => {
                  const driver: any = new DatabaseAuthorizationDriver({ resolveChain })
                  driver.onScopeMoved = async () => void driverCalls.push('moved')
                  driver.onScopeAttached = async () => void driverCalls.push('attached')
                  return driver
                },
              },
              scopes: {
                resolveChain,
                descendantsOf: descendantsFrom(t.tree),
                maxDepth: 3,
                ...(outbox
                  ? {
                      outbox: {
                        enqueue: async (change: unknown) => {
                          queued.push(change)
                          return { id: queued.length }
                        },
                        pending: async () => [],
                        markApplied: async () => {},
                        markFailed: async () => {},
                      },
                    }
                  : {}),
              },
              ...(within === 'requireWithin-sin-within' ? { requireWithin: true } : {}),
              delegablePermissions: DELEGABLE,
              warnOnOptInSecurity: false,
            } as any)
            const options = { actor: t.adminA, ...(withinScope ? { within: withinScope } : {}) }
            const error = await caught(() => manager.scopes[op](child, parent, options))
            if (expected === 'ok') {
              assert.isUndefined(error, `${error?.code}: ${error?.message}`)
              assert.deepEqual([queued.length, driverCalls.length], outbox ? [1, 0] : [0, 1])
            } else {
              assert.equal(error?.code, expected, `${error?.code}: ${error?.message}`)
              assert.deepEqual([queued.length, driverCalls.length], [0, 0], 'nada encolado ni aplicado')
            }
          })
        }
      }
    }
  }

  test('RC2-B · moved con within y un hijo DESCONOCIDO bajo un padre propio demasiado profundo ⇒ UNKNOWN_SCOPE del origen (antes: DEPTH_LIMIT); sin within, DEPTH_LIMIT como siempre', async ({ assert }) => {
    // Consecuencia declarada del reorden (CHANGELOG): el origen es parte del bloque de contención, y en `moved` con
    // `within` el hijo tiene que existir. No es un oráculo: el padre es del propio tenant (el destino ya pasó).
    const t = await threeTenants()
    const unitA1x: ScopeRef = { type: 'unit', uuid: uuidv7() }
    await t.tree.attach(unitA1x, t.unitA1)
    const resolveChain = resolveChainFrom(t.tree)
    const manager = new AuthorizationManager({
      default: 'database',
      drivers: { database: () => new DatabaseAuthorizationDriver({ resolveChain }) },
      scopes: { resolveChain, descendantsOf: descendantsFrom(t.tree), maxDepth: 3 },
      delegablePermissions: DELEGABLE,
      warnOnOptInSecurity: false,
    } as any)
    const ghost: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const withWithin = await caught(() => manager.scopes.moved(ghost, unitA1x, { within: t.orgA, actor: t.adminA }))
    assert.equal(withWithin?.code, 'E_AUTHZ_UNKNOWN_SCOPE', String(withWithin?.message))
    const without = await caught(() => manager.scopes.moved(ghost, unitA1x, { actor: t.adminA }))
    assert.equal(without?.code, 'E_AUTHZ_SCOPE_DEPTH_LIMIT', String(without?.message))
  })

  /**
   * **Caso de GUARDIA** de la propiedad universal candidata del linaje «un 422 que nombra identificadores de otro tenant»
   * (`linajes.md`; 3E · Q2 → 3G · X5 → R2-03/R2-05 → RC2-A): con `within` del tenant A apuntando a lo de B, por TODAS las
   * escrituras con contención y sus variantes (destino/origen, rol por uuid, owner dormido, ciclo y techo detrás de un
   * `within` que falla), ningún error —`message` ni `JSON.stringify`— lleva un uuid de B que el llamante NO pasó. La
   * lista de rutas es A MANO (no por reflexión: eso es la propuesta para 2.6); una escritura nueva con `within` tiene que
   * entrar aquí.
   */
  test('guardia · ninguna escritura con within ajeno devuelve un error que nombre un uuid de otro tenant que el llamante no pasó', async ({ assert }) => {
    const t = await threeTenants()
    const resolveChain = resolveChainFrom(t.tree)
    const manager = new AuthorizationManager({
      default: 'database',
      drivers: { database: () => new DatabaseAuthorizationDriver({ resolveChain }) },
      scopes: { resolveChain, descendantsOf: descendantsFrom(t.tree), maxDepth: 3 },
      delegablePermissions: DELEGABLE,
      warnOnOptInSecurity: false,
    } as any)
    const bRole = await manager.defineScopedRole(t.adminB, t.unitB1, { slug: 'b-lead', scopeType: 'unit', rank: 10, permissions: ['docs:read'] }, { within: t.orgB })
    const victim = { type: 'users', uuid: uuidv7() }
    const fresh = (): ScopeRef => ({ type: 'unit', uuid: uuidv7() })
    const opts = { within: t.orgA, actor: t.adminA }
    const foreign = [t.orgB, t.unitB1, t.unitB1x].map((s) => s.uuid!)
    const routes: Array<[string, string[], () => Promise<unknown>]> = [
      ['grant', [t.unitB1x.uuid!], () => manager.grant(victim, 'unit-editor', t.unitB1x, opts)],
      ['revoke', [t.unitB1x.uuid!], () => manager.revoke(victim, 'unit-editor', t.unitB1x, opts)],
      ['deny', [t.unitB1x.uuid!], () => manager.deny(victim, 'docs:read', t.unitB1x, opts)],
      ['removeDeny', [t.unitB1x.uuid!], () => manager.removeDeny(victim, 'docs:read', t.unitB1x, opts)],
      ['grant por uuid de un rol ajeno', [], () => manager.grant(victim, { uuid: bRole.uuid }, t.unitA1, opts)],
      ['attached (destino)', [t.unitB1.uuid!], () => manager.scopes.attached(fresh(), t.unitB1, opts)],
      ['attached (origen)', [t.unitB1x.uuid!], () => manager.scopes.attached(t.unitB1x, t.unitA1, opts)],
      ['moved (destino)', [t.unitB1.uuid!], () => manager.scopes.moved(fresh(), t.unitB1, opts)],
      ['moved (origen)', [t.unitB1x.uuid!], () => manager.scopes.moved(t.unitB1x, t.unitA1, opts)],
      ['moved (destino + ciclo)', [t.orgB.uuid!, t.unitB1x.uuid!], () => manager.scopes.moved(t.orgB, t.unitB1x, opts)],
      ['attached (destino + techo)', [t.unitB1x.uuid!], () => manager.scopes.attached(fresh(), t.unitB1x, opts)],
      ['detached', [t.unitB1x.uuid!], () => manager.scopes.detached(t.unitB1x, opts)],
      ['defineScopedRole', [t.unitB1x.uuid!], () => manager.defineScopedRole(t.adminA, t.unitB1x, { slug: 'x', scopeType: 'unit', rank: 5, permissions: ['docs:read'] }, opts)],
      ['updateScopedRole', [], () => manager.updateScopedRole(t.adminA, bRole.uuid, { name: 'x' }, opts)],
      ['deleteScopedRole', [], () => manager.deleteScopedRole(t.adminA, bRole.uuid, opts)],
    ]
    const dormant: Array<[string, string[], () => Promise<unknown>]> = [
      ['updateScopedRole (owner dormido)', [], () => manager.updateScopedRole(t.adminA, bRole.uuid, { name: 'x' }, opts)],
      ['deleteScopedRole (owner dormido)', [], () => manager.deleteScopedRole(t.adminA, bRole.uuid, opts)],
      ['grant por uuid de un rol dormido', [], () => manager.grant(victim, { uuid: bRole.uuid }, t.unitA1, opts)],
    ]
    const judge = async ([name, passed, run]: [string, string[], () => Promise<unknown>]) => {
      const error = await caught(run)
      assert.exists(error, `${name}: tenía que fallar`)
      assert.equal(error?.status, 422, `${name}: ${error?.code} ${error?.message}`)
      for (const uuid of foreign.filter((u) => !passed.includes(u))) {
        assert.notInclude(String(error?.message), uuid, `${name} · message: ${error?.message}`)
        assert.notInclude(JSON.stringify(error), uuid, `${name} · JSON.stringify`)
      }
    }
    for (const route of routes) await judge(route)
    await t.tree.detach(t.unitB1x)
    await t.tree.detach(t.unitB1)
    for (const route of dormant) await judge(route)
  })

  test('límite declarado rotación 2 · R2-03 oráculo de existencia: UNKNOWN_SCOPE y NOT_WITHIN se distinguen por el code; se voltea en 2.6', async ({ assert }) => {
    const t = await threeTenants()
    const manager = managerOver(resolveChainFrom(t.tree), descendantsFrom(t.tree))
    const victim = { type: 'users', uuid: uuidv7() }
    const foreign = await caught(() => manager.grant(victim, 'unit-editor', t.unitB1, { within: t.orgA, actor: t.adminA }))
    const ghost = await caught(() => manager.grant(victim, 'unit-editor', { type: 'unit', uuid: uuidv7() }, { within: t.orgA, actor: t.adminA }))
    assert.equal(foreign?.code, 'E_AUTHZ_NOT_WITHIN', 'existe en otro tenant')
    assert.equal(ghost?.code, 'E_AUTHZ_UNKNOWN_SCOPE', 'no existe: OTRO código (oráculo declarado; receta: 404 uniforme)')
  })
})

// ---------------------------------------------------------------------------------------------------------------------
// R2-04 · `pruneOrphanRoles({ maxLocalRoles })` + la letra del 500.
// ---------------------------------------------------------------------------------------------------------------------
test.group('rotación 2 · R2-04 · prune-orphans tiene mando sobre su cota (compartido: manager/catálogo)', () => {
  test('R2-04 · 10 001 roles locales de UN owner ⇒ por defecto 500 que nombra la opción y la bandera; con maxLocalRoles: 50 000 lista y purga el huérfano real de B', async ({ assert }) => {
    const t = await threeTenants()
    const full = resolveChainFrom(t.tree)
    const normal = managerOver(full, descendantsFrom(t.tree))
    await withAuthzCatalogWrite(async (trx) => {
      const now = new Date()
      for (let base = 0; base < 10_000; base += 500) {
        const rows = []
        for (let i = base; i < base + 500; i++) {
          rows.push({ uuid: uuidv7(), slug: `r${i}`, name: `r${i}`, scope_type: 'organization', rank: 1, owner_scope_key: `organization|${t.orgA.uuid}`, created_at: now, updated_at: now })
        }
        await trx.table('authz_roles').multiInsert(rows)
      }
    })
    await normal.defineScopedRole(t.adminA, t.orgA, { slug: 'una-mas', scopeType: 'organization', rank: 10, permissions: ['docs:read'] }, { within: t.orgA })
    await normal.defineScopedRole(t.adminB, t.orgB, { slug: 'b-lead', scopeType: 'organization', rank: 10, permissions: ['docs:read'] }, { within: t.orgB })
    await t.tree.detach(t.orgB)

    const dry = await caught(() => normal.pruneOrphanRoles())
    assert.equal(dry?.code, 'E_AUTHZ_TOO_MANY_LOCAL_ROLES')
    assert.include(String(dry?.message), 'pruneOrphanRoles({ maxLocalRoles })', 'el mensaje nombra la opción REAL')
    assert.include(String(dry?.message), '--max-local-roles', 'y la bandera REAL')
    const listed = await normal.pruneOrphanRoles({ maxLocalRoles: 50_000 })
    assert.deepEqual(listed.orphans.map((o) => o.role.slug), ['b-lead'])
    const forced = await normal.pruneOrphanRoles({ force: true, maxLocalRoles: 50_000 })
    assert.deepEqual(forced.purged.map((r) => r.slug), ['b-lead'])
    const tight = await caught(() => normal.pruneOrphanRoles({ maxLocalRoles: 10_000 }))
    assert.equal(tight?.code, 'E_AUTHZ_TOO_MANY_LOCAL_ROLES', 'la cota es la que se pasa: tras la purga quedan 10 001 locales y la cota pasada es 10 000')
  })

  test('R2-04 · maxLocalRoles que no es un entero ≥ 1 ⇒ 500 E_AUTHZ_CONFIG antes de leer nada (también en dry-run)', async ({ assert }) => {
    const t = await threeTenants()
    let reads = 0
    const manager = managerOver(async (scope) => {
      reads++
      return resolveChainFrom(t.tree)(scope)
    }, descendantsFrom(t.tree))
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '10' as any, null as any]) {
      const error = await caught(() => manager.pruneOrphanRoles({ maxLocalRoles: bad }))
      assert.equal(error?.status, 500, String(bad))
      assert.equal(error?.code, 'E_AUTHZ_CONFIG', String(bad))
      assert.include(String(error?.message), '--max-local-roles')
    }
    assert.equal(reads, 0, 'ni un resolveChain')
    assert.deepEqual((await manager.pruneOrphanRoles({ maxLocalRoles: 1 })).orphans, [], 'el mínimo legal es 1')
  })
})

// ---------------------------------------------------------------------------------------------------------------------
// R2-05 · la re-comprobación en transacción de defineScopedRole: autoridad, sin owner ajeno.
// ---------------------------------------------------------------------------------------------------------------------
test.group('rotación 2 · R2-05 · el re-chequeo de defineScopedRole decide por autoridad (compartido: manager/catálogo)', () => {
  /** `descendantsOf` que, la PRIMERA vez, confirma «desde otro proceso» un homónimo con `owner` (sin tocar el memo de este). */
  function windowWith(t: Awaited<ReturnType<typeof threeTenants>>, slug: string, scopeType: string, owner: ScopeRef) {
    const below = descendantsFrom(t.tree)
    let fired = false
    return async (scope: ScopeRef, options: any) => {
      if (!fired) {
        fired = true
        await withAuthzCatalogWrite(async (trx) => {
          const perm: any = (await trx.from('authz_permissions').where('slug', 'docs:read').select('uuid'))[0]
          const now = new Date()
          const uuid = uuidv7()
          await trx.table('authz_roles').insert({
            uuid, slug, name: slug, scope_type: scopeType, rank: 10,
            owner_scope_key: `${owner.type}|${owner.uuid}`, created_at: now, updated_at: now,
          })
          await trx.table('authz_role_permissions').insert({ uuid: uuidv7(), role_uuid: uuid, permission_uuid: perm.uuid, created_at: now })
        })
      }
      return below(scope, options)
    }
  }
  const spec = { slug: 'lead', scopeType: 'unit', rank: 10, permissions: ['docs:read'] }
  const rows = async (slug: string) => db.from('authz_roles').where('slug', slug).select('owner_scope_key')

  test('R2-05 · B define lead@unit mientras A (otro proceso, tenant HERMANO) confirma su lead@unit ⇒ el de B ENTRA (no hay colisión) y nada nombra a A', async ({ assert }) => {
    const t = await threeTenants()
    const managerB = managerOver(resolveChainFrom(t.tree), windowWith(t, 'lead', 'unit', t.orgA))
    const role = await managerB.defineScopedRole(t.adminB, t.orgB, spec, { within: t.orgB })
    assert.equal(role.owner, `organization|${t.orgB.uuid}`)
    assert.sameMembers((await rows('lead')).map((r: any) => r.owner_scope_key), [`organization|${t.orgA.uuid}`, `organization|${t.orgB.uuid}`])
  })

  test('R2-05 · M2 se mantiene: el homónimo del MISMO owner confirmado en la ventana ⇒ 422 CATALOG_CONFLICT y nada escrito', async ({ assert }) => {
    const t = await threeTenants()
    const managerB = managerOver(resolveChainFrom(t.tree), windowWith(t, 'lead', 'unit', t.orgB))
    const error = await caught(() => managerB.defineScopedRole(t.adminB, t.orgB, spec, { within: t.orgB }))
    assert.equal(error?.code, 'E_AUTHZ_CATALOG_CONFLICT', String(error?.message))
    assert.lengthOf(await rows('lead'), 1)
    for (const foreign of [t.orgA.uuid!, t.orgC.uuid!]) assert.notInclude(String(error?.message), foreign)
  })

  test('R2-05 · Y1 (final 2): el homónimo de un DESCENDIENTE confirmado en la ventana no bloquea al ancestro: entra y lo ensombrece (2 roles)', async ({ assert }) => {
    const t = await threeTenants()
    const managerA = managerOver(resolveChainFrom(t.tree), windowWith(t, 'lead', 'unit', t.unitA1))
    const role = await managerA.defineScopedRole(t.adminA, t.orgA, spec, { within: t.orgA })
    assert.equal(role.owner, `organization|${t.orgA.uuid}`)
    assert.sameMembers((await rows('lead')).map((r: any) => r.owner_scope_key), [`unit|${t.unitA1.uuid}`, `organization|${t.orgA.uuid}`])
  })

  test('R2-05 · Y1 (final 1): el homónimo de un ANCESTRO confirmado en la ventana ⇒ 422 CATALOG_CONFLICT (autoridad hacia arriba)', async ({ assert }) => {
    const t = await threeTenants()
    // El owner es la unit y el rol de nivel `team` (que cuelga de ella): así `descendantsOf` corre y abre la ventana.
    await t.tree.attach({ type: 'team', uuid: uuidv7() }, t.unitA1)
    const managerA = managerOver(resolveChainFrom(t.tree), windowWith(t, 'lead', 'team', t.orgA))
    const error = await caught(() => managerA.defineScopedRole(t.adminA, t.unitA1, { ...spec, scopeType: 'team' }, { within: t.orgA }))
    assert.equal(error?.code, 'E_AUTHZ_CATALOG_CONFLICT', String(error?.message))
    assert.include(String(error?.message), 'un ancestro', 'el 422 preciso de la regla de autoridad (nombra la cadena del PROPIO llamante)')
    assert.lengthOf(await rows('lead'), 1)
  })

  test('TESTER · R2-05 · un GLOBAL homónimo confirmado en la ventana ⇒ 422 CATALOG_CONFLICT (global gana) y nada escrito', async ({ assert }) => {
    // T-02 (cierre 2): la fila «global» de la tabla de verdad de R2-05 tenía como fuente «lo que hace hoy»; en la ventana
    // el memo no tiene el homónimo y la única barrera es la línea `global` de `#assertNoRoleCollision` en `'sin-árbol'`
    // (mutante M5: filtrar `'global'` del re-chequeo ⇒ el local se escribe).
    const t = await threeTenants()
    const below = descendantsFrom(t.tree)
    let fired = false
    const window = async (scope: ScopeRef, options: any) => {
      if (!fired) {
        fired = true
        await withAuthzCatalogWrite(async (trx) => {
          const now = new Date()
          await trx.table('authz_roles').insert({ uuid: uuidv7(), slug: 'lead', name: 'lead', scope_type: 'unit', rank: 10, owner_scope_key: 'global', created_at: now, updated_at: now })
        })
      }
      return below(scope, options)
    }
    const managerB = managerOver(resolveChainFrom(t.tree), window)
    const error = await caught(() => managerB.defineScopedRole(t.adminB, t.orgB, spec, { within: t.orgB }))
    assert.equal(error?.code, 'E_AUTHZ_CATALOG_CONFLICT', String(error?.message))
    assert.include(String(error?.message), 'global')
    assert.lengthOf(await rows('lead'), 1)
  })

  /**
   * T-08 = RC2-D (cierre 2; repro D del auditor del cierre): el «Not done» de R2-05, ACEPTADO y declarado (⚪, respuesta
   * del dueño). El homónimo de un DESCENDIENTE confirmado en la ventana entra sin la comprobación de rango de 3G · W3 (el
   * re-chequeo no puede resolver la cadena del owner nuevo dentro de la trx) y el evento `role_defined` no lo lista en
   * `shadowedByAncestor`; `authz:catalog:diff` sí. Control: con el rol ya visible al validar, W3 rechaza. Si alguien lo
   * cierra (re-validar fuera de la trx), este caso se pone rojo y el «Not done» del CHANGELOG cae.
   */
  test('límite declarado rotación 2 · R2-05 W3 en la ventana: un actor de rank 5 define lead@unit en orgA mientras unitA1 confirma su lead@unit rank 40 ⇒ entra sin RANK_EXCEEDED y el evento no dice shadowedByAncestor (el diff sí); se voltea si se cierra', async ({ assert }) => {
    const t = await threeTenants()
    const events: any[] = []
    const full = resolveChainFrom(t.tree)
    const hooks = { onCatalogWrite: (e: any) => void events.push(e) }
    const normal = managerOver(full, descendantsFrom(t.tree), { hooks })
    const junior = { type: 'users', uuid: uuidv7() }
    const jr = await normal.defineScopedRole(t.adminA, t.orgA, { slug: 'org-junior', scopeType: 'organization', rank: 5, permissions: ['docs:read'] }, { within: t.orgA })
    await normal.grant(junior, { uuid: jr.uuid }, t.orgA, { within: t.orgA, actor: t.adminA })

    // Control (W3 vigente): la víctima rank 40 ya existe al validar ⇒ 422 RANK_EXCEEDED.
    await normal.defineScopedRole(t.adminA, t.unitA1, { slug: 'lead-ctl', scopeType: 'unit', rank: 40, permissions: ['docs:read'] }, { within: t.orgA })
    const ctl = await caught(() => normal.defineScopedRole(junior, t.orgA, { slug: 'lead-ctl', scopeType: 'unit', rank: 1, permissions: ['docs:read'] }, { within: t.orgA }))
    assert.equal(ctl?.code, 'E_AUTHZ_RANK_EXCEEDED', String(ctl?.message))

    // La ventana: la víctima (otro proceso) confirma su lead@unit rank 40 mientras el junior valida.
    const below = descendantsFrom(t.tree)
    let fired = false
    let victimUuid = ''
    const windowed = managerOver(full, async (scope: ScopeRef, options: any) => {
      if (!fired) {
        fired = true
        await withAuthzCatalogWrite(async (trx) => {
          const perm: any = (await trx.from('authz_permissions').where('slug', 'docs:read').select('uuid'))[0]
          const now = new Date()
          victimUuid = uuidv7()
          await trx.table('authz_roles').insert({ uuid: victimUuid, slug: 'lead', name: 'lead', scope_type: 'unit', rank: 40, owner_scope_key: `unit|${t.unitA1.uuid}`, created_at: now, updated_at: now })
          await trx.table('authz_role_permissions').insert({ uuid: uuidv7(), role_uuid: victimUuid, permission_uuid: perm.uuid, created_at: now })
        })
      }
      return below(scope, options)
    }, { hooks })
    const entered = await windowed.defineScopedRole(junior, t.orgA, { slug: 'lead', scopeType: 'unit', rank: 1, permissions: ['docs:read'] }, { within: t.orgA })
    assert.equal(entered.owner, `organization|${t.orgA.uuid}`, 'LÍMITE: entra sin juzgar rango contra el rank 40')
    const defined = events.find((e) => e.action === 'role_defined' && e.role?.uuid === entered.uuid)
    assert.exists(defined)
    assert.isUndefined(defined.shadowedByAncestor, 'LÍMITE: el evento no dice a quién ensombrece')
    const diff = await diffAuthzCatalog(CATALOG as any, { resolveChain: full })
    assert.isTrue(
      diff.shadowedByAncestor.some((d) => d.slug === 'lead' && d.owner === `unit|${t.unitA1.uuid}`),
      `el diff SÍ lo lista: ${JSON.stringify(diff.shadowedByAncestor)}`
    )
    const amb = await caught(() => normal.grant({ type: 'users', uuid: uuidv7() }, { slug: 'lead', scopeType: 'unit' }, t.unitA1, { within: t.orgA, actor: t.adminA }))
    assert.equal(amb?.code, 'E_AUTHZ_AMBIGUOUS_ROLE', 'ruidoso: el slug queda ambiguo bajo unitA1')
    assert.isNotEmpty(victimUuid)
  })
})

// ---------------------------------------------------------------------------------------------------------------------
// R2-06 · declarado, no arreglado: la recarga ENTERA del catálogo por una escritura de catálogo de cualquier tenant.
// ---------------------------------------------------------------------------------------------------------------------
test.group('rotación 2 · R2-06 · declarado (compartido: catálogo)', () => {
  test('límite declarado rotación 2 · R2-06 recarga entera: una escritura de catálogo de un tenant recarga el catálogo de todos; se voltea en 2.6', async ({ assert }) => {
    const t = await threeTenants()
    const normal = managerOver(resolveChainFrom(t.tree), descendantsFrom(t.tree))
    await normal.defineScopedRole(t.adminB, t.orgB, { slug: 'b-lead', scopeType: 'organization', rank: 10, permissions: ['docs:read'] }, { within: t.orgB })
    const a = await normal.defineScopedRole(t.adminA, t.orgA, { slug: 'a-lead', scopeType: 'organization', rank: 10, permissions: ['docs:read'] }, { within: t.orgA })
    const otherProcess = new CatalogCache()
    const before = await otherProcess.view()
    assert.strictEqual(await otherProcess.view(), before, 'control: sin escrituras, la misma foto')
    await normal.updateScopedRole(t.adminA, a.uuid, { name: 'renombrado' }, { within: t.orgA })
    const after = await otherProcess.view()
    assert.notStrictEqual(after, before, 'una escritura del tenant A: foto NUEVA en el otro «proceso»')
    assert.lengthOf(after.rolesNamed('b-lead', 'organization'), 1, 'y es el catálogo ENTERO (los roles de B también se recargan)')
  })
})

// ---------------------------------------------------------------------------------------------------------------------
// Letra con dientes: las filas de Limits y el CHANGELOG del cierre.
// ---------------------------------------------------------------------------------------------------------------------
test.group('rotación 2 · letra (README «Limits» y CHANGELOG)', () => {
  test('las tres filas declaradas (R2-01, R2-03, R2-06) tienen receta, detector, cierre 2.6 y SU caso en este fichero; el CHANGELOG abre [Unreleased] y corrige la frase de 3E', ({ assert }) => {
    const readme = read('README.md')
    const here = read('tests/rotacion2_cierre.spec.ts')
    const rowOf = (start: string) => readme.split('\n').find((line) => line.startsWith(start))
    for (const [start, label] of [
      ['| **Two deployments on different databases of the same MySQL server still share the relay lease during 2.5.x (R2-01)**', 'R2-01'],
      ['| **`E_AUTHZ_UNKNOWN_SCOPE` vs `E_AUTHZ_NOT_WITHIN` tells whether a scope exists in another tenant (R2-03)**', 'R2-03'],
      ['| **Any tenant\'s catalog write makes every process reload the WHOLE catalog (R2-06)**', 'R2-06'],
      ['| **The third mass-purge trigger does not cover a single victim (RC2-C)**', 'RC2-C'],
    ] as const) {
      const row = rowOf(start)
      assert.exists(row, `la fila de ${label}`)
      for (const phrase of ['declared yellow of shared code', '**Recipe**', '**Detector**', '**Closes in 2.6**', `Case: «límite declarado rotación 2 · ${label}`]) {
        assert.include(row!, phrase, `${label}: la fila no dice «${phrase}»`)
      }
      const title = row!.match(/Case: «([^»]+)»/)![1]
      assert.include(here, `test('${title}'`, `${label}: el caso que nombra la fila no existe`)
    }
    assert.include(rowOf('| **`E_AUTHZ_UNKNOWN_SCOPE` vs')!, 'a uniform 404')
    assert.include(rowOf('| **`E_AUTHZ_UNKNOWN_SCOPE` vs')!, 'not measured')
    assert.include(rowOf('| **Any tenant')!, 'not measured')
    assert.include(readme, '`pruneOrphanRoles({ maxLocalRoles })`, `authz:catalog:prune-orphans --max-local-roles`')
    assert.include(readme, "`'granting-across-owners'`")
    assert.include(readme, '`error.details.chain`')
    const changelog = read('CHANGELOG.md')
    const unreleased = changelog.slice(0, changelog.search(/^## \[2\.5\.0-alpha\.4\]/m))
    assert.include(unreleased, '## [Unreleased] — rotation 2 closure')
    assert.include(unreleased, '«**Errors that no longer name another tenant\'s identifiers**». It was\nfalse for `E_AUTHZ_NOT_WITHIN`')
    for (const phrase of ['*Problem*', '*Decision*', '*Not done*', 'R2-01', 'R2-02', 'R2-03', 'R2-04', 'R2-05', 'R2-06']) assert.include(unreleased, phrase)
  })

  /**
   * T-06 (cierre 2): las frases nuevas del cierre, cada una buscada en SU sección (una frase repetida en otra sección no
   * la salva), y el CHANGELOG partido por párrafo: cada `**…(R2-0N).**` / `**…(RC2-X).**` con problema, decisión y su
   * «Not done» (borrar el «Not done» de un párrafo ya no lo salva el de otro).
   */
  test('T-06 · las frases del cierre en su sección del README y un «Not done» por párrafo del CHANGELOG', ({ assert }) => {
    const readme = read('README.md')
    const section = (start: string, length = 6000) => {
      const at = readme.indexOf(start)
      assert.isAtLeast(at, 0, `no encuentro «${start}»`)
      return readme.slice(at, at + length)
    }
    const relay = section('**The relay is a single writer.**', 2500)
    assert.include(relay, 'On MySQL `GET_LOCK` is per **server**, so since the rotation 2 closure the lease name carries the **database**')
    assert.include(relay, 'two deployments on different databases of one server still exclude each other until 2.6')
    const safeties = section('**Two safeties, because the dangerous input is your own resolver.**', 4000)
    assert.include(safeties, '**or the orphans belong to more than one owner and any of them still grants (`stillGranting: true`) or nobody knows (`undefined`)**')
    assert.include(safeties, 'naming the counts (never another owner\'s identifiers)')
    assert.include(safeties, '**so the third trigger does not cover a single victim**')
    assert.include(safeties, 'always read the `--dry-run` before `--force`')
    assert.include(safeties, 'run the pass with a resolver that has **no** tenant context')
    const rowOf = (start: string) => {
      const row = readme.split('\n').find((line) => line.startsWith(start))
      assert.exists(row, start)
      return row!
    }
    const conflict = rowOf('| `E_AUTHZ_CATALOG_CONFLICT` |')
    assert.include(conflict, 'a homonym committed in that window by an owner that is neither global nor an ancestor-or-self')
    assert.include(conflict, 'is **not** a collision and the message never names another tenant\'s owner')
    assert.include(conflict, 'is shadowed **without** the rank check of shadowing and is not in the event\'s `shadowedByAncestor`')
    const notWithin = rowOf('| `E_AUTHZ_NOT_WITHIN` |')
    assert.include(notWithin, '`error.details.chain`, **not enumerable**, so `JSON.stringify(error)` does not carry it')
    assert.include(notWithin, 'For `updateScopedRole`/`deleteScopedRole` the message names the role you passed, not its owner')
    assert.include(notWithin, 'it comes **before** `E_AUTHZ_SCOPE_CYCLE` and `E_AUTHZ_SCOPE_DEPTH_LIMIT`')
    assert.include(rowOf('| `E_AUTHZ_UNKNOWN_SCOPE` |'), 'the owner (which you did not pass, and may be another tenant\'s) is in `error.details.owner`, **not enumerable**')
    const containment = section('**Containment.**', 4000)
    assert.include(containment, 'the message names **the role**, never its owner')
    assert.include(containment, 'containment — destination **and** origin — is decided **before** the cycle check and `scopes.maxDepth`')
    const oracle = rowOf('| **`E_AUTHZ_UNKNOWN_SCOPE` vs `E_AUTHZ_NOT_WITHIN`')
    assert.include(oracle, 'decide containment before the cycle check and `scopes.maxDepth`')
    assert.include(oracle, 'The same holds for **roles** by uuid in `updateScopedRole`/`deleteScopedRole`')

    const changelog = read('CHANGELOG.md')
    const unreleased = changelog.slice(0, changelog.search(/^## \[2\.5\.0-alpha\.4\]/m))
    // Un párrafo = desde su cabecera en negrita hasta la siguiente cabecera en negrita a principio de línea.
    const paragraphs = unreleased.split(/\n(?=\*\*)/)
    const paragraphOf = (id: string) => {
      const found = paragraphs.filter((p) => new RegExp(`^\\*\\*[^*]*\\(${id}\\)\\.\\*\\*`).test(p))
      assert.lengthOf(found, 1, `un párrafo con cabecera «(${id}).**»`)
      return found[0]
    }
    for (const id of ['R2-01', 'R2-02', 'R2-03', 'R2-04', 'R2-05', 'RC2-A', 'RC2-B']) {
      const paragraph = paragraphOf(id)
      for (const token of ['*Problem*', '*Decision*', '*Not done*']) assert.include(paragraph, token, `${id}: le falta ${token}`)
    }
    assert.include(paragraphOf('R2-05'), 'is shadowed **without** the rank check of 3G · W3')
    assert.include(paragraphOf('R2-02'), 'every multi-owner `--force` now needs\n`--allow-mass-purge`')
    assert.include(unreleased, '### Closure 2 (re-attack of the closure)')
    assert.include(unreleased, '(T-07)')
    // RC2-E: el `--help` de la bandera nombra el tercer disparador.
    assert.include(read('commands/authz_catalog_prune_orphans.ts'), 'or orphans of several owners that still grant (or cannot be counted)')
  })
})

// ---------------------------------------------------------------------------------------------------------------------
// TESTER (re-ataque del cierre 2): las filas que le faltan a la tabla de RC2-B y la letra sin dientes.
// ---------------------------------------------------------------------------------------------------------------------
test.group('TESTER · re-ataque cierre 2', () => {
  /** El manager de la tabla de RC2-B, con outbox y driver espías. */
  function edgeManager(t: Awaited<ReturnType<typeof threeTenants>>, outbox: boolean, extra: Record<string, unknown> = {}) {
    const queued: unknown[] = []
    const driverCalls: string[] = []
    const resolveChain = resolveChainFrom(t.tree)
    const manager = new AuthorizationManager({
      default: 'database',
      drivers: {
        database: () => {
          const driver: any = new DatabaseAuthorizationDriver({ resolveChain })
          driver.onScopeMoved = async () => void driverCalls.push('moved')
          driver.onScopeAttached = async () => void driverCalls.push('attached')
          return driver
        },
      },
      scopes: {
        resolveChain,
        descendantsOf: descendantsFrom(t.tree),
        maxDepth: 3,
        ...(outbox
          ? {
              outbox: {
                enqueue: async (change: unknown) => {
                  queued.push(change)
                  return { id: queued.length }
                },
                pending: async () => [],
                markApplied: async () => {},
                markFailed: async () => {},
              },
            }
          : {}),
      },
      delegablePermissions: DELEGABLE,
      warnOnOptInSecurity: false,
      ...extra,
    } as any)
    return { manager, queued, driverCalls }
  }

  /**
   * La fila que le falta al «bloque de contención» de RC2-B: `requireWithin: 'non-root'` con `within: app`. El CHANGELOG
   * dice que el bloque —exigido, `'non-root'`, destino, origen— va ENTERO antes del ciclo y del techo; la tabla de 60
   * filas solo tiene `requireWithin: true`. Mutante R8 (juzgar la arista antes cuando `within` es la raíz) ⇒ vivo sin
   * estas 12 filas.
   */
  for (const op of ['moved', 'attached'] as const) {
    for (const edge of ['ok', 'ciclo', 'profunda'] as const) {
      for (const outbox of [true, false]) {
        test(`TESTER · RC2-B · tabla · ${op} requireWithin='non-root' within=app arista=${edge} outbox=${outbox} ⇒ E_AUTHZ_WITHIN_ROOT_FORBIDDEN`, async ({ assert }) => {
          const t = await threeTenants()
          const unitA2: ScopeRef = { type: 'unit', uuid: uuidv7() }
          const unitA1x: ScopeRef = { type: 'unit', uuid: uuidv7() }
          await t.tree.attach(unitA2, t.orgA)
          await t.tree.attach(unitA1x, t.unitA1)
          const cases: Record<string, [ScopeRef, ScopeRef]> = {
            ok: [unitA2, t.unitA1],
            ciclo: [t.unitA1, unitA1x],
            profunda: [unitA2, unitA1x],
          }
          const [child, parent] = cases[edge]
          const { manager, queued, driverCalls } = edgeManager(t, outbox, { requireWithin: 'non-root' })
          const error = await caught(() => manager.scopes[op](child, parent, { actor: t.adminA, within: APP_SCOPE }))
          assert.equal(error?.code, 'E_AUTHZ_WITHIN_ROOT_FORBIDDEN', `${error?.code}: ${error?.message}`)
          assert.deepEqual([queued.length, driverCalls.length], [0, 0], 'nada encolado ni aplicado')
        })
      }
    }
  }

  /**
   * El «Not done» de RC2-B en el CHANGELOG: «E_AUTHZ_UNKNOWN_SCOPE of the parent still comes first» (oráculo de
   * existencia declarado, cierra en 2.6). Es una frase publicada sin caso: si alguien adelanta `within` a la existencia
   * del padre (el arreglo de 2.6) nada se pone rojo y la fila de Limits queda falsa. Caracterización que se voltea.
   */
  test('TESTER · límite declarado rotación 2 · RC2-B: en moved/attached con within ajeno, un PADRE desconocido sigue siendo UNKNOWN_SCOPE (antes que NOT_WITHIN) y uno ajeno que existe NOT_WITHIN; se voltea en 2.6', async ({ assert }) => {
    const t = await threeTenants()
    const { manager, queued, driverCalls } = edgeManager(t, true)
    const opts = { actor: t.adminA, within: t.orgA }
    const ghost: ScopeRef = { type: 'unit', uuid: uuidv7() }
    for (const op of ['moved', 'attached'] as const) {
      const child = op === 'moved' ? t.unitA1 : ({ type: 'unit', uuid: uuidv7() } as ScopeRef)
      const missing = await caught(() => manager.scopes[op](child, ghost, opts))
      const foreign = await caught(() => manager.scopes[op](child, t.unitB1, opts))
      assert.equal(missing?.code, 'E_AUTHZ_UNKNOWN_SCOPE', `${op}: ${missing?.message}`)
      assert.equal(foreign?.code, 'E_AUTHZ_NOT_WITHIN', `${op}: ${foreign?.message}`)
    }
    assert.deepEqual([queued.length, driverCalls.length], [0, 0])
  })

  /** Letra sin dientes del cierre 2 (mutantes D1–D4: los cuatro vivos con el spec del implementador). */
  test('TESTER · letra del cierre 2: «not where» del oráculo, las dos consecuencias de RC2-B, el párrafo RC2-C del CHANGELOG y el orden «sin within» de Containment', ({ assert }) => {
    const readme = read('README.md')
    const oracle = readme.split('\n').find((line) => line.startsWith('| **`E_AUTHZ_UNKNOWN_SCOPE` vs `E_AUTHZ_NOT_WITHIN`'))!
    assert.include(oracle, 'learns that it exists *somewhere else*, not where')
    const containment = readme.slice(readme.indexOf('**Containment.**'), readme.indexOf('**Containment.**') + 4000)
    assert.include(containment, 'without `within`, or with one that passes, the order of the other errors does not change')
    const changelog = read('CHANGELOG.md')
    const unreleased = changelog.slice(0, changelog.search(/^## \[2\.5\.0-alpha\.4\]/m))
    const rc2b = unreleased.split(/\n(?=\*\*)/).find((p) => /^\*\*[^*]*\(RC2-B\)\.\*\*/.test(p))!
    assert.include(rc2b, '`E_AUTHZ_WITHIN_REQUIRED` now comes before the cycle and the depth (it came after)')
    assert.include(rc2b, '`E_AUTHZ_UNKNOWN_SCOPE` of the origin comes before the depth')
    assert.include(rc2b, '`E_AUTHZ_UNKNOWN_SCOPE` of the parent still comes first')
    for (const id of ['RC2-C', 'RC2-D']) {
      const paragraph = unreleased.split(/\n(?=\*\*)/).filter((p) => p.startsWith(`**Declared, not fixed (${id})`))
      assert.lengthOf(paragraph, 1, `el párrafo «Declared, not fixed (${id})» del CHANGELOG`)
    }
  })
})
