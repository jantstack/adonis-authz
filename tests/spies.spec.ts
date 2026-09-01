/**
 * Coste observable de las operaciones: cuántas veces tocan el árbol del
 * consumidor y el backend. No es semántica (eso lo juzga el contrato); es la
 * factura actual, fijada para que cambie a propósito.
 *
 * `authorize` con una cadena de 3 (unit → org → app) resuelve ancestros UNA
 * vez en ambos drivers. En Fase 2 el memo por request bajará este número en
 * llamadas repetidas y en Fase 3b el modo facts lo dejará en 0: cada cambio
 * reescribe este test conscientemente.
 */

import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import { AuthorizationManager } from '../src/manager.js'
import { memoryScopeTree, resolveChainFrom } from '../src/testing/main.js'
import type { ContractScopeTree } from '../src/testing/main.js'
import { APP_SCOPE } from '../src/types.js'
import type { AuthorizationDriver, ScopeRef, ScopeChainResolver } from '../src/types.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { syncAuthzCatalog } from '../src/catalog.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { countCalls, countQueries, withFailing } from './helpers/spies.js'

const CATALOG = {
  permissions: [{ slug: 'docs:write' }],
  roles: [{ slug: 'editor', scopeType: 'app', permissions: ['docs:write'] }],
}

/**
 * El driver recibe una función que delega en `holder.resolveChain` en
 * cada llamada: así el contador puede sustituir el método DESPUÉS de
 * construir el driver y seguir viendo las llamadas.
 */
function makeResolverHolder(tree: ContractScopeTree) {
  const holder = { resolveChain: resolveChainFrom(tree) }
  const resolver: ScopeChainResolver = (scope) => holder.resolveChain(scope)
  return { holder, resolver }
}

async function threeLevelTree(): Promise<{ tree: ContractScopeTree; unit: ScopeRef }> {
  const tree = memoryScopeTree()
  const org: ScopeRef = { type: 'organization', uuid: uuidv7() }
  const unit: ScopeRef = { type: 'unit', uuid: uuidv7() }
  await tree.attach(org, APP_SCOPE)
  await tree.attach(unit, org)
  return { tree, unit }
}

interface SpiedDriver {
  name: string
  make(resolver: ScopeChainResolver): Promise<AuthorizationDriver>
  teardown(): Promise<void>
  /**
   * Llamadas al backend de HECHOS durante `fn` (SQL en database, cliente FGA
   * en openfga). Las lecturas del catálogo y las revalidaciones de su
   * versión (2D · F1) no son hechos y se cuentan aparte (`versionChecks`).
   */
  backendCalls(driver: AuthorizationDriver, fn: () => Promise<void>): Promise<number>
  /**
   * Llamadas al backend de hechos que cuesta UN `authorize` con la cadena de
   * 3 y un rol que concede en la raíz (2A · A2): `database` = 2 consultas
   * (denies, asignaciones); `openfga` = 1 batchCheck (denies + roles en la
   * misma request; antes 2).
   */
  factsPerAuthorize: number
  /**
   * Llamadas al backend de hechos que cuesta `authorizeMany` de N scopes
   * (2B · B6): `database` compone N `authorize` (2 por scope, 1 si el deny
   * corta antes de mirar las asignaciones); `openfga` usa UN batchCheck para
   * todos (el SDK trocea a 50 por su cuenta).
   */
  factsPerAuthorizeMany(n: number, deniedPositions: number): number
}

/** Consultas que LEEN el catálogo; el join de hechos con los vínculos no cuenta. */
function catalogReads(queries: Array<{ sql: string }>): number {
  return queries.filter((q) => /from\s+[`"]?authz_(permissions|roles|role_permissions)[`"]?/i.test(q.sql)).length
}

/** Revalidaciones del memo contra la versión compartida (2D · F1): un SELECT por clave primaria. */
function versionChecks(queries: Array<{ sql: string }>): number {
  return queries.filter((q) => /from\s+[`"]?authz_catalog_version[`"]?/i.test(q.sql)).length
}

/** Consultas de HECHOS: todo lo que no es catálogo ni revalidación. */
function factsQueries(queries: Array<{ sql: string }>): number {
  return queries.length - catalogReads(queries) - versionChecks(queries)
}


const drivers: SpiedDriver[] = [
  {
    name: 'database',
    make: async (resolveChain) => new DatabaseAuthorizationDriver({ resolveChain }),
    teardown: async () => {},
    backendCalls: async (_driver, fn) => factsQueries((await countQueries(fn)).queries),
    factsPerAuthorize: 2,
    factsPerAuthorizeMany: (n, denied) => 2 * n - denied,
  },
]

/**
 * **Aquí ya no hay entrada `openfga`** (3b-2k · K2). Este grupo mide el COSTE
 * por operación con `authorize` pasando por el árbol del consumidor: «resuelve
 * ancestros exactamente 1 vez», «si el resolutor falla, authorize no cae a un
 * false silencioso», «authorizeMany resuelve cada scope una vez». Con el modo
 * `resolver` borrado, `openfga` **es** `facts` y ninguna de esas tres frases
 * es cierta de él: `authorize` es un `Check` y no llama al resolutor (par de
 * capacidad `singleCheckAuthorize`), y con el resolutor caído RESPONDE (par
 * `hierarchyFacts`). Medirlo aquí exigiría además espejar el árbol del test
 * en el store y proyectar el catálogo, que es justo lo que el harness del
 * juez hace.
 *
 * Dónde vive ahora esa evidencia, toda contra el driver real:
 *  - las requests por primitiva en `facts` —`{check: 1, batchCheck: 0}`,
 *    `resolveChain: 0`, un `batchCheck` de N items en `authorizeMany`, el
 *    memo del catálogo— las cuenta `tests/openfga_facts.spec.ts` con un store
 *    en memoria y espías de `check`/`batchCheck`/resolutor;
 *  - «`authorize` no consulta el árbol» y «la membresía sí» son los pares
 *    `singleCheckAuthorize` y `roleInheritanceNative` del juez, con un espía
 *    sobre `chainOf`, contra el `:8101`;
 *  - «el resolutor caído no tumba la decisión, y todo lo demás sí» es el par
 *    `hierarchyFacts` (3b-2k · K1).
 */

for (const spied of drivers) {
  test.group(`espías [${spied.name}]`, (group) => {
    group.each.setup(async () => {
      await cleanAuthzTables()
      await syncAuthzCatalog(CATALOG)
    })
    group.teardown(() => spied.teardown())

    test('authorize con cadena de 3 resuelve ancestros exactamente 1 vez', async ({ assert }) => {
      const { tree, unit } = await threeLevelTree()
      const { holder, resolver } = makeResolverHolder(tree)
      const driver = await spied.make(resolver)
      const alice = { type: 'users', uuid: uuidv7() }
      await driver.grant(alice, 'editor', APP_SCOPE)

      const counter = countCalls(holder, ['resolveChain'])
      try {
        assert.isTrue(await driver.authorize(alice, 'docs:write', unit))
        assert.equal(counter.counts.resolveChain, 1)
      } finally {
        counter.restore()
      }
    })

    test('si el resolutor falla, authorize no cae a un false silencioso', async ({ assert }) => {
      // El árbol del consumidor es una dependencia más: su caída se nota,
      // igual que la del backend (invariante 5).
      const { tree, unit } = await threeLevelTree()
      const { holder, resolver } = makeResolverHolder(tree)
      const driver = await spied.make(resolver)
      const alice = { type: 'users', uuid: uuidv7() }
      await driver.grant(alice, 'editor', APP_SCOPE)

      let caught: any
      try {
        await withFailing(holder, 'resolveChain', () => driver.authorize(alice, 'docs:write', unit))
        assert.fail('debería haber rechazado')
      } catch (error) {
        caught = error
      }
      // Clasificado como caída de una dependencia (503, código propio), con
      // el error del consumidor como causa: ni crudo ni disfrazado de bug.
      assert.equal(caught.status, 503)
      assert.equal(caught.code, 'E_AUTHZ_RESOLVER_FAILED')
      assert.equal(caught.cause?.message, 'resolveChain caído')
      // Y al restaurarlo, vuelve a responder.
      assert.isTrue(await driver.authorize(alice, 'docs:write', unit))
    })

    test('un ancestro inválido devuelto por el resolutor es 503 E_AUTHZ_RESOLVER_FAILED, no un 422', async ({
      assert,
    }) => {
      // D13 (auditor H11). La pregunta era válida; lo inválido es la RESPUESTA
      // del árbol (`{app, 'X'}`, `{organization, 'a|b'}`, un no-array): es un
      // fallo de la dependencia, no del llamante, y se clasifica como tal.
      const { tree, unit } = await threeLevelTree()
      const { holder, resolver } = makeResolverHolder(tree)
      const driver = await spied.make(resolver)
      const alice = { type: 'users', uuid: uuidv7() }
      await driver.grant(alice, 'editor', APP_SCOPE)

      // 2.5-B · K1 (invariante 17): el elemento 0 tiene que ser el PROPIO
      // scope canónico. Una cadena vacía, o una cuyo elemento 0 sea otro
      // scope —aunque esté bien formado—, es una respuesta que el llamante
      // no pidió: 503, nunca una identidad sustituida en silencio (con la
      // que el deny de `unit` se escribiría bajo `organization`).
      const original = holder.resolveChain
      for (const bad of [
        [{ type: 'app', uuid: 'X' }],
        [{ type: 'organization', uuid: 'a|b' }, APP_SCOPE],
        [{ type: 'organization' }],
        'no-es-un-array',
        [],
        [{ type: 'organization', uuid: uuidv7() }, APP_SCOPE],
        [{ type: 'unit', uuid: uuidv7() }, APP_SCOPE],
      ]) {
        holder.resolveChain = async () => bad as any
        let caught: any
        try {
          await driver.authorize(alice, 'docs:write', unit)
          assert.fail(`${JSON.stringify(bad)}: debería haber rechazado`)
        } catch (error) {
          caught = error
        } finally {
          holder.resolveChain = original
        }
        assert.equal(caught.status, 503, JSON.stringify(bad))
        assert.equal(caught.code, 'E_AUTHZ_RESOLVER_FAILED', JSON.stringify(bad))
      }
      assert.isTrue(await driver.authorize(alice, 'docs:write', unit))

      // El inverso: una cadena cuyo elemento 0 es el MISMO id escrito de
      // otra forma (guiones quitados: lo que devuelve el tipo `uuid` de PG)
      // es la canonicalización que el puerto existe para admitir, no un
      // fallo; si la comparación fuera `===` esto sería un 503.
      const canonical: ScopeRef = { type: 'unit', uuid: unit.uuid!.replaceAll('-', '') }
      assert.notEqual(canonical.uuid, unit.uuid)
      holder.resolveChain = async () => [canonical, APP_SCOPE]
      try {
        assert.isTrue(
          await driver.authorize(alice, 'docs:write', unit),
          'el mismo id escrito sin guiones es la canonicalización que el puerto admite, no un 503'
        )
      } finally {
        holder.resolveChain = original
      }
    })

    test('100 authorize seguidos leen el catálogo una vez (3 consultas), lo revalidan una vez por pregunta y pagan solo los hechos (2A · A1/A2, 2D · F1)', async ({
      assert,
    }) => {
      // Antes: `database` leía `authz_permissions` en cada pregunta (100) y
      // `openfga` además los roles que conceden (200), y openfga hacía DOS
      // batchCheck por pregunta. Ahora: una carga del catálogo por driver,
      // UNA revalidación (SELECT por clave primaria a `authz_catalog_version`)
      // por pregunta y, además, solo el backend de hechos (`factsPerAuthorize`).
      const { tree, unit } = await threeLevelTree()
      const { resolver } = makeResolverHolder(tree)
      const driver = await spied.make(resolver)
      const alice = { type: 'users', uuid: uuidv7() }
      await driver.grant(alice, 'editor', APP_SCOPE)

      // El grant ya cargó el memo: lo que se mide es el régimen estable.
      const { queries } = await countQueries(async () => {
        const calls = await spied.backendCalls(driver, async () => {
          for (let i = 0; i < 100; i++) assert.isTrue(await driver.authorize(alice, 'docs:write', unit))
        })
        assert.equal(calls, 100 * spied.factsPerAuthorize)
      })
      assert.equal(catalogReads(queries), 0)
      assert.equal(versionChecks(queries), 100, 'una revalidación por pregunta, ni una más (una foto por operación)')

      // Y desde frío (memo invalidado): exactamente una carga de tres consultas.
      ;(driver as any).catalog.invalidate()
      const { queries: cold } = await countQueries(async () => {
        for (let i = 0; i < 100; i++) assert.isTrue(await driver.authorize(alice, 'docs:write', unit))
      })
      assert.equal(catalogReads(cold), 3)
      assert.equal(versionChecks(cold), 100)
    })

    test('forRequest(): las lecturas de una vista resuelven cada scope una vez; las escrituras, en fresco (2A · A3)', async ({
      assert,
    }) => {
      const { tree, unit } = await threeLevelTree()
      const { holder, resolver } = makeResolverHolder(tree)
      const driver = await spied.make(resolver)
      const manager = new AuthorizationManager({
        default: spied.name,
        drivers: { [spied.name]: () => driver },
        scopes: { resolveChain: resolver },
        warnOnOptInSecurity: false,
      })
      const alice = { type: 'users', uuid: uuidv7() }
      await manager.grant(alice, 'editor', APP_SCOPE)

      const counter = countCalls(holder, ['resolveChain'])
      try {
        const view = manager.forRequest()
        // Diez lecturas sobre el mismo scope: UNA llamada al árbol.
        for (let i = 0; i < 10; i++) assert.isTrue(await view.authorize(alice, 'docs:write', unit))
        assert.isTrue(await view.hasRole(alice, 'editor', unit))
        assert.deepEqual(await view.listRoles(alice, unit), [])
        assert.equal(counter.counts.resolveChain, 1)

        // Una escritura en la misma vista resuelve en fresco (auditor C3/E3):
        // `deny` y `grant` validan el scope contra el árbol, sin memo.
        await view.deny(alice, 'docs:write', unit)
        assert.equal(counter.counts.resolveChain, 2)
        await view.grant(alice, 'editor', APP_SCOPE)
        assert.equal(counter.counts.resolveChain, 2, 'la raíz nunca se pregunta')
        // Y el memo es de ANCESTROS, no de decisiones: la respuesta cambia.
        assert.isFalse(await view.authorize(alice, 'docs:write', unit))
        assert.equal(counter.counts.resolveChain, 2)
        // `removeDeny`/`revoke` borran en el scope exacto, pero con su
        // identidad CANÓNICA (2.5-B · K1): una llamada al árbol, en fresco.
        await view.removeDeny(alice, 'docs:write', unit)
        assert.equal(counter.counts.resolveChain, 3)
        assert.isTrue(await view.authorize(alice, 'docs:write', unit))
        assert.equal(counter.counts.resolveChain, 3)

        // Fuera de la vista, cada lectura pregunta al árbol.
        await manager.authorize(alice, 'docs:write', unit)
        await manager.authorize(alice, 'docs:write', unit)
        assert.equal(counter.counts.resolveChain, 5)
        // Otra vista, otro memo.
        await manager.forRequest().authorize(alice, 'docs:write', unit)
        assert.equal(counter.counts.resolveChain, 6)
        // `scopes.*` (escritura del árbol) también resuelve en fresco: el
        // padre (existe, sin ciclo) y el hijo (su identidad canónica, si el
        // árbol ya lo conoce — K1).
        const org2 = { type: 'organization', uuid: uuidv7() }
        await tree.attach(org2, APP_SCOPE)
        await view.scopes.attached({ type: 'unit', uuid: uuidv7() }, org2)
        assert.equal(counter.counts.resolveChain, 8)
      } finally {
        counter.restore()
      }
    })

    test('authorizeMany: N scopes cuestan lo declarado (openfga: 1 batchCheck), resuelven cada scope una vez y el vacío no toca nada (2B · B6)', async ({
      assert,
    }) => {
      const tree = memoryScopeTree()
      const org: ScopeRef = { type: 'organization', uuid: uuidv7() }
      await tree.attach(org, APP_SCOPE)
      const units: ScopeRef[] = []
      for (let i = 0; i < 10; i++) {
        const unit: ScopeRef = { type: 'unit', uuid: uuidv7() }
        await tree.attach(unit, org)
        units.push(unit)
      }
      const { holder, resolver } = makeResolverHolder(tree)
      const driver = await spied.make(resolver)
      const manager = new AuthorizationManager({
        default: spied.name,
        drivers: { [spied.name]: () => driver },
        scopes: { resolveChain: resolver },
        warnOnOptInSecurity: false,
      })
      const alice = { type: 'users', uuid: uuidv7() }
      await manager.grant(alice, 'editor', APP_SCOPE)
      await manager.deny(alice, 'docs:write', units[3])

      const counter = countCalls(holder, ['resolveChain'])
      try {
        const scopes = [...units, ...units]
        const calls = await spied.backendCalls(driver, async () => {
          const results = await manager.authorizeMany(alice, 'docs:write', scopes)
          assert.deepEqual(results, scopes.map((s) => s !== units[3]))
        })
        assert.equal(calls, spied.factsPerAuthorizeMany(scopes.length, 2))
        // 20 posiciones, 10 scopes distintos: cada uno resuelto UNA vez.
        assert.equal(counter.counts.resolveChain, 10)
        counter.reset()
        assert.equal(await spied.backendCalls(driver, async () => void assert.deepEqual(await manager.authorizeMany(alice, 'docs:write', []), [])), 0)
        assert.equal(counter.counts.resolveChain, 0)
      } finally {
        counter.restore()
      }
    })

    test('effectivePermissions con cadena de 3 lee roles y denies UNA vez por sujeto (≤ 2 lecturas de hechos), no 2 por nivel (2D · G5)', async ({
      assert,
    }) => {
      // Antes: `listRoles` + `listDenies` por nivel = 2N lecturas (openfga:
      // 2N `Read` paginados). Ahora: `rolesInChain` (una lectura) + `listDenies`
      // del sujeto (una lectura), en ambos drivers.
      const { tree, unit } = await threeLevelTree()
      const { resolver } = makeResolverHolder(tree)
      const driver = await spied.make(resolver)
      const manager = new AuthorizationManager({
        default: spied.name,
        drivers: { [spied.name]: () => driver },
        scopes: { resolveChain: resolver },
        warnOnOptInSecurity: false,
      })
      const alice = { type: 'users', uuid: uuidv7() }
      await manager.grant(alice, 'editor', APP_SCOPE)
      assert.deepEqual(await manager.effectivePermissions(alice, unit), ['docs:write'])
      const calls = await spied.backendCalls(driver, async () => {
        assert.deepEqual(await manager.effectivePermissions(alice, unit), ['docs:write'])
      })
      assert.isAtMost(calls, 2)
      await manager.deny(alice, 'docs:write', unit)
      assert.deepEqual(await manager.effectivePermissions(alice, unit), [])
    })

    test('una identidad inválida se rechaza con 0 llamadas al backend', async ({ assert }) => {
      // L0.5/L0.10/L0.15: la validación va ANTES de catálogo, árbol y hechos.
      // No es solo coste: una escritura a medias (`user:undefined` en FGA)
      // era el defecto. Cero consultas es la prueba de que no hay rastro.
      const { tree } = await threeLevelTree()
      const { resolver } = makeResolverHolder(tree)
      const driver = await spied.make(resolver)
      const bad: Array<() => Promise<unknown>> = [
        () => driver.grant({ type: 'users', uuid: undefined as any }, 'editor', APP_SCOPE),
        () => driver.grant({ type: 'users', uuid: 'x#y' }, 'editor', APP_SCOPE),
        () => driver.authorize({ type: 'users', uuid: "x' OR '1'='1" }, 'docs:write', APP_SCOPE),
        () => driver.grant({ type: 'users', uuid: uuidv7() }, 'editor', { type: 'app', uuid: 'X' }),
        () =>
          driver.deny({ type: 'users', uuid: uuidv7() }, 'docs:write', {
            type: 'organization',
            uuid: '00000000-0000-0000-0000-000000000000',
          }),
      ]
      for (const call of bad) {
        // Dos medidas, no una: desde 2A/2D `backendCalls` descuenta el
        // catálogo y la revalidación de versión, así que por sí solo ya no
        // ve a un driver que cargue el catálogo (o lea `authz_catalog_version`)
        // ANTES de validar. La segunda cuenta TODAS las consultas: cero es
        // cero — ni hechos, ni catálogo, ni versión.
        const { queries } = await countQueries(async () => {
          const calls = await spied.backendCalls(driver, async () => {
            try {
              await call()
              assert.fail('debería haber rechazado')
            } catch (error: any) {
              assert.equal(error.status, 422)
              assert.equal(error.code, 'E_AUTHZ_INVALID_IDENTITY')
            }
          })
          assert.equal(calls, 0)
        })
        assert.equal(queries.length, 0, 'la validación va antes del catálogo, de su versión, del árbol y de los hechos')
      }
    })
  })
}

/**
 * 3b-1 · T-3b 6/7 (tester 3F · §6.6 y §6.7): dos costes que la Fase 3
 * DOCUMENTÓ y nadie medía. Uno es del catálogo (una consulta en lote dentro
 * del cerrojo, no una por rol) y el otro del manager (lo que cuesta declarar
 * `hooks.onWrite`). Los dos van aquí, que es donde vive la factura.
 */
test.group('espías — costes documentados de la Fase 3 (3b-1 · T-3b)', (group) => {
  group.each.setup(cleanAuthzTables)

  /** Consultas a `authz_roles` que EXCLUYEN al owner global: la búsqueda de homónimos locales. */
  function localHomonymLookups(queries: Array<{ sql: string }>): number {
    return queries.filter(
      (q) => /from\s+[`"]?authz_roles[`"]?/i.test(q.sql) && /owner_scope_key/i.test(q.sql) && /\bnot\b|<>|!=/i.test(q.sql)
    ).length
  }

  test('T-3b 6 (T2): syncAuthzCatalog busca los homónimos LOCALES en UNA consulta en lote, no una por rol del spec — corre con el cerrojo de authz_catalog_version sostenido', async ({
    assert,
  }) => {
    // 3F · T2 lo cambió a `whereIn` porque la sección crítica alargada hace
    // probable el 503 `E_AUTHZ_BACKEND_TIMEOUT` de los `defineScopedRole`
    // concurrentes. Sin este contador, volver a una consulta por rol no lo
    // nota nadie.
    const { withAuthzCatalogWrite } = await import('../src/catalog_cache.js')
    await syncAuthzCatalog({ permissions: [{ slug: 'docs:write' }], roles: [] })
    const slugs = ['uno', 'dos', 'tres', 'cuatro']
    await withAuthzCatalogWrite(async (trx) => {
      const now = new Date()
      await trx.table('authz_roles').insert(
        slugs.map((slug, i) => ({
          uuid: uuidv7(), slug, name: slug, scope_type: 'unit', rank: 1,
          owner_scope_key: `organization|org-${i}`, created_at: now, updated_at: now,
        }))
      )
    })
    const spec = {
      permissions: [{ slug: 'docs:write' }],
      roles: slugs.map((slug) => ({ slug, scopeType: 'unit' as const, permissions: ['docs:write'] })),
    }
    const { result, queries } = await countQueries(() => syncAuthzCatalog(spec))
    assert.lengthOf(result.shadowedByGlobal, slugs.length, 'los cuatro locales quedan ensombrecidos')
    assert.equal(localHomonymLookups(queries), 1, 'UNA consulta en lote para los cuatro roles del spec')
  })

  test('T-3b 7 (T4): declarar hooks.onWrite cuesta un resolveChain FRESCO por escritura — el memo de forRequest() no lo absorbe', async ({
    assert,
  }) => {
    // Lo que el README promete desde 3F · T4 («no es gratis: un resolveChain
    // fresco —no el memo de forRequest()— más una vista de catálogo POR
    // escritura; declara el hook cuando quieras auditoría, no por defecto»).
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:write' }],
      roles: [{ slug: 'unit-editor', scopeType: 'unit', permissions: ['docs:write'] }],
    })
    const { tree, unit } = await threeLevelTree()
    const { holder, resolver } = makeResolverHolder(tree)
    const config = (hooks: Record<string, unknown>) =>
      new AuthorizationManager({
        default: 'database',
        drivers: { database: () => new DatabaseAuthorizationDriver({ resolveChain: resolver }) },
        scopes: { resolveChain: resolver },
        warnOnOptInSecurity: false,
        ...hooks,
      } as any)
    const alice = { type: 'users', uuid: uuidv7() }

    const medir = async (authz: AuthorizationManager, fn: (m: any) => Promise<unknown>): Promise<number> => {
      await authz.driver()
      const counter = countCalls(holder, ['resolveChain'])
      try {
        await fn(authz)
        return counter.counts.resolveChain
      } finally {
        counter.restore()
      }
    }
    const mudo = config({})
    const auditado = config({ hooks: { onWrite: async () => {} } })

    assert.equal(await medir(mudo, (m) => m.grant(alice, 'unit-editor', unit)), 1, 'sin hook: la cadena de la escritura')
    assert.equal(await medir(mudo, (m) => m.revoke(alice, 'unit-editor', unit)), 1)
    assert.equal(await medir(auditado, (m) => m.grant(alice, 'unit-editor', unit)), 2, 'con hook: una más, para resolver el rol del evento')
    assert.equal(await medir(auditado, (m) => m.revoke(alice, 'unit-editor', unit)), 2)

    // …y es FRESCO: dentro de una vista de `forRequest()` —donde las
    // LECTURAS sí memoizan la cadena— el hook sigue costando la suya.
    const vistaMuda = mudo.forRequest()
    assert.equal(
      await medir(mudo, async () => {
        await vistaMuda.authorize(alice, 'docs:write', unit)
        await vistaMuda.authorize(alice, 'docs:write', unit)
      }),
      1,
      'dos lecturas en la misma vista: una sola resolución'
    )
    const vista = auditado.forRequest()
    assert.equal(await medir(auditado, () => vista.grant(alice, 'unit-editor', unit)), 2, 'el memo de la vista no absorbe la del hook')

    // …y con el memo YA CALIENTE, que es el caso que distingue de verdad.
    // Con la vista recién creada las dos resoluciones son forzosamente dos
    // llamadas al árbol (el memo está vacío cuando llega la escritura), así
    // que la aserción de arriba pasa igual si el hook leyera el memo: solo
    // este caso separa «fresco» de «memoizado». Y la frescura no es un
    // detalle de coste — el evento de auditoría tiene que describir el árbol
    // de AHORA, no la foto con la que empezó la petición.
    const caliente = auditado.forRequest()
    await caliente.authorize(alice, 'docs:write', unit) // el memo queda poblado
    assert.equal(
      await medir(auditado, () => caliente.grant(alice, 'unit-editor', unit)),
      2,
      'memo caliente: la escritura y el hook siguen resolviendo cada uno lo suyo, en fresco'
    )
    const calienteMuda = mudo.forRequest()
    await calienteMuda.authorize(alice, 'docs:write', unit)
    assert.equal(
      await medir(mudo, () => calienteMuda.grant(alice, 'unit-editor', unit)),
      1,
      'y sin hook sigue costando una: la segunda es del hook, no del memo'
    )
  })
})
