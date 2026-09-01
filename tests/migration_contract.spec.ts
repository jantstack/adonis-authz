/**
 * 3b-3b · B3 — **el contrato de migración aplicado al par del paquete**
 * (`database` ⇄ `openfga` en modo `facts`), y la prueba de que ese contrato
 * SABE FALLAR.
 *
 * No se juzga con un doble en memoria: el store es el `:8101` real y el árbol
 * es el SQL del harness (`demo_scopes`), así que la precisión de la caducidad
 * y la ortografía del scope se ven en PostgreSQL y en MySQL de verdad.
 */

import { test } from '@japa/runner'
import db from '@adonisjs/lucid/services/db'
import { AuthorizationManager } from '../src/manager.js'
import { sqlScopeEdges } from '../src/sql_descendants.js'
import { resolveChainFrom } from '../src/testing/main.js'
import {
  MIGRATION_CATALOG,
  MIGRATION_PERMISSIONS,
  MIGRATION_QUESTION_COUNT,
  makeMigrationSeed,
  migrationQuestions,
  runMigrationContract,
  runMigrationDirection,
} from '../src/testing/main.js'
import type { MigrationContractHarness } from '../src/testing/main.js'
import { syncAuthzCatalog } from '../src/catalog/catalog.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { OpenFgaAuthorizationDriver, openFgaFactsModel } from '../src/openfga.js'
import { cleanAuthzTables } from './helpers/schema.js'
import { cleanSqlScopeTree, sqlScopeTree } from './helpers/sql_scope_tree.js'

const HOLDER_TYPES = { users: 'user', admins: 'admin' }

test.group('3b-3b · el set fijo de preguntas', () => {
  test('son 448, y son exactamente 168 + 168 + 42 + 24 + 28 + 18', ({ assert }) => {
    const questions = migrationQuestions(makeMigrationSeed())
    assert.lengthOf(questions, MIGRATION_QUESTION_COUNT)
    const byKind = questions.reduce<Record<string, number>>((acc, q) => {
      acc[q.kind] = (acc[q.kind] ?? 0) + 1
      return acc
    }, {})
    assert.deepEqual(byKind, {
      authorize: 168,
      hasRole: 168,
      listRoles: 42,
      listScopes: 24,
      listSubjects: 28,
      listRoleScopes: 18,
    })
    // Y ninguna se repite: 448 preguntas, no 448 llamadas a la misma.
    assert.lengthOf(new Set(questions.map((q) => q.id)), MIGRATION_QUESTION_COUNT)
  })
})

const openFgaTestUrl = process.env.OPENFGA_TEST_URL

if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl
  const stores: string[] = []

  async function dropStores() {
    const { OpenFgaClient } = await import('@openfga/sdk')
    while (stores.length) {
      await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
    }
  }

  /**
   * El par real: `database` sobre `authz_*` y `openfga` en modo `facts` sobre
   * un store nuevo, los dos con el MISMO árbol SQL del consumidor (que no se
   * migra) y el MISMO catálogo local (que tampoco).
   */
  function pairHarness(expectedLosses: MigrationContractHarness['expectedLosses'], mutate?: (drivers: any) => void): MigrationContractHarness {
    return {
      name: 'database ⇄ openfga (facts)',
      a: 'database',
      b: 'openfga',
      expectedLosses,
      makeTree: async () => sqlScopeTree(db),
      seedCatalog: (catalog) => syncAuthzCatalog(catalog),
      cleanup: async () => {
        await cleanAuthzTables()
        await cleanSqlScopeTree(db)
        await dropStores()
      },
      setup: async (tree) => {
        const chain = resolveChainFrom(tree)
        const { OpenFgaClient } = await import('@openfga/sdk')
        const store = await new OpenFgaClient({ apiUrl }).createStore({ name: `migration-${Date.now()}-${stores.length}` })
        stores.push(store.id!)
        const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(
          openFgaFactsModel(HOLDER_TYPES, [...MIGRATION_PERMISSIONS])
        )
        const fga = new OpenFgaAuthorizationDriver({
          apiUrl,
          storeId: store.id!,
          modelId: model.authorization_model_id!,
          holderTypes: HOLDER_TYPES,
          resolveChain: chain,
          acceptScopeDriftRisk: true,
          logger: { warn: () => {} },
        })
        // El marcador de raíz y la proyección del catálogo, ya con el store
        // publicado: en `facts` quien filtra lo que un rol concede es la
        // proyección, no el catálogo local.
        await syncAuthzCatalog(MIGRATION_CATALOG, { projection: fga.catalogProjection() })
        // El árbol del consumidor se ESPEJA en el store (es lo que hace
        // `authorization.scopes.attached` en una app de verdad).
        const attachEdge = tree.attach.bind(tree)
        tree.attach = async (child, parent) => {
          await attachEdge(child, parent)
          await fga.onScopeAttached!(child, parent)
        }
        const database = new DatabaseAuthorizationDriver({ resolveChain: chain })
        const drivers: any = { database, openfga: fga }
        mutate?.(drivers)
        const manager = new AuthorizationManager({
          default: 'database',
          drivers: { database: () => drivers.database, openfga: () => drivers.openfga },
          holderTypes: HOLDER_TYPES,
          scopes: {
            resolveChain: chain,
            enumerateEdges: sqlScopeEdges({
              table: 'demo_scopes',
              uuidColumn: 'uuid',
              parentColumn: 'parent_uuid',
              typeColumn: 'type',
            }),
          },
          warnOnOptInSecurity: false,
        })
        return { reconcile: (options) => manager.reconcile(options as any), drivers }
      },
    }
  }

  /**
   * **Las pérdidas declaradas del par del paquete.** Cada una se midió; el
   * informe del lote dice dónde. Ninguna cambia una respuesta del set fijo, y
   * eso también es una afirmación que el contrato comprueba: si alguna las
   * cambiara sin declarar `changesAnswer`, fallaría.
   */
  const LOSSES: MigrationContractHarness['expectedLosses'] = [
    {
      reason: 'expired',
      why:
        'Una asignación cuyo `expires_at` ya pasó NO concede (invariante 3), así que no se migra: escribirla ' +
        'sería llevar al destino una caducidad muerta. Se pierde la FILA, no una respuesta — y por eso ' +
        '`changesAnswer` no la reclama para ninguna. Se cuenta en las dos direcciones (`authz_assignments` ' +
        'en la ida, la condición `not_expired` de la tupla en la vuelta).',
    },
  ]

  runMigrationContract(pairHarness(LOSSES))

  /* ══ El contrato tiene que SABER FALLAR ═══════════════════════════════════
   * Un contrato que no falla no es una garantía. Aquí se le mete una pérdida
   * NO declarada de las dos formas posibles y se comprueba el rojo.
   * ════════════════════════════════════════════════════════════════════════ */

  test.group('3b-3b · el contrato de migración SABE fallar', (group) => {
    group.each.setup(async () => {
      return async () => {
        await cleanAuthzTables()
        await cleanSqlScopeTree(db)
        await dropStores()
      }
    })

    test('una pérdida REAL que no se declara hace fallar el contrato', async ({ assert }) => {
      const verdict = await runMigrationDirection(pairHarness([]), 'a→b')

      assert.isNotEmpty(verdict.failures, 'con expectedLosses vacío, `expired` no está declarada')
      assert.deepEqual(verdict.declaredButAbsent, [], 'no sobra ninguna declaración: falta una')
      assert.isTrue(
        verdict.reports.some((r) => (r.skipped['expired'] ?? 0) > 0),
        'y la pérdida SÍ ocurrió: está contada en skipped'
      )
    })?.timeout(600_000)

    test('una pérdida DECLARADA que no ocurre también hace fallar el contrato', async ({ assert }) => {
      const verdict = await runMigrationDirection(
        pairHarness([
          ...LOSSES,
          { reason: 'unknown-holder-type', why: 'inventada: en esta siembra no ocurre nunca' },
        ]),
        'a→b'
      )

      assert.deepEqual(verdict.declaredButAbsent, ['unknown-holder-type'])
      assert.isTrue(verdict.failures.some((f) => f.includes('unknown-holder-type')))
    })?.timeout(600_000)

    test('un hecho que se pierde EN SILENCIO cambia una respuesta y no hay pérdida que lo explique', async ({
      assert,
    }) => {
      // El mutante: el ORIGEN se deja un deny por el camino, sin contarlo.
      // Es exactamente la forma de una migración «casi correcta».
      const verdict = await runMigrationDirection(
        pairHarness(LOSSES, (drivers) => {
          const real = drivers.openfga.enumerateFacts.bind(drivers.openfga)
          drivers.openfga.enumerateFacts = async (page: any) => {
            const got = await real(page)
            return { ...got, facts: got.facts.filter((f: any) => f.kind !== 'deny') }
          }
        }),
        'b→a'
      )

      assert.isNotEmpty(verdict.failures)
      assert.isTrue(
        verdict.mismatches.some((m) => m.explainedBy === null && m.question.startsWith('authorize(')),
        'una respuesta de authorize cambió y nada la explica'
      )
      assert.isTrue(verdict.failures.some((f) => f.includes('no hay pérdida declarada')))
    })?.timeout(600_000)

    /**
     * **Lote 3b-4 · C1 — la pérdida que las 448 NO ven.**
     *
     * El caso de arriba se caza porque la pérdida MUEVE una respuesta. Las
     * dos caras de `expectedLosses` cruzan `Object.keys(report.skipped)`, o
     * sea lo que el driver se auto-declara, así que una pérdida que ni
     * cambia una respuesta ni se cuenta pasaba el contrato entero: medido,
     * las TRES combinaciones en verde.
     *
     * El mutante es una «normalización» plausible: el deny de la RAÍZ se
     * emite bajo el scope de un hecho del MISMO holder. El deny sigue en la
     * cadena que bloqueaba, así que las 168 `authorize` responden IGUAL —y
     * las otras 280 ni miran denies—, pero el HECHO sembrado
     * `deny(u4, billing:read, app)` ha desaparecido y nadie lo cuenta.
     * Quien lo caza es el CENSO, que mira el destino hecho a hecho.
     */
    test('lote 3b-4 · C1: una pérdida SILENCIOSA que no mueve ninguna de las 448 la caza el CENSO', async ({
      assert,
    }) => {
      const verdict = await runMigrationDirection(
        pairHarness(LOSSES, (drivers) => {
          const real = drivers.openfga.enumerateFacts.bind(drivers.openfga)
          drivers.openfga.enumerateFacts = async (page: any) => {
            const got = await real(page)
            const anchor = new Map<string, any>()
            for (const fact of got.facts) {
              if (fact.kind === 'assignment') anchor.set(`${fact.holder.type}|${fact.holder.uuid}`, fact.scope)
            }
            const facts = got.facts.map((fact: any) => {
              if (fact.kind !== 'deny' || fact.scope.type !== 'app') return fact
              const moved = anchor.get(`${fact.holder.type}|${fact.holder.uuid}`)
              return moved ? { ...fact, scope: moved } : fact
            })
            return { ...got, facts }
          }
        }),
        'b→a'
      )

      // (a) Las 448 no se enteran: ni una sola respuesta cambia.
      assert.deepEqual(verdict.mismatches, [], 'ninguna de las 448 se mueve: el deny sigue bloqueando lo mismo')
      // (b) Y el driver tampoco lo cuenta: el único motivo visto es la
      //     pérdida declarada de siempre.
      assert.deepEqual(
        [...new Set(verdict.reports.flatMap((r) => Object.keys(r.skipped)))],
        ['expired'],
        'la pérdida no aparece en report.skipped: es SILENCIOSA'
      )
      // (c) Lo caza el censo, y lo NOMBRA.
      assert.lengthOf(verdict.silentLosses, 1)
      assert.match(verdict.silentLosses[0].fact, /^deny users:[0-9a-f-]+ billing:read @ app$/)
      assert.isTrue(verdict.failures.some((f) => f.includes('PÉRDIDA SILENCIOSA')))
      // (d) Y el censo pudo hacerse entero: ambos drivers traen `listDenies`.
      assert.deepEqual(verdict.censusLimits, [])
    })?.timeout(600_000)
  })
}
