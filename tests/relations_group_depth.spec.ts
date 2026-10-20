/**
 * **Lote «antes de RC» · R1 — el límite de anidación de grupos SEGÚN EL DRIVER** (decisiones del dueño 2026-10-17 (5) y
 * (5-bis), opción (a); F0 · M-c). La propiedad pura y los mutantes viven en `guard_surface.spec.ts`
 * (`relations.group.depth`); aquí los casos de MOTOR (los cuatro modos de `TEST_DB`) y, con `OPENFGA_TEST_URL`, los del
 * servidor real:
 *
 *  - `database` SIN límite por defecto (una cadena de 30 entra) y con el opt-in (`database.enforceGroupDepth`) el 422
 *    con cero escrituras y CERO eventos por el manager, la unión `alto + 1 + bajo`, la letra (el `message` es del tenant;
 *    `OPENFGA_RESOLVE_NODE_LIMIT` en `details`, no enumerable) y la carrera entre transacciones DECLARADA (pg/mysql);
 *  - la validación de la config al ARRANCAR (500, no 422);
 *  - la fila de «Limits», atada a las constantes;
 *  - contra OpenFGA: la calibración REAL (22 en v1.19 por defecto), las dos caras en el borde (miembro T, no-miembro con
 *    membresía F, sin 503), la arista 23 ⇒ 422, `maxGroupDepth` mayor que el calibrado ⇒ 500, y el reconcile
 *    `database → openfga` que NIEGA la partición de 23 saltos (cero escrituras) y migra la sana.
 */
import { test } from '@japa/runner'
import { readFile } from 'node:fs/promises'
import { v7 as uuidv7 } from 'uuid'
import db from '@adonisjs/lucid/services/db'
import { defineRelationsConfig } from '../src/relations/define_relations_config.js'
import { DatabaseRelationsDriver } from '../src/drivers/database_relations_driver.js'
import { RelationsManager } from '../src/relations/manager.js'
import { reconcileRelations } from '../src/relations/reconcile.js'
import {
  GROUP_DEPTH_CALIBRATION_BACKOFF_MS,
  GROUP_DEPTH_CALIBRATION_MAX,
  GROUP_DEPTH_CONFIG_MAX,
  GROUP_DEPTH_RECALIBRATION_MIN_INTERVAL_MS,
  GROUP_DEPTH_DEADLINE_MS,
  GROUP_DEPTH_MAX_NODES,
  GROUP_DEPTH_MAX_READS,
  GROUP_DEPTH_MAX_TUPLES,
  RELATIONS_GROUP_DEPTH_MEASURED,
} from '../src/relations/group_depth.js'
import { testEngine } from './helpers/app.js'
import type { RelationsConfig } from '../src/relations/define_relations_config.js'
import type { RelSubject, ScopeRef } from '../src/types.js'

const spec = (extra: Record<string, unknown> = {}) =>
  defineRelationsConfig({ objectTypes: [{ type: 'document', relations: [{ name: 'viewer' }], deny: 'write' }], holderTypes: ['user'], ...extra } as any)
const grp = (id: string): RelSubject => ({ object: { type: 'group', id }, relation: 'member' })
const unit = (): ScopeRef => ({ type: 'unit', uuid: uuidv7() })
const ids = (prefix: string, n: number) => Array.from({ length: n + 1 }, (_, i) => `${prefix}${i}`)

async function chain(driver: { relate: DatabaseRelationsDriver['relate'] }, partition: ScopeRef, names: string[], options?: any) {
  for (let i = 0; i + 1 < names.length; i++) await driver.relate(grp(names[i]), 'member', { type: 'group', id: names[i + 1] }, partition, options)
}

async function caught(run: () => Promise<unknown>): Promise<any> {
  return run().then(
    () => null,
    (error) => error
  )
}

async function rowsIn(partition: ScopeRef): Promise<number> {
  const result: any = await db.from('authz_relations').where('partition_key', `${partition.type}|${partition.uuid}`).count('* as n')
  return Number(result[0].n)
}

test.group('R1 · database — el límite es OPT-IN y, con él, 422 sin escribir ni notificar', () => {
  test('sin database.enforceGroupDepth no hay techo: una cadena de 30 grupos entra (database no tiene techo técnico)', async ({ assert }) => {
    const driver = new DatabaseRelationsDriver(spec({ maxGroupDepth: 22 }))
    assert.isNull(await driver.groupDepthLimit(), 'maxGroupDepth SOLO no activa el gate en database (V2-4: mando aparte)')
    const partition = unit()
    await chain(driver, partition, ids('g', 30))
    assert.equal(await rowsIn(partition), 30)
  })

  test('con el opt-in: la unión alto + 1 + bajo (ninguna mitad excede) ⇒ 422 con cero escrituras y cero eventos; la letra no nombra el backend', async ({ assert }) => {
    const config = spec({ maxGroupDepth: 4, database: { enforceGroupDepth: true } })
    const driver = new DatabaseRelationsDriver(config)
    const events: unknown[] = []
    const manager = new RelationsManager(driver, config, { onRelationWrite: (e) => void events.push(e) })
    const partition = unit()
    await chain(manager, partition, ['a', 'b', 'c'])
    await chain(manager, partition, ['d', 'e'])
    const before = await rowsIn(partition)
    events.length = 0
    // c ⊂ d: a⊂b⊂c (2) + 1 + d⊂e (1) = 4 ⇒ entra; con e ⊂ f antes, 5 ⇒ 422.
    await manager.relate(grp('e'), 'member', { type: 'group', id: 'f' }, partition)
    events.length = 0
    const error = await caught(() => manager.relate(grp('c'), 'member', { type: 'group', id: 'd' }, partition))
    assert.equal(error?.status, 422, error?.message)
    assert.equal(error?.code, 'E_AUTHZ_GROUP_DEPTH_LIMIT')
    assert.equal(error.details.reason, 'too-deep')
    assert.equal(error.details.depth, 5)
    assert.equal(error.details.maxGroupDepth, 4)
    assert.include(error.message, 'el techo es 4')
    assert.include(error.message, 'No se ha escrito nada')
    for (const word of ['openfga', 'OpenFGA', 'OPENFGA_RESOLVE_NODE_LIMIT']) assert.notInclude(error.message, word, `el message es del TENANT: '${word}' va en details`)
    assert.include(error.details.server, 'OPENFGA_RESOLVE_NODE_LIMIT')
    assert.notInclude(JSON.stringify(error), 'OPENFGA_RESOLVE_NODE_LIMIT', 'details NO enumerable')
    assert.equal(await rowsIn(partition), before + 1, 'solo la e⊂f; la c⊂d no se escribió')
    assert.lengthOf(events, 0, '422 ⇒ esa escritura no ocurrió y no hay evento (invariante 13)')
    // La membresía de un HOLDER y una relación de dominio sobre el grupo no son anidación: no pasan por el gate.
    await manager.relate({ type: 'user', uuid: uuidv7() }, 'member', { type: 'group', id: 'a' }, partition)
    await manager.relate(grp('f'), 'viewer', { type: 'document', id: 'x' }, partition)
  })

  test('cierre-2 · D1 (a), A3: por el CONTENEDOR (AuthzProvider → container.make(\'authz.relations\')) con el techo en defineRelationsConfig, la arista que deja 4 saltos con techo 3 ⇒ 422 y cero filas', async ({ assert }) => {
    const { Container } = await import('@adonisjs/fold')
    const { default: AuthzProvider } = await import('../providers/authz_provider.js')
    const { defineConfig } = await import('../src/define_config.js')
    const relationsConfig = spec({ maxGroupDepth: 3, database: { enforceGroupDepth: true } })
    const config = defineConfig({
      default: 'database',
      drivers: {},
      warnOnOptInSecurity: false,
      relations: { config: relationsConfig, drivers: { database: () => new DatabaseRelationsDriver(relationsConfig) } },
    } as any)
    const container = new Container()
    const app = { container, config: { get: (key: string) => (key === 'authorization' ? config : undefined) } }
    new AuthzProvider(app as any).register()
    const relations: RelationsManager = await (container as any).make('authz.relations')
    const partition = unit()
    await chain(relations, partition, ['a', 'b', 'c', 'd'])
    const error = await caught(() => relations.relate(grp('d'), 'member', { type: 'group', id: 'e' }, partition))
    assert.equal(error?.status, 422, error?.message)
    assert.equal(error?.code, 'E_AUTHZ_GROUP_DEPTH_LIMIT')
    assert.equal(error.details.depth, 4)
    assert.equal(await rowsIn(partition), 3, 'la arista que excede no se escribió')
  })

  test('T-6 · dentro de UNA transacción del llamante el conteo ve sus propias aristas (lee por la trx)', async ({ assert }) => {
    const driver = new DatabaseRelationsDriver(spec({ maxGroupDepth: 2, database: { enforceGroupDepth: true } }))
    const partition = unit()
    const trx = await db.transaction()
    try {
      await chain(driver, partition, ['t0', 't1', 't2'], { transaction: trx })
      const error = await caught(() => driver.relate(grp('t2'), 'member', { type: 'group', id: 't3' }, partition, { transaction: trx }))
      assert.equal(error?.code, 'E_AUTHZ_GROUP_DEPTH_LIMIT', error?.message)
    } finally {
      await trx.rollback()
    }
    assert.equal(await rowsIn(partition), 0)
  })

  test('la carrera entre transacciones CONCURRENTES está DECLARADA: cada una ve su foto y las dos entran (pg/mysql)', async ({ assert }) => {
    const driver = new DatabaseRelationsDriver(spec({ maxGroupDepth: 2, database: { enforceGroupDepth: true } }))
    const partition = unit()
    await chain(driver, partition, ['b', 'c'])
    const one = await db.transaction()
    const two = await db.transaction()
    try {
      await driver.relate(grp('a'), 'member', { type: 'group', id: 'b' }, partition, { transaction: one })
      await driver.relate(grp('c'), 'member', { type: 'group', id: 'd' }, partition, { transaction: two })
      await one.commit()
      await two.commit()
    } catch (error) {
      if (!one.isCompleted) await one.rollback()
      if (!two.isCompleted) await two.rollback()
      throw error
    }
    assert.equal(await rowsIn(partition), 3, 'a⊂b⊂c⊂d = 3 saltos con techo 2: el límite DECLARADO (sin cerrojo) — README «Limits»')
  })
    // Cierre de R1 (tester 🟡): fuera de pg/mysql no hay dos transacciones concurrentes que observar (SQLite serializa
    // las escrituras: la segunda espera a la primera o es SQLITE_BUSY) — skip EXPLÍCITO, no un `return` verde.
    .skip(!['pg', 'mysql'].includes(testEngine()), 'solo pg/mysql: SQLite serializa las escrituras (no hay dos fotos concurrentes)')
})

test.group('R1 · la config se valida AL ARRANCAR (500 E_AUTHZ_CONFIG, nunca un gate apagado en silencio)', () => {
  test('maxGroupDepth fuera de 1..97 o false, y database.enforceGroupDepth sin número ⇒ 500; un typo de la clave ⇒ 422 de clave desconocida', ({ assert }) => {
    for (const bad of [0, -1, Number.NaN, '', '24', 24.5, 98, null, true, Number.POSITIVE_INFINITY]) {
      const error = (() => {
        try {
          spec({ maxGroupDepth: bad })
          return null
        } catch (e: any) {
          return e
        }
      })()
      assert.equal(error?.status, 500, `maxGroupDepth ${String(bad)} (${typeof bad})`)
      assert.equal(error?.code, 'E_AUTHZ_CONFIG')
    }
    for (const extra of [{ database: { enforceGroupDepth: true } }, { maxGroupDepth: false, database: { enforceGroupDepth: true } }, { maxGroupDepth: 3, database: { enforceGroupDepth: 'yes' } }]) {
      assert.throws(() => spec(extra), /enforceGroupDepth/)
    }
    assert.throws(() => spec({ maxGroupDepht: 3 }), /maxGroupDepht/)
    const ok: RelationsConfig = spec({ maxGroupDepth: 97, database: { enforceGroupDepth: true } })
    assert.equal(ok.maxGroupDepth, 97)
    assert.isTrue(ok.enforceGroupDepth)
    assert.notProperty(spec(), 'maxGroupDepth', 'sin declararla, la config congelada no la inventa')
  })

  test('la fila de «Limits» del README está atada a las constantes', async ({ assert }) => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    assert.include(readme, `| \`maxGroupDepth\` (\`RELATIONS_GROUP_DEPTH_MEASURED\`) | ${RELATIONS_GROUP_DEPTH_MEASURED} |`)
    assert.include(readme, `1..${GROUP_DEPTH_CONFIG_MAX}`)
    assert.include(readme, `\`GROUP_DEPTH_MAX_NODES\` | ${GROUP_DEPTH_MAX_NODES.toLocaleString('en-US')} |`)
    assert.include(readme, `\`GROUP_DEPTH_MAX_READS\` | ${GROUP_DEPTH_MAX_READS.toLocaleString('en-US')} |`)
    assert.include(readme, `\`GROUP_DEPTH_MAX_TUPLES\` | ${GROUP_DEPTH_MAX_TUPLES.toLocaleString('en-US')} |`)
    assert.include(readme, `\`GROUP_DEPTH_DEADLINE_MS\` | ${GROUP_DEPTH_DEADLINE_MS.toLocaleString('en-US')} ms |`)
    assert.include(readme, 'Switch the `database` ceiling on first', '🟡 5 del auditor: la receta antes del cutover')
    // Cierre-2 de R1 (decisiones del dueño 2026-10-20): D5 (espera, re-calibración, receta de `ready` que NO relanza),
    // D4/P4 (la regla de letra 422/503) y D6/T3 (la precisión del invariante 6 y la ventana de MySQL REPEATABLE READ).
    assert.include(readme, `\`GROUP_DEPTH_CALIBRATION_BACKOFF_MS\` | ${GROUP_DEPTH_CALIBRATION_BACKOFF_MS.toLocaleString('en-US')} ms |`)
    assert.include(readme, `\`GROUP_DEPTH_RECALIBRATION_MIN_INTERVAL_MS\` | ${GROUP_DEPTH_RECALIBRATION_MIN_INTERVAL_MS.toLocaleString('en-US')} ms |`)
    assert.include(readme, "**Lowering the server's limit no longer needs a restart**", 'D5: bajar el límite ya no pide reinicio')
    assert.include(readme, '**Raising it does**', 'D5: subirlo sí')
    assert.include(readme, '**Calibrating at boot (optional) — log, never rethrow.**', 'D5: la receta de ready')
    assert.include(readme, 'and **record the error, do not throw it**:')
    const recipe = readme.slice(readme.indexOf('**Calibrating at boot (optional)'), readme.indexOf('**Planning to move from `database` to `openfga`?'))
    assert.include(recipe, '} catch (error) {', 'la receta captura')
    assert.notMatch(recipe.slice(recipe.indexOf('} catch (error) {'), recipe.indexOf('```', recipe.indexOf('} catch (error) {'))), /\bthrow\b/, 'ROJO (D5): la receta de ready relanza')
    assert.include(readme, '**The rule of the letter: the 422 is neutral, the 503 names the backend.**', 'D4/P4: la regla de letra')
    assert.include(readme, '**One more read goes through it, and only one: the group nesting depth gate of `database`**', 'D6/T3: la precisión del invariante 6')
    assert.include(readme, 'it decides no permission', 'D6/T3: dato de la escritura, no autoridad')
    assert.include(readme, "**under MySQL's REPEATABLE READ the window of that race is the whole life of your transaction**", 'D6/T3: la ventana de RR')
    assert.include(readme, 'A test pins the closed list of reads that go through your transaction — statement by statement and with its table, raw SQL included —', 'D6/T3 + cierre-3 · R-1: el diente P3, nombrado (lecturas, no métodos)')
    // Cierre-3 de R1 (re-ataque): R-2 el deadline del presupuesto es 503 transitorio sin evento, no 422; R-3 el grupo de
    // más de GROUP_DEPTH_MAX_TUPLES holders no se anida en openfga; R-6 la tabla de errores nombra el presupuesto; R-4 la
    // re-calibración la dispara cualquier 503 de profundidad (declarado).
    assert.include(readme, `\`GROUP_DEPTH_DEADLINE_MS\` | ${GROUP_DEPTH_DEADLINE_MS.toLocaleString('en-US')} ms | \`openfga\`, on a nesting \`relate\` | 503 \`E_AUTHZ_BACKEND_UNAVAILABLE\`, transient`, 'ROJO (R-2): la fila del deadline no dice 503')
    assert.notInclude(readme, "422 (`details.budget: 'deadline'`)", 'ROJO (R-2): queda la letra vieja del deadline ⇒ 422')
    assert.include(readme, '**Past the deadline it is a 503, not a 422**', 'R-2: la prosa de Relations')
    assert.include(readme, `| Direct holders of ONE group that is nested, renewed or sits below a nesting edge (\`openfga\`) | \`GROUP_DEPTH_MAX_TUPLES\` | ${GROUP_DEPTH_MAX_TUPLES.toLocaleString('en-US')} |`, 'ROJO (R-3): falta la fila del grupo grande')
    assert.include(readme, `**a group with more than ${GROUP_DEPTH_MAX_TUPLES.toLocaleString('en-US')} direct holders cannot be nested into another group`)
    assert.include(readme, 'whoever can add holders to a group can block every nesting that walks through it')
    assert.include(readme, 'exceeds the check\'s budget of `GROUP_DEPTH_MAX_READS` requests or `GROUP_DEPTH_MAX_TUPLES` tuples read', 'ROJO (R-6): la tabla de errores no nombra el presupuesto')
    assert.include(readme, "Declared: any read's 503 `E_AUTHZ_RESOLUTION_LIMIT` triggers it", 'R-4: límite declarado de la re-calibración')
    assert.equal(GROUP_DEPTH_CALIBRATION_MAX, GROUP_DEPTH_CONFIG_MAX - 1, 'la negativa lleva dos tuplas contextuales más que la positiva')
    assert.equal(RELATIONS_GROUP_DEPTH_MEASURED, 22, 'F0 · M-c: min(24, 22)')
  })
})

const openFgaTestUrl = process.env.OPENFGA_TEST_URL
if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl
  const HOLDERS = { user: 'user' } as const

  async function provision(config: RelationsConfig): Promise<{ storeId: string; modelId: string }> {
    const { OpenFgaClient } = await import('@openfga/sdk')
    const { openFgaFactsModel } = await import('../src/drivers/openfga_facts.js')
    const store = await new OpenFgaClient({ apiUrl }).createStore({ name: `r1-depth-${Date.now()}-${Math.random().toString(36).slice(2, 8)}` })
    const model = await new OpenFgaClient({ apiUrl, storeId: store.id }).writeAuthorizationModel(openFgaFactsModel(HOLDERS, [], { objectTypes: config.objectTypes }))
    return { storeId: store.id!, modelId: model.authorization_model_id! }
  }

  async function dropStore(storeId: string): Promise<void> {
    const { OpenFgaClient } = await import('@openfga/sdk')
    await new OpenFgaClient({ apiUrl, storeId }).deleteStore()
  }

  async function fgaDriver(config: RelationsConfig, store: { storeId: string; modelId: string }) {
    const { OpenFgaRelationsDriver } = await import('../src/drivers/openfga_relations_driver.js')
    return new OpenFgaRelationsDriver(config, { apiUrl, ...store, holderTypes: HOLDERS, timeoutMs: 5_000 })
  }

  test.group('R1 · openfga real — la calibración y el gate contra el servidor', () => {
    test(`la calibración REAL da ${RELATIONS_GROUP_DEPTH_MEASURED} (v1.19, --resolve-node-limit por defecto); en el borde el miembro es T y el no-miembro con membresía F (nunca 503); la arista ${RELATIONS_GROUP_DEPTH_MEASURED + 1} ⇒ 422 sin escribir; maxGroupDepth mayor ⇒ 500`, async ({ assert }) => {
      const config = spec()
      const store = await provision(config)
      try {
        const driver = await fgaDriver(config, store)
        const limit = await driver.groupDepthLimit()
        assert.equal(limit, RELATIONS_GROUP_DEPTH_MEASURED, 'calibrado = min(positiva 24, negativa 22) en v1.19 por defecto')
        const partition = unit()
        const names = ids('g', limit!)
        await chain(driver as any, partition, names)
        const member = { type: 'user', uuid: uuidv7() }
        const outsider = { type: 'user', uuid: uuidv7() }
        await driver.relate(member, 'member', { type: 'group', id: 'g0' }, partition)
        await driver.relate(outsider, 'member', { type: 'group', id: 'h0' }, partition)
        await driver.relate(grp('h0'), 'member', { type: 'group', id: 'h1' }, partition)
        const doc = { type: 'document', id: 'x' }
        await driver.relate(grp(`g${limit}`), 'viewer', doc, partition)
        for (let i = 0; i < 20; i++) {
          assert.isTrue(await driver.check(member, 'viewer', doc, partition), `miembro a ${limit} saltos (tirada ${i})`)
          assert.isFalse(await driver.check(outsider, 'viewer', doc, partition), `no-miembro con membresía a ${limit} saltos (tirada ${i})`)
        }
        const error = await caught(() => driver.relate(grp(`g${limit}`), 'member', { type: 'group', id: `g${limit! + 1}` }, partition))
        assert.equal(error?.code, 'E_AUTHZ_GROUP_DEPTH_LIMIT', error?.message)
        assert.equal(error.details.depth, limit! + 1)
        const { OpenFgaClient } = await import('@openfga/sdk')
        const client = new OpenFgaClient({ apiUrl, storeId: store.storeId })
        const after = await client.read({ object: `group:${partition.type}|${partition.uuid}|g${limit! + 1}`, relation: 'member' })
        assert.lengthOf(after.tuples, 0, 'la arista que excede no está en el store')
        // La app puede BAJAR el techo, nunca subirlo por encima del calibrado.
        const higher = await fgaDriver(spec({ maxGroupDepth: limit! + 1 }), store)
        const config500 = await caught(() => higher.groupDepthLimit())
        assert.equal(config500?.status, 500, config500?.message)
        assert.equal(config500?.code, 'E_AUTHZ_CONFIG')
        assert.include(config500.message, 'OPENFGA_RESOLVE_NODE_LIMIT')
        assert.equal(await (await fgaDriver(spec({ maxGroupDepth: 10 }), store)).groupDepthLimit(), 10)
      } finally {
        await dropStore(store.storeId)
      }
    }).timeout(120_000)

    test(`cierre de R1 · contra el servidor: la arista POR DEBAJO de una cadena de ${RELATIONS_GROUP_DEPTH_MEASURED} (x ⊂ g0) ⇒ 422 (la Read hacia ARRIBA, user=group:…#member + object 'group:', funciona en v1.19); el ciclo ⇒ 422 cycle; renovar una arista de una cadena que ya excede ⇒ 422 y el relate IDÉNTICO es no-op`, async ({ assert }) => {
      const config = spec()
      const store = await provision(config)
      try {
        const driver = await fgaDriver(config, store)
        const limit = (await driver.groupDepthLimit())!
        assert.equal(limit, RELATIONS_GROUP_DEPTH_MEASURED)
        const partition = unit()
        await chain(driver as any, partition, ids('g', limit))
        const { OpenFgaClient } = await import('@openfga/sdk')
        const client = new OpenFgaClient({ apiUrl, storeId: store.storeId })
        const pk = `${partition.type}|${partition.uuid}`
        // La lectura del gate hacia ARRIBA, ejecutada de verdad: los padres de g0 son exactamente g1.
        const parents = await client.read({ user: `group:${pk}|g0#member`, relation: 'member', object: 'group:' })
        assert.deepEqual(parents.tuples.map((t: any) => t.key.object), [`group:${pk}|g1`], 'Read por user + tipo de objeto')
        const below = await caught(() => driver.relate(grp('x'), 'member', { type: 'group', id: 'g0' }, partition))
        assert.equal(below?.code, 'E_AUTHZ_GROUP_DEPTH_LIMIT', below?.message)
        assert.equal(below.details.reason, 'too-deep')
        assert.equal(below.details.depth, limit + 1)
        const cycle = await caught(() => driver.relate(grp(`g${limit}`), 'member', { type: 'group', id: 'g0' }, partition))
        assert.equal(cycle?.code, 'E_AUTHZ_GROUP_DEPTH_LIMIT', cycle?.message)
        assert.equal(cycle.details.reason, 'cycle')
        const none = await client.read({ user: `group:${pk}|x#member`, relation: 'member', object: 'group:' })
        assert.lengthOf(none.tuples, 0, 'x ⊂ g0 no se escribió')
        // Una cadena que YA excede (sembrada con el gate apagado: lo preexistente) con la última arista con caducidad.
        const off = await fgaDriver(spec({ maxGroupDepth: false }), store)
        const deep = unit()
        const at = new Date(Date.now() + 3_600_000)
        await chain(off as any, deep, ids('d', limit))
        await off.relate(grp(`d${limit}`), 'member', { type: 'group', id: `d${limit + 1}` }, deep, { expiresAt: at })
        // Idéntico (misma caducidad) ⇒ no-op, sin 422 (invariante 6).
        assert.isNull(await caught(() => driver.relate(grp(`d${limit}`), 'member', { type: 'group', id: `d${limit + 1}` }, deep, { expiresAt: at })))
        // Renovar (otra caducidad) ⇒ 422 sin tocar la arista.
        const renew = await caught(() => driver.relate(grp(`d${limit}`), 'member', { type: 'group', id: `d${limit + 1}` }, deep, { expiresAt: new Date(at.getTime() + 60_000) }))
        assert.equal(renew?.code, 'E_AUTHZ_GROUP_DEPTH_LIMIT', renew?.message)
        const edge = await client.read({ user: `group:${deep.type}|${deep.uuid}|d${limit}#member`, relation: 'member', object: `group:${deep.type}|${deep.uuid}|d${limit + 1}` })
        assert.lengthOf(edge.tuples, 1)
        assert.equal((edge.tuples[0] as any).key.condition?.context?.valid_until, at.toISOString(), 'la caducidad vieja sigue (cero escrituras)')
      } finally {
        await dropStore(store.storeId)
      }
    }).timeout(120_000)

    test(`reconcile database → openfga: la partición con ${RELATIONS_GROUP_DEPTH_MEASURED + 1} saltos se NIEGA (cero escrituras en ella, también en --dry-run) y la sana migra`, async ({ assert }) => {
      const config = spec()
      const store = await provision(config)
      try {
        const to = await fgaDriver(config, store)
        const from = new DatabaseRelationsDriver(config)
        const deep = unit()
        const fine = unit()
        await chain(from, deep, ids('c', RELATIONS_GROUP_DEPTH_MEASURED + 1))
        await chain(from, fine, ids('k', 3))
        const dry = await reconcileRelations({ from, to, partitions: [deep, fine], dryRun: true, toConfig: config })
        const real = await reconcileRelations({ from, to, partitions: [deep, fine], toConfig: config })
        for (const report of [dry, real]) {
          assert.deepEqual(
            (report.partitionsRefused ?? []).map((r) => [r.partition, r.causes.map((c) => c.reason)]),
            [[`unit|${deep.uuid}`, ['too-deep']]]
          )
          assert.deepEqual(report.tooDeep?.map((t) => [t.depth, t.limit]), [[RELATIONS_GROUP_DEPTH_MEASURED + 1, RELATIONS_GROUP_DEPTH_MEASURED]])
        }
        assert.equal(real.written, 3, 'solo la partición sana')
        assert.lengthOf((await to.enumerateRelations(deep)).tuples, 0, 'la negada: cero escrituras')
        assert.lengthOf((await to.enumerateRelations(fine)).tuples, 3)
      } finally {
        await dropStore(store.storeId)
      }
    }).timeout(120_000)
  })
}
