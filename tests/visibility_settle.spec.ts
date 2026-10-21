/**
 * **`openfga.roles.visibility.settle`** (lote C · sublote «asentar»; linaje L13): la propiedad y sus controles. El arnés,
 * el dominio y el oráculo viven en `tests/helpers/visibility_settle.ts`; la medición completa (enumeración acotada + PCT
 * 1..2000 + fallos inyectados con el relay REAL, las dos consistencias) en `.claude/reproducciones/loteC-asentar-paso4.ts`
 * y en `.claude/contexto/loteC-asentar-fase2-paso4.md`.
 *
 * **Paso 4 (settle implementado): el control de la fase 1 se INVIERTE.** Los entrelazados que el panel reprodujo (R1, R2,
 * R3, K2, K4, dos `moved` del mismo nodo) y los hallazgos 2/3/4 del panel TREE salen sin OPEN, sin ORPHAN y sin CLOSED no
 * atribuido; el rojo pasa a vivir en los mutantes del settle (paso 5). Lo que SIGUE rojo a propósito es el límite
 * declarado: TREE en línea con dos `moved` concurrentes del MISMO nodo (juez TREE §5, regla 6), juzgado contra el árbol
 * del CONSUMIDOR (`frank@C`, `gina@C`).
 *
 * Las 7 reglas del juez TREE §5 (sustituyen a «0 OPEN y 0 CLOSED» de la fase 1):
 *  1. cara L13 contra el STORE: 0 OPEN, 0 ORPHAN y 0 CLOSED salvo ATRIBUIDO (`closedAttribution`);
 *  2. cara contra el CONSUMIDOR: sin TREE, OPEN(consumidor) = OPEN(store) = 0;
 *  3. TREE nunca en silencio: solo lo eximen `same-node-inline` y `purge-incomplete` (`treeExemption`);
 *  4. sanidad «solo» también en `minimize`;
 *  5. universo con `frank` y `gina`;
 *  6. CONTROL TREE en línea fijado en ROJO;
 *  7. el relay REAL drena lo que falló (`faultCampaign`).
 */
import { readFile } from 'node:fs/promises'
import db from '@adonisjs/lucid/services/db'
import { test } from '@japa/runner'
import { isPartialWrite } from '../src/errors.js'
import { fixedUuid, sdkError } from './helpers/fga_memory_client.js'
import { resolveChainFrom } from '../src/testing/scope_tree.js'
import { SETTLE_MAX_ROUNDS } from '../src/drivers/openfga_driver.js'
import {
  closedAttribution,
  dropSettleRoles,
  enumerationCampaign,
  maintenanceSource,
  seedCatalogLinks,
  faultCampaign,
  oracleSelfCheck,
  OPS,
  pctCampaign,
  raceFaultCampaign,
  runSettleCase,
  seedSettleRoles,
  settleCapCase,
  settleRig,
  ROLES,
  U,
  type CampaignReport,
  type Op,
  type RunResult,
  type RunSpec,
  type TreeName,
} from './helpers/visibility_settle.js'

const isOpen = (kind: string) => kind === 'OPEN-edge' || kind === 'OPEN-grant'
const isClosed = (kind: string) => kind === 'CLOSED-edge' || kind === 'CLOSED-grant'
const LEGIT_SOLO = /E_AUTHZ_(ROLE_NOT_VISIBLE|UNKNOWN_ROLE)/
const summary = (r: RunResult) =>
  `store=${JSON.stringify(r.violations)} consumidor=${JSON.stringify(r.vConsumer.filter((v) => v.kind !== 'TREE'))} ` +
  `ops=${JSON.stringify(r.outcomes)} relay=${JSON.stringify(r.relay)}`
const campaignLine = (label: string, r: CampaignReport) =>
  `${label}: ${r.badCases.length} malos de ${r.runs} (OPEN=${r.open} ORPHAN=${r.orphan} CLOSED=${r.closed}/${r.closedAttributed} atribuidos ` +
  `TREE silenciosos=${r.treeSilent} consumidor sin TREE=${r.consumerOpenNoTree}) — ${r.examples.slice(0, 3).join(' || ')}`

test.group('GS · P · openfga.roles.visibility.settle (lote C · asentar, linaje L13)', (group) => {
  group.setup(async () => {
    await seedSettleRoles()
    return () => dropSettleRoles()
  })

  test('el oráculo independiente: un estado consistente da 0; una arista plantada fuera del owner es OPEN; una quitada, CLOSED', ({ assert }) => {
    const { clean, planted, removed } = oracleSelfCheck()
    assert.deepEqual(clean, [])
    assert.includeMembers(planted.map((v) => v.kind), ['OPEN-edge', 'OPEN-grant'], 'la cara (a) Y la cara (b) del oráculo ven la arista plantada')
    assert.isTrue(planted.some((v) => v.kind === 'OPEN-grant' && v.detail === 'victim@C'), 'la víctima denegada en A concede en C (el fail-open del 🟠)')
    assert.includeMembers(removed.map((v) => v.kind), ['CLOSED-edge', 'CLOSED-grant'])
  })

  /** Regla 4 (juez TREE §5): sin carreras, cada operación sola deja el store coherente en las DOS consistencias. */
  test('regla 4 · sin carreras, en `higher` Y en `minimize`, cada operación sola: 0 violaciones (store y consumidor), 0 TREE y solo los 422 legítimos', async ({ assert }) => {
    const bad: string[] = []
    for (const consistency of ['higher', 'minimize'] as const) {
      for (const tree of ['T1', 'T2', 'T3'] as const) {
        for (const op of OPS) {
          const r = await runSettleCase({ tree, ops: [op], stale: [false], consistency, policy: { kind: 'solo' } })
          if (r.violations.length || r.vConsumer.length) bad.push(`${consistency} ${tree} ${op}: ${summary(r)}`)
          if (r.outcomes[0].status === 'error' && !LEGIT_SOLO.test(r.outcomes[0].code!)) bad.push(`${consistency} ${tree} ${op}: ${r.outcomes[0].code}`)
        }
      }
    }
    // Hallazgo 3 del panel TREE, por su nombre: `churnC` SOLO en `minimize` (T3) dejaba C bajo B en el store y bajo A en el
    // consumidor (el atajo idempotente de `reparent` leía el padre rancio) y `frank@C` OPEN contra el consumidor.
    assert.deepEqual(bad, [])
  }).timeout(60_000)

  /**
   * **El control de la fase 1, INVERTIDO** (paso 4): los entrelazados del panel —árbol, actor 1 ∥ actor 2 que corre ENTERO
   * en el I/O k del actor 1— daban un fail-OPEN persistente con el código de antes del settle; ahora la cara L13 sale
   * limpia (0 OPEN, 0 ORPHAN, 0 CLOSED no atribuido). Más los casos con nombre de los hallazgos 2 y 4 del panel TREE.
   */
  test('CONTROL invertido · los entrelazados del panel (R1, R2, R3, K2, K4, mismo nodo) y los hallazgos 2 y 4 del panel TREE dejan la cara L13 limpia', async ({ assert }) => {
    const named: Array<[string, TreeName, Op, Op, number, [boolean, boolean]]> = [
      ['R1 (🟠 1): projectCatalogRole ∥ moved C fuera del owner', 'T1', 'projectR', 'moveC', 4, [false, false]],
      ['R2 (🟡 2): grant con la cadena vieja ∥ moved', 'T1', 'grantR@C', 'moveC', 2, [false, false]],
      ['R3 (🟡 5): moved C→P ∥ moved P entero tras la arista de C', 'T1', 'moveCtoP', 'moveP', 15, [false, false]],
      ['K2: P bajo X no owner; moved P→A ∥ moved C→Q', 'T3', 'moveP', 'moveCtoQ', 17, [false, false]],
      ['K4: el mover con el memo RANCIO no ve el rol recién definido', 'T1', 'moveC', 'grantR2@C', 1, [true, false]],
      ['dos moved en línea del MISMO nodo (cara L13)', 'T2', 'moveC', 'moveC', 14, [false, false]],
      ['hallazgo 2 (ORPHAN): grant RP ∥ purgeRole RP', 'T1', 'grantRP@P', 'purgeRP', 2, [false, false]],
      ['hallazgo 4 (K4 en la proyección): projectCatalogRole(R2) con memo rancio ∥ grant R2', 'T1', 'projectR2', 'grantR2@C', 1, [true, false]],
      ['hallazgo 4 (K4 en la proyección): grant R2 ∥ projectCatalogRole(R2) con memo rancio', 'T1', 'grantR2@C', 'projectR2', 1, [false, true]],
    ]
    const red: string[] = []
    for (const [label, tree, a1, a2, k, stale] of named) {
      const r = await runSettleCase({ tree, ops: [a1, a2], stale, consistency: 'higher', policy: { kind: 'preempt', k } })
      if (!r.fired) red.push(`${label}: la preempción no disparó (el arnés perdió potencia)`)
      const bad = r.violations.filter((v) => isOpen(v.kind) || v.kind === 'ORPHAN-edge' || isClosed(v.kind))
      if (bad.length) red.push(`${label} (${tree} ${a1}∥${a2}@${k}): ${summary(r)}`)
    }
    assert.deepEqual(red, [])
    const pct = await pctCampaign({ from: 1, to: 400, consistency: 'higher' })
    assert.deepEqual(pct.badCases, [], campaignLine('PCT 1..400 higher', pct))
    // Las semillas que la fase 1 fijó en rojo (31, 64, 127) siguen corriendo y ya no dan OPEN.
    assert.notIncludeMembers(pct.openCases.map((c) => c.split(' ')[1]), ['seed=31', 'seed=64', 'seed=127'])
    // Progreso (no vacuidad): la mayoría de corridas entrelaza de verdad y cada operación termina bien alguna vez.
    assert.isAbove(pct.effective, pct.runs / 3)
    for (const op of OPS) assert.isAbove(pct.opOk[op] ?? 0, 0, `${op} nunca terminó bien en PCT`)
  }).timeout(120_000)

  /**
   * **Regla 6 · CONTROL TREE en línea fijado en ROJO**: dos `moved` concurrentes del MISMO nodo sin outbox es el límite
   * declarado bajo `acceptScopeDriftRisk` (decisión del dueño 2026-10-20 (2)). El settle alinea las aristas con el árbol
   * del STORE (cara L13 limpia), pero el store se queda con OTRO padre que el consumidor: contra el consumidor, un rol
   * GLOBAL salta el deny de A (`frank@C`) y un rol de organización de A se hereda dentro de B (`gina@C`). Si alguien lo
   * cierra (receta `FOR UPDATE` medida, otra opción del panel), este control se INVIERTE.
   */
  test('regla 6 · CONTROL TREE en línea (ROJO a propósito): moveC ∥ moveC del MISMO nodo deja TREE eximido y OPEN contra el CONSUMIDOR (frank@C en T1, gina@C en T2)', async ({ assert }) => {
    const t1 = await runSettleCase({ tree: 'T1', ops: ['moveC', 'moveC'], stale: [false, false], consistency: 'higher', policy: { kind: 'preempt', k: 2 } })
    const t2 = await runSettleCase({ tree: 'T2', ops: ['moveC', 'moveC'], stale: [false, false], consistency: 'higher', policy: { kind: 'preempt', k: 2 } })
    for (const [label, r, who] of [['T1', t1, 'frank@C'], ['T2', t2, 'gina@C']] as const) {
      assert.isTrue(r.fired, `${label}: la preempción disparó`)
      assert.deepEqual(r.outcomes.map((o) => o.status), ['ok', 'ok'], `${label}: las dos «ok»`)
      assert.isTrue(r.violations.some((v) => v.kind === 'TREE'), `${label}: el store diverge del consumidor (TREE)`)
      assert.equal(r.treeExempt, 'same-node-inline', `${label}: eximido SOLO por el predicado con nombre`)
      assert.deepEqual(r.violations.filter((v) => v.kind !== 'TREE'), [], `${label}: la cara L13 (store) está limpia`)
      assert.isTrue(r.vConsumer.some((v) => v.kind === 'OPEN-grant' && v.detail === who), `${label}: OPEN contra el consumidor ${who} (${summary(r)})`)
    }
  })

  /**
   * **Regla 7 · el relay REAL** (y la pieza 1 de la firma «lote C · TREE»): una notificación que falla se encola con el
   * padre que llevaba y la drena `relayScopeChanges()`. El caso que discrimina: `moveC` (C de A a B) falla en el `Write` de
   * la arista y DESPUÉS otro `moveC` lo devuelve a A; relevar el padre ENCOLADO (B) dejaba el store con C bajo B y el
   * consumidor con C bajo A, en silencio y con todo «applied» (mutante `relay.trust-enqueued-parent`). Con el padre FRESCO
   * converge.
   */
  test('regla 7 · fallos inyectados + relay REAL: el relevo aplica el padre FRESCO del consumidor (moveC falla, otro moveC lo devuelve: sin TREE) y la campaña de fallos (T1) queda limpia', async ({ assert }) => {
    const spec: RunSpec = { tree: 'T1', ops: ['moveC', 'moveC'], stale: [false, false], consistency: 'higher', policy: { kind: 'solo' }, fault: { actor: 0, nth: 2, when: 'before' } }
    const r = await runSettleCase(spec)
    assert.isTrue(r.faulted)
    assert.deepEqual(r.outcomes.map((o) => `${o.status}${o.code ? `:${o.code}` : ''}`), ['error:E_AUTHZ_BACKEND_UNAVAILABLE', 'ok'])
    // Asentar · cierre 1 (🔴 1 del auditor): el padre fresco (A) no es el encolado (B) y NINGUNA otra entrada de la cola lo
    // respalda (el segundo `moveC` fue en línea): el relay NO aplica a ciegas — falla con E_AUTHZ_SCOPE_TREE_DRIFT, que
    // consume intento (se aparcaría con aviso). El store ya tiene el padre del consumidor (el en línea lo escribió): sin
    // TREE. Con el mutante `relay.trust-enqueued-parent` el relay aplicaría B en silencio (TREE).
    assert.deepEqual(r.relay, ['failed:moved(E_AUTHZ_SCOPE_TREE_DRIFT)', 'failed:moved(E_AUTHZ_SCOPE_TREE_DRIFT)', 'failed:moved(E_AUTHZ_SCOPE_TREE_DRIFT)'], 'no se aplica un padre que la cola no respalda')
    assert.deepEqual(r.violations, [], `sin TREE ni nada: ${summary(r)}`)
    assert.deepEqual(r.vConsumer, [])
    // Un `attached` que falló de un nodo que el consumidor ya borró (el `detached` fue EN LÍNEA, no está en la cola): el
    // relay no lo da por `superseded` en silencio — 422 con motivo, consume intento —, y no escribe arista.
    const superseded = await runSettleCase({ tree: 'T1', ops: ['attachDtoQ', 'detachD'], stale: [false, false], consistency: 'higher', policy: { kind: 'solo' }, fault: { actor: 0, nth: 1, when: 'before' } })
    assert.include(superseded.relay, 'failed:attached(E_AUTHZ_UNKNOWN_SCOPE)', summary(superseded))
    assert.notInclude(superseded.relay.join(' '), 'applied:attached', summary(superseded))
    assert.deepEqual(superseded.violations, [])
    const faults = await faultCampaign({ consistency: 'higher', trees: ['T1'] })
    assert.deepEqual(faults.badCases, [], campaignLine('fallos T1 higher', faults))
    assert.isAbove(faults.relay['applied:moved'] ?? 0, 0, 'el relay real relevó moved')
    assert.isAbove(faults.relay['applied:detached'] ?? 0, 0, 'y detached')
  }).timeout(120_000)

  /**
   * Tres piezas de la firma que la QUIETUD no ve (la propiedad juzga el estado final), cada una con su caso:
   *  - **R4 (🟡 4) · decisión PREVIA con el store en `grant`**: durante el lag de un `moved` que ENTRA en el owner (el
   *    consumidor ya tiene C bajo A, el store todavía bajo B) el `grant` local no escribe la arista ni un instante
   *    (fail-CLOSED, como `attached`); sin la decisión previa la escribía y el settle la borraba después (ventana real).
   *  - **`finally` en `reparent`** (auditor 🟡 5 (iii)): un `Write` de la arista que vence el deadline PERO SE CONFIRMÓ
   *    (fallo `after`) en modo en línea, sin relay que reintente: el settle corre igual y la alta del rol local llega.
   *  - **la pata Dekker de `purgeRole`** (hallazgo 2): un `grant` que corre ENTERO entre la demostración de cero y el
   *    DELETE SQL de la purga (decide con el rol VIVO); el repaso de la purga tras el DELETE lo borra.
   */
  test('R4 (decisión previa), `finally` de reparent y pata Dekker de purgeRole: las piezas que la quietud no ve', async ({ assert }) => {
    // R4: `moveC` (T2: de B a A) falla ANTES de escribir la arista y no hay relay; después, grant R@C (carol).
    const lag = await runSettleCase({ tree: 'T2', ops: ['moveC', 'grantR@C'], stale: [false, false], consistency: 'higher', policy: { kind: 'solo' }, fault: { actor: 0, nth: 1, when: 'before' }, noDrain: true, trace: true })
    assert.deepEqual(lag.outcomes.map((o) => o.status), ['error', 'ok'], summary(lag))
    const edgeWrites = lag.writes.filter((w) => w.actor === 'a1' && w.writes.some((t) => t.relation === 'binding'))
    assert.deepEqual(edgeWrites, [], 'el grant durante el lag no escribe la arista scope#binding (ni para borrarla después)')
    assert.isFalse(lag.violations.some((v) => isOpen(v.kind)), summary(lag))

    // `finally`: `moveC` (T2: de B a A, ENTRA en el owner) con el `Write` de la arista confirmado y un 503 después.
    // (El `Write` 1 es el barrido previo —borra con `Ignore` lo que la cadena nueva prohíbe, aquí nada efectivo—; el 2 es
    // la arista.)
    const after = await runSettleCase({ tree: 'T2', ops: ['moveC'], stale: [false], consistency: 'higher', policy: { kind: 'solo' }, fault: { actor: 0, nth: 2, when: 'after' }, noDrain: true, trace: true })
    assert.isTrue(after.faulted)
    assert.isTrue(after.writes[1]?.writes.some((t) => t.relation === 'parent'), 'el Write que vence el deadline es el de la arista, y se confirmó')
    assert.equal(after.outcomes[0].code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
    assert.deepEqual(after.violations, [], `el settle corre aunque el Write lance: ${summary(after)}`)

    // Pata Dekker: purgeRP (actor 1) ∥ grantRP@P (actor 2) en CADA I/O de la purga — incluido el punto de planificación
    // del arnés justo antes de su commit SQL, donde el grant decide con el rol VIVO y escribe antes del DELETE.
    const solo = await runSettleCase({ tree: 'T1', ops: ['purgeRP'], stale: [false], consistency: 'higher', policy: { kind: 'solo' } })
    const orphan: string[] = []
    for (const tree of ['T1', 'T3'] as const) {
      for (let k = 1; k <= solo.io[0]; k++) {
        const r = await runSettleCase({ tree, ops: ['purgeRP', 'grantRP@P'], stale: [false, false], consistency: 'higher', policy: { kind: 'preempt', k } })
        // Asentar · cierre 1 (🟡-5 del tester): también sin CLOSED — con UNA sola vuelta de «borrar y releer» (mutante
        // `purgeRole.one-round`) la purga se rinde con el binding de erin a medias (T1 @4–6: `RP@P [erin]` sin arista).
        if (r.fired && r.violations.some((v) => v.kind === 'ORPHAN-edge' || v.kind === 'ORPHAN-fact' || isClosed(v.kind))) orphan.push(`${tree} @${k}: ${summary(r)}`)
      }
    }
    assert.deepEqual(orphan, [])
  }).timeout(60_000)

  /**
   * **La cota del settle** (resolución 7 del juez): alcanzada DE VERDAD con un escritor del árbol que mueve C en cada
   * relectura. Siempre 409 `E_AUTHZ_WRITE_CONFLICT` marcado PARCIAL (`indeterminate: true` en `onWrite`), la arista
   * borrada (fail-CLOSED declarado, intra-tenant), y: en un `grant` que CREÓ la asignación, también su `assignee` («no
   * ocurrió»); en un re-grant la asignación SIGUE (el 409 no significa «no asignado»). Desviación declarada en el
   * informe: `role_binding#role` NO se borra (es compartida con los demás holders del rol en ese scope).
   */
  test('la cota del settle: 409 marcado parcial, arista borrada, y «no ocurrió» solo en un grant que creó la asignación', async ({ assert }) => {
    const binding = 'role_binding:unit|0190a000-0000-7000-8000-000000000b02|0190a000-0000-7000-8000-000000000c01'
    const edge = (tuples: Array<{ user: string; relation: string; object: string }>) =>
      tuples.some((t) => t.relation === 'binding' && t.user === binding)
    const assignee = (tuples: Array<{ user: string; relation: string; object: string }>, who: string) =>
      tuples.some((t) => t.relation === 'assignee' && t.object === binding && t.user === `user:${who}`)
    for (const regrant of [false, true]) {
      const { error, tuples, flips } = await settleCapCase(regrant)
      const label = regrant ? 're-grant (alice)' : 'grant nuevo (carol)'
      assert.equal(error?.code, 'E_AUTHZ_WRITE_CONFLICT', `${label}: ${error?.message}`)
      assert.equal(error?.status, 409)
      assert.isTrue(isPartialWrite(error), `${label}: marcado PARCIAL`)
      assert.isAtLeast(flips, SETTLE_MAX_ROUNDS + 1, `${label}: llegó a la cota (${flips} relecturas)`)
      assert.isFalse(edge(tuples), `${label}: la arista scope#binding se borra al rendirse`)
      assert.isTrue(tuples.some((t) => t.relation === 'role' && t.object === binding), `${label}: role_binding#role (compartida) se queda`)
      if (regrant) assert.isTrue(assignee(tuples, 'alice'), 'un re-grant que se rinde NO quita la asignación')
      else assert.isFalse(assignee(tuples, 'carol'), 'un grant nuevo que se rinde vuelve a «no ocurrió»: sin assignee')
      assert.isTrue(assignee(tuples, 'victim'), `${label}: las demás asignaciones del binding no se tocan`)
    }
  })

  /**
   * **Hallazgo 3 del panel TREE · guardia de FUENTE**: toda lectura que alimenta una escritura va con HIGHER por el helper
   * único (`readForWrite`/`checkForWrite`/`readAssignment` con `WRITE_CONSISTENCY`). Los métodos que escriben no pueden
   * leer con `this.consistency` (el `minimize_latency` del driver es para DECIDIR) ni por `readAllTuples(`/`batchCheckAll(`
   * directos. Sin servidor, el HIGHER del `Check` no se puede matar de otra forma (la caché del doble solo la ve la cara
   * `minimize` de la propiedad).
   */
  test('hallazgo 3 · guardia de fuente: los métodos que ESCRIBEN leen con HIGHER por el helper único (ni `this.consistency`, ni `readAllTuples(`, ni `batchCheckAll(`)', async ({ assert }) => {
    const source = await readFile(new URL('../src/drivers/openfga_driver.ts', import.meta.url), 'utf-8')
    const body = (signature: string) => {
      const start = source.indexOf(signature)
      assert.isAtLeast(start, 0, `no encuentro ${signature}`)
      // Hasta el siguiente método de la clase (dos espacios + modificador/async/nombre al principio de línea).
      const rest = source.slice(start + signature.length)
      const next = rest.search(/\n {2}(?:private |async |get |static |readonly |[a-zA-Z#]+\()/)
      return rest.slice(0, next < 0 ? undefined : next)
    }
    const writers = [
      'private async reparent(',
      'private async sweepLocalRoleBindings(',
      'private async localBindingsBelow(',
      'private async settleSubtree(',
      'private async sweepRoleVisibility(',
      'private async decideRoleVisibility(',
      'private async settleRoleVisibility(',
      'private async settleRounds(',
      'private async storeChain(',
      'private async readAssignment(',
      'private async writeGrant(',
      'async onScopeDetached(',
      'async purgeScope(',
      'async purgeRole(',
      'async projectCatalogRole(',
      'private async projectRolePermits(',
      'private async ensureFactsRoot(',
      'private async projectCatalog(',
      'private async readEveryTuple(',
    ]
    const bad: string[] = []
    for (const signature of writers) {
      const text = body(signature)
      for (const forbidden of ['this.consistency', 'this.readAllTuples(', 'this.batchCheckAll(']) {
        if (text.includes(forbidden)) bad.push(`${signature} usa ${forbidden}`)
      }
    }
    assert.deepEqual(bad, [])
    assert.include(body('private async readAssignment('), 'consistency: WRITE_CONSISTENCY')
    assert.include(body('private async checkForWrite('), 'consistency: WRITE_CONSISTENCY')
    assert.include(body('private readForWrite('), 'consistency: WRITE_CONSISTENCY')
    assert.include(source, 'const WRITE_CONSISTENCY = ConsistencyPreference.HigherConsistency')
  })

  test('propiedad (reglas 1–3 y 7): enumeración acotada + memo rancio + PCT 1..2000 + fallos inyectados con el relay real, 3 actores, las dos consistencias ⇒ 0 corridas malas', async ({ assert }) => {
    const failures: string[] = []
    for (const consistency of ['higher', 'minimize'] as const) {
      for (const [label, report] of [
        ['enumeración', await enumerationCampaign({ consistency })],
        ['enumeración rancio (K4)', await enumerationCampaign({ consistency, staleForR2: true })],
        ['PCT 1..2000', await pctCampaign({ from: 1, to: 2000, consistency })],
        ['fallos + relay', await faultCampaign({ consistency })],
        // Asentar · cierre 2 (🟡-4 del tester): fallo ∥ carrera con el relay REAL (la cifra OPEN 188 → 0 del cierre 1, que
        // vivía solo en `.claude/reproducciones`). Solo en `higher`, como se midió; el residuo C1-4 va contado aparte.
        ...(consistency === 'higher' ? ([['fallo ∥ carrera + relay', await raceFaultCampaign({ consistency, drain: true })]] as const) : []),
      ] as const) {
        if (report.badCases.length) failures.push(campaignLine(`${consistency} ${label}`, report))
        // Asentar · cierre 1 (🟡-7 del tester): la propiedad AFIRMA progreso — una campaña que dejara de entrelazar (o de
        // disparar fallos, o de relevar) saldría verde con `badCases = []`.
        const progress = (ok: boolean, what: string) => {
          if (!ok) failures.push(`${consistency} ${label}: sin progreso — ${what}`)
        }
        progress(report.runs > 0 && report.effective > 0, `effective=${report.effective} de ${report.runs}`)
        if (label === 'enumeración') progress((report.treeExempt['same-node-inline'] ?? 0) > 0, 'la regla 6 (TREE same-node-inline) no apareció')
        if (label === 'PCT 1..2000') for (const op of OPS) progress((report.opOk[op] ?? 0) > 0, `${op} nunca terminó bien`)
        if (label === 'fallo ∥ carrera + relay') {
          progress(report.open === 0, `OPEN=${report.open}`)
          // El residuo declarado no puede crecer a escondidas: su firma es una sola combinación (C1-4).
          progress(report.residue.length <= 2, `residuo C1-4 = ${report.residue.length} (${report.residue.slice(0, 3).join(' | ')})`)
        }
        if (label === 'fallos + relay') {
          progress((report.relay['applied:moved'] ?? 0) > 0, 'el relay real no relevó ningún moved')
          progress((report.relay['applied:detached'] ?? 0) > 0, 'el relay real no relevó ningún detached')
        }
      }
    }
    assert.deepEqual(failures, [])
  })
    .skip(process.env.AUTHZ_SETTLE_PROPERTY !== '1', 'completa (~4 min): AUTHZ_SETTLE_PROPERTY=1 la corre (job nocturno, a decidir en el paso 5)')
    .timeout(1_200_000)
})

/**
 * **`closedAttribution` fijada por test** (asentar · cierre 2, 🟡-3 del tester del cierre 1): el oráculo que admite un
 * CLOSED solo si lo causa lo que tocó el actor del fallo o del 409 de cota. Aflojarlo (volver a la «manta») no ponía
 * nada rojo. Los 6 sintéticos del tester (`c1/attr_probe.ts`), como test puro (mutante `oracle.attribution-blanket`).
 */
test.group('GS · P · asentar · cierre 2 · el oráculo de atribución de CLOSED', () => {
  test('closedAttribution: atribuye solo lo que TOCA el actor del fallo o del 409 de cota (6 sintéticos)', ({ assert }) => {
    const mk = (violations: any[], outcomes: any[], faultedActor?: number) =>
      ({ violations, outcomes, faulted: faultedActor !== undefined, faultedActor }) as unknown as RunResult
    const cases: Array<[string, RunResult, 'fault' | 'cap-409' | null]> = [
      ['fallo en grantR@C, CLOSED R@C', mk([{ kind: 'CLOSED-edge', detail: 'R@C [alice]' }], [{ op: 'grantR@C', status: 'error' }, { op: 'moveP', status: 'ok' }], 0), 'fault'],
      ['fallo en grantR@C, CLOSED RP@P (ajeno)', mk([{ kind: 'CLOSED-edge', detail: 'RP@P [bob]' }], [{ op: 'grantR@C', status: 'error' }, { op: 'purgeRP', status: 'ok' }], 0), null],
      ['409 SIN cap (árbol), CLOSED R@C', mk([{ kind: 'CLOSED-edge', detail: 'R@C [alice]' }], [{ op: 'moveC', status: 'error', code: 'E_AUTHZ_WRITE_CONFLICT' }, { op: 'grantR@C', status: 'ok' }]), null],
      ['cap en grantR@C, CLOSED R@C + RP@P (exige todos)', mk([{ kind: 'CLOSED-edge', detail: 'R@C [alice]' }, { kind: 'CLOSED-edge', detail: 'RP@P [bob]' }], [{ op: 'grantR@C', status: 'error', cap: true }, { op: 'moveP', status: 'ok' }]), null],
      ['fallo en moveC, CLOSED-grant erin@P', mk([{ kind: 'CLOSED-grant', detail: 'erin@P' }], [{ op: 'moveC', status: 'error' }, { op: 'grantRP@P', status: 'ok' }], 0), null],
      ['fallo del actor 1 (purgeRP), CLOSED R@C del actor 0', mk([{ kind: 'CLOSED-edge', detail: 'R@C [alice]' }], [{ op: 'grantR@C', status: 'ok' }, { op: 'purgeRP', status: 'error' }], 1), null],
    ]
    assert.deepEqual(
      cases.map(([name, r]) => [name, closedAttribution(r)]),
      cases.map(([name, , want]) => [name, want])
    )
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * Asentar · cierre 1 — casos DIRIGIDOS (tester del paso 4: 🟠-2, 🟠-3, 🟡-1, 🟡-2, 🟡-4 y `settle.cap-unmarked`). Cada
 * uno mata un mutante que vivía con `npm test` (y casi todos con la propiedad completa): piezas del código nuevo de las
 * que nadie demostraba la rotura.
 * ════════════════════════════════════════════════════════════════════════ */
test.group('GS · P · asentar · cierre 1 · casos dirigidos del settle', (group) => {
  group.setup(async () => {
    await seedSettleRoles()
    return () => dropSettleRoles()
  })
  // Algunos casos purgan RP de `authz_roles` de verdad: se re-siembra antes de cada uno.
  group.each.setup(() => seedSettleRoles())

  /** 🟠-2 · la regla de NIVEL del settle (inv. 18, 3b-2g · R1) sin servidor (mutante `decide.no-level-check`). */
  test('🟠-2 · NIVEL: el rol pasa a `organization` ⇒ projectCatalogRole borra su arista en la unit y alice deja de leer; volver a `unit` la restaura', async ({ assert }) => {
    const rig = await settleRig({ tree: 'T1' })
    assert.isTrue(rig.edge('R', 'C'))
    assert.isTrue(rig.can('alice', 'C'))
    rig.setRoles(Object.values(ROLES).map((r) => (r.uuid === ROLES.R.uuid ? { ...r, scopeType: 'organization' } : r)))
    await rig.driver.projectCatalogRole(ROLES.R.uuid)
    assert.isFalse(rig.edge('R', 'C'), 'un nivel que el catálogo ya no declara no es visible')
    assert.isFalse(rig.edge('R', 'D'))
    assert.isFalse(rig.can('alice', 'C'))
    rig.setRoles(Object.values(ROLES))
    await rig.driver.projectCatalogRole(ROLES.R.uuid)
    assert.isTrue(rig.edge('R', 'C'), 'inverso: vuelve a coincidir el nivel')
    assert.isTrue(rig.can('alice', 'C'))
    assert.deepEqual(await rig.judge(), [])
  })

  /** 🟠-3 · inv. 5 en el `batchCheck` del settle: un error POR ÍTEM es 503, nunca un `false` que borra (mutante `checkForWrite.swallow-item-error`). */
  test('🟠-3 · un error por ítem (5xx) en el batchCheck del settle ⇒ 503 y la arista NO se borra (re-grant y grant nuevo); sin el error, la arista', async ({ assert }) => {
    for (const who of ['alice', 'carol'] as const) {
      const rig = await settleRig({ tree: 'T1' })
      const inner = rig.driver.client.batchCheck
      rig.driver.client.batchCheck = async (body: any, options: any) => {
        const response = await inner(body, options)
        for (const item of response.result) {
          if (item.request?.relation === 'role') {
            item.allowed = false
            item.error = { internal_error: 'internal_error', message: 'el servidor no pudo evaluar este ítem' }
          }
        }
        return response
      }
      let error: any = null
      try {
        await rig.driver.grant({ type: 'users', uuid: who }, { uuid: ROLES.R.uuid }, U.C, { expiresAt: null })
      } catch (e) {
        error = e
      }
      assert.equal(error?.status, 503, `${who}: ${error?.message}`)
      assert.isTrue(rig.edge('R', 'C'), `${who}: la arista sigue (un error no es «no visible»)`)
      rig.driver.client.batchCheck = inner
      await rig.driver.grant({ type: 'users', uuid: who }, { uuid: ROLES.R.uuid }, U.C, { expiresAt: null })
      assert.isTrue(rig.edge('R', 'C'), `${who}: inverso`)
    }
  })

  /** 🟡-2 · resolución 9, condición 2: ante el límite de profundidad de `ancestor`, caer a `storeChain` (mutante `decide.depth-fallback-deletes`). */
  test('🟡-2 · `ancestor` excede la cota del servidor (owner a 2 saltos, cota 1) ⇒ cae a storeChain y la arista se QUEDA; con el owner fuera de la cadena, no hay arista', async ({ assert }) => {
    const deep = await settleRig({ tree: 'T1', depthLimits: { ancestor: 1 } })
    assert.isTrue(deep.edge('R', 'D'))
    await deep.driver.projectCatalogRole(ROLES.R.uuid)
    assert.isTrue(deep.edge('R', 'D'), 'D ⊂ C ⊂ A: el owner SÍ es ancestro; un 400 de profundidad no es «no visible»')
    assert.isTrue(deep.can('alice', 'D'))
    const outside = await settleRig({ tree: 'T2', depthLimits: { ancestor: 1 } })
    await outside.driver.projectCatalogRole(ROLES.R.uuid)
    assert.isFalse(outside.edge('R', 'D'), 'inverso: D ⊂ C ⊂ B, el owner A no está')
    assert.deepEqual(await outside.judge(), [])
  })

  /** 🟡-1 · el settle del `grant` local corre aunque su `Write` lance tras confirmarse (mutante `grant.settle-only-on-success2`). */
  test('🟡-1 · grant local cuyo Write se CONFIRMA y lanza 503 ∥ moveC fuera del owner justo antes: el settle del grant corre igual (sin OPEN)', async ({ assert }) => {
    const solo = await runSettleCase({ tree: 'T1', ops: ['grantR@C'], stale: [false], consistency: 'higher', policy: { kind: 'solo' } })
    const open: string[] = []
    let hit = 0
    // `nth`: el primer `Write` del grant choca con la estructura compartida (duplicado ⇒ se repite con `Ignore`); el que
    // se confirma y lanza es el segundo.
    for (const nth of [1, 2]) {
      for (let k = 1; k <= solo.io[0]; k++) {
        const r = await runSettleCase({ tree: 'T1', ops: ['grantR@C', 'moveC'], stale: [false, false], consistency: 'higher', policy: { kind: 'preempt', k }, fault: { actor: 0, nth, when: 'after' }, noDrain: true })
        if (!r.fired || !r.faulted) continue
        if (r.outcomes[0].code === 'E_AUTHZ_BACKEND_UNAVAILABLE') hit++
        if (r.violations.some((v) => isOpen(v.kind))) open.push(`w${nth}@${k}: ${summary(r)}`)
      }
    }
    assert.isAbove(hit, 0, 'el Write del grant llegó a fallar tras confirmarse')
    assert.deepEqual(open, [])
  }).timeout(30_000)

  /** 🟡-4 · en `reparent` el error ORIGINAL manda y el del settle va como causa (mutante `reparent.settle-error-wins`). */
  test('🟡-4 · reparent: el Write de la arista se confirma y lanza un error de DESPLIEGUE; el settle del `finally` recibe un 503 ⇒ sale el de despliegue, parcial, con el 503 como causa', async ({ assert }) => {
    let failedSettle = false
    let armed = false
    const rig = await settleRig({
      tree: 'T2',
      hooks: {
        fault: (event) => {
          const body = event.body as any
          if (event.kind === 'write' && body?.writes?.some((t: any) => t.relation === 'parent')) {
            armed = true
            return { error: sdkError('real-write-type-absent'), when: 'after' }
          }
          // Persistente: desde el cierre 1 el settle reintenta UNA vez un fallo suelto.
          if (event.kind === 'batchCheck' && armed) {
            failedSettle = true
            return { error: sdkError('fake-503-unavailable') }
          }
          return undefined
        },
      },
    })
    await rig.tree.move(U.C, U.A)
    let error: any = null
    try {
      await rig.driver.onScopeMoved(U.C, U.A)
    } catch (e) {
      error = e
    }
    assert.isTrue(failedSettle, 'el settle llegó a releer')
    assert.notEqual(error?.status, 503, `el original manda: ${error?.code} ${error?.message}`)
    assert.isTrue(isPartialWrite(error), 'parcial: la arista ya entró')
    const cause = error?.cause?.status === 503 ? error.cause : error?.settleError
    assert.equal(cause?.status, 503, 'el 503 del settle va como causa')
  })

  /** `settle.cap-unmarked` · caso DIRECTO: el settle marca parcial por sí mismo (el reconcile, cuarto llamador, no marca). */
  test('cota · el 409 del settle llamado a secas (como desde reconcile, `progress.writes = 0`) sale marcado PARCIAL', async ({ assert }) => {
    const { error, flips } = await settleCapCase('direct')
    assert.equal(error?.code, 'E_AUTHZ_WRITE_CONFLICT', error?.message)
    assert.isAtLeast(flips, SETTLE_MAX_ROUNDS + 1)
    assert.isTrue(isPartialWrite(error), 'marcado parcial por el propio settle')
  })

  /** 🟡 5 del auditor · K4 en `revoke` por slug: decide con la foto FRESCA, no con el memo (mutante `revoke.memo-catalog`). */
  test('K4 · revoke por SLUG con el memo rancio: el local recién definido que ensombrece al global también se revoca (antes: no-op mudo)', async ({ assert }) => {
    const globalHomonym = { uuid: fixedUuid(0xc0f), slug: ROLES.R2.slug, scopeType: 'unit', owner: 'global', rank: 10 }
    const rig = await settleRig({
      tree: 'T1',
      roles: [...Object.values(ROLES), globalHomonym],
      staleRoles: [ROLES.R, ROLES.RP, ROLES.G, ROLES.GO, globalHomonym],
    })
    const dave = { type: 'users', uuid: 'dave' }
    await rig.driver.grant(dave, { uuid: ROLES.R2.uuid }, U.C, { expiresAt: null })
    assert.isTrue(rig.can('dave', 'C'))
    await rig.driver.revoke(dave, ROLES.R2.slug, U.C)
    assert.isFalse(rig.can('dave', 'C'), 'la asignación del local homónimo también se revoca')
    assert.isFalse(rig.fga.tuples().some((t) => t.relation === 'assignee' && t.user === 'user:dave'))
  })

  /**
   * `reconcile.binding-direct` (tester §4.1; «reconcile como actor» del paso 6, adelantado): la pasada decide las altas de
   * `scope#binding` de roles locales con una foto de TODA la pasada; un `purgeRole` del rol que termina entre la foto y las
   * escrituras deja la arista RESUCITADA si se escribe a ciegas. Por el settle, se relee y no se escribe.
   */
  test('reconcile · una purga del rol entre la foto de la pasada y sus escrituras: la alta de scope#binding NO se escribe a ciegas (sin ORPHAN); sin la purga, la alta llega', async ({ assert }) => {
    for (const purge of [true, false]) {
      let armed = true
      let rig: any
      rig = await settleRig({
        tree: 'T1',
        hooks: {
          onIo: async (event) => {
            if (!armed || event.kind !== 'write') return
            armed = false
            if (purge) {
              await rig.another('purger').purgeRole(ROLES.RP.uuid)
              rig.setRoles(Object.values(ROLES).filter((r) => r.uuid !== ROLES.RP.uuid))
            }
          },
        },
      })
      // El store perdió la arista de RP@P (un relay perdido): la pasada de mantenimiento la quiere escribir. En el inverso
      // también perdió `role_binding#role` (la estructura): la pasada la repone ANTES del settle, que si no la vería
      // muerta y no daría la alta (mutante `reconcile.settle-before-writes`: CLOSED).
      const bindingRP = `role_binding:${U.P.type}|${U.P.uuid}|${ROLES.RP.uuid}`
      const edgeRP = { user: bindingRP, relation: 'binding', object: `scope:${U.P.type}|${U.P.uuid}` }
      const roleRP = { user: `role:${ROLES.RP.uuid}`, relation: 'role', object: bindingRP }
      await rig.fga.client('setup').write({ writes: [], deletes: purge ? [edgeRP] : [edgeRP, roleRP] })
      const edges = async ({ limit, after }: { limit: number; after?: string }) => {
        const all: any[] = []
        for (const node of Object.values(U)) {
          const chain = await rig.tree.chainOf(node)
          if (chain) all.push({ child: chain[0], parent: chain[1] })
        }
        all.sort((a, b) => a.child.uuid.localeCompare(b.child.uuid))
        const from = after ? all.findIndex((e) => e.child.uuid === after) + 1 : 0
        const page = all.slice(from, from + limit)
        return { edges: page, ...(from + limit < all.length ? { cursor: page[page.length - 1].child.uuid } : {}) }
      }
      await rig.driver.reconcile(
        {
          enumerateEdges: edges,
          resolveChain: resolveChainFrom(rig.tree),
          facts: (page: any) => rig.driver.enumerateFacts(page),
          factsOrigin: { name: 'openfga', authzTables: false, self: true },
        },
        {}
      )
      if (purge) assert.isFalse(rig.fga.has(edgeRP), 'la purga corrió entre la foto y las escrituras: la arista no resucita')
      else {
        assert.isTrue(rig.fga.has(roleRP), 'inverso: la pasada repone la estructura')
        assert.isTrue(rig.fga.has(edgeRP), 'inverso: sin la purga, la pasada repone la arista (el settle corre DESPUÉS de la estructura)')
      }
    }
  })

  /** 🟡 3 del auditor: un RE-grant (`existed: true`, otra caducidad) ∥ la purga del rol no deja ORPHAN (mutante `grant.orphan-regrant`). */
  test('🟡 3 · regrant (otra caducidad) ∥ purgeRole en cada I/O de los dos: 0 ORPHAN (el re-grant también deshace)', async ({ assert }) => {
    const orphan: string[] = []
    let fired = 0
    for (const [a1, a2] of [['regrantRP@P', 'purgeRP'], ['purgeRP', 'regrantRP@P']] as const) {
      const solo = await runSettleCase({ tree: 'T1', ops: [a1], stale: [false], consistency: 'higher', policy: { kind: 'solo' } })
      for (let k = 1; k <= solo.io[0]; k++) {
        const r = await runSettleCase({ tree: 'T1', ops: [a1, a2], stale: [false, false], consistency: 'higher', policy: { kind: 'preempt', k } })
        if (!r.fired) continue
        fired++
        if (r.violations.some((v) => v.kind === 'ORPHAN-edge' || v.kind === 'ORPHAN-fact')) orphan.push(`${a1}∥${a2}@${k}: ${summary(r)}`)
      }
    }
    assert.isAbove(fired, 0)
    assert.deepEqual(orphan, [])
  }).timeout(30_000)

  /**
   * Desviación 2 = (b) (firma del dueño 2026-10-21): una purga que FALLA en los hechos (un `grant` repone el binding tras
   * cada borrado, hasta agotar las vueltas) NO deja CLOSED: la proyección `permits_*` se borra solo tras demostrar cero en
   * los hechos (mutante `purgeRole.projection-first`).
   */
  test('desviación 2 (b) · purgeRole que agota las vueltas (500 PURGE_INCOMPLETE): la proyección permits_* sigue (sin CLOSED por la purga fallida)', async ({ assert }) => {
    let deletes = 0
    let readded = 0
    let rig: any
    const erin = { user: 'user:erin', relation: 'assignee', object: `role_binding:${U.P.type}|${U.P.uuid}|${ROLES.RP.uuid}` }
    let armed = true
    rig = await settleRig({
      tree: 'T1',
      hooks: {
        onIo: async (event) => {
          if (!armed) return
          if (event.kind === 'write') deletes++
          // Un `grant` de erin aterriza entre cada borrado y su relectura.
          if (event.kind === 'read' && deletes > readded) {
            readded = deletes
            await rig.fga.client('granter').write({ writes: [erin], deletes: [] }, { conflict: { onDuplicateWrites: 'ignore' } })
          }
        },
      },
    })
    let error: any = null
    try {
      await rig.driver.purgeRole(ROLES.RP.uuid)
    } catch (e) {
      error = e
    }
    assert.equal(error?.code, 'E_AUTHZ_PURGE_INCOMPLETE', error?.message)
    assert.isTrue(rig.fga.tuples().some((t: any) => t.object === `role:${ROLES.RP.uuid}` && t.relation.startsWith('permits_')), 'la proyección sigue')
    // C1-5 (firmada en el cierre 1, con su aserción en el cierre 2 — 🟡-5 del tester): la letra de
    // `E_AUTHZ_PURGE_INCOMPLETE` promete DOS cosas más. (i) Quien escribió durante la purga queda con su binding A MEDIAS:
    // el `assignee` de erin sigue, sin `role_binding#role` ni arista ⇒ erin NO concede en P (un CLOSED de una asignación
    // creada a la vez que la purga del rol, nunca un OPEN).
    const bindingRP = `role_binding:${U.P.type}|${U.P.uuid}|${ROLES.RP.uuid}`
    assert.isTrue(rig.fga.has(erin), 'el assignee de erin quedó escrito')
    assert.isFalse(rig.fga.tuples().some((t: any) => t.object === bindingRP && t.relation === 'role'), 'sin role_binding#role')
    assert.isFalse(rig.fga.tuples().some((t: any) => t.user === bindingRP && t.relation === 'binding'), 'sin scope#binding')
    assert.isFalse(rig.can('erin', 'P'), 'binding a medias: no concede')
    // (ii) El REINTENTO (sin el escritor concurrente) termina, borra la proyección y la fila del rol — pero NO ve el
    // `assignee` de erin: `purgeRole` enumera los bindings por `role:<uuid>#role` y ese ancla ya no existe (MEDIDO en el
    // cierre 2; la letra «el reintento borra igual» del cierre 1 era falsa en esta cara: desviación C2-1). Lo que queda
    // no concede ni es membresía (el rol ya no está en el catálogo, invariante 11) y lo recoge `reconcile --prune`.
    armed = false
    await rig.driver.purgeRole(ROLES.RP.uuid)
    const left = () => rig.fga.tuples().filter((t: any) => `${t.user} ${t.object}`.includes(ROLES.RP.uuid))
    assert.deepEqual(left(), [erin], 'tras el reintento solo queda el assignee huérfano de erin (C2-1)')
    assert.notExists(await db.from('authz_roles').where('uuid', ROLES.RP.uuid).first(), 'el reintento SÍ borró la fila del rol')
    // El catálogo del rig es inyectado: se le dice lo que la base ya dice (RP no existe).
    rig.setRoles(Object.values(ROLES).filter((r) => r.uuid !== ROLES.RP.uuid))
    assert.isFalse(rig.can('erin', 'P'))
    assert.deepEqual(await rig.driver.listRoles({ type: 'users', uuid: 'erin' }, U.P), [], 'no es membresía: el catálogo ya no tiene RP')
    const restore = await seedCatalogLinks(Object.values(ROLES).filter((r) => r.uuid !== ROLES.RP.uuid))
    try {
      await rig.driver.reconcile(maintenanceSource(rig.tree, rig.driver), { prune: true })
    } finally {
      await restore()
    }
    assert.deepEqual(left(), [], 'reconcile --prune lo recoge')
    assert.deepEqual(await rig.judge(), [], 'y la pasada deja el store limpio')
  })

  /**
   * **R2-1 del re-ataque del cierre 2 (firmado con C2-1 (a) y su mitigación; cierre 3).** El `assignee` huérfano de C2-1
   * RESUCITA si el rol vuelve con el MISMO uuid (`CatalogRoleSpec.uuid` fijo: `syncAuthzCatalog` reinserta
   * `existing?.uuid ?? role.uuid`, y el id del binding es determinista): sin ningún grant posterior a la purga erin vuelve
   * a ser MIEMBRO (`hasRole` lee el `assignee` directo) y el primer `grant` del rol en ese scope reescribe la estructura
   * compartida y erin CONCEDE — un grant que la purga se llevó y vuelve a conceder.
   *
   * Lo que se fija (la mitigación firmada, en la forma que el coste permite; ver el informe del cierre 3): (i) el residuo
   * tal cual, como se declara; (ii) la red que lo VE antes de reutilizar el uuid: `reconcile --dry-run` lo cuenta como
   * hecho sobrante y la pasada NO es limpia (exit ≠ 0; ⚪-b del tester); (iii) la receta: `reconcile --prune` ANTES de
   * reutilizar el uuid ⇒ el rol vuelve limpio, erin no es miembro y el grant de bob no la arrastra. El AVISO dentro del sync
   * no se implementa: detectar el huérfano exige un `Read` del store ENTERO (no hay índice por uuid de rol), medido en
   * `:8104` (9,1 s con 50 000 tuplas, superlineal), y llegaría DESPUÉS del commit que ya lo resucitó.
   */
  test('R2-1 · uuid de rol REUTILIZADO tras una purga fallida: el huérfano de C2-1 vuelve a ser membresía y, tras un grant ajeno, concede; `reconcile --dry-run` lo delata y `--prune` ANTES de reutilizar el uuid lo evita', async ({ assert }) => {
    const { reconcileLines } = await import('../commands/authz_reconcile.js')
    const Q = U.Q
    const erinAt = (r: { uuid: string }) => ({ user: 'user:erin', relation: 'assignee', object: `role_binding:${Q.type}|${Q.uuid}|${r.uuid}` })
    const erin = { type: 'users', uuid: 'erin' }
    const bob = { type: 'users', uuid: 'bob' }
    const others = Object.values(ROLES).filter((r) => r.uuid !== ROLES.G.uuid)
    /** C2-1 con el rol GLOBAL G (uuid fijo): purga que agota las vueltas con erin escribiendo, y el reintento limpio. */
    const purgeLeavingOrphan = async () => {
      await seedSettleRoles()
      let deletes = 0
      let readded = 0
      let armed = true
      let rig: any
      rig = await settleRig({
        tree: 'T1',
        hooks: {
          onIo: async (event) => {
            if (!armed) return
            if (event.kind === 'write') deletes++
            if (event.kind === 'read' && deletes > readded) {
              readded = deletes
              await rig.fga.client('granter').write({ writes: [erinAt(ROLES.G)], deletes: [] }, { conflict: { onDuplicateWrites: 'ignore' } })
            }
          },
        },
      })
      const failed = await rig.driver.purgeRole(ROLES.G.uuid).then(() => null, (e: any) => e)
      assert.equal(failed?.code, 'E_AUTHZ_PURGE_INCOMPLETE', failed?.message)
      armed = false
      await rig.driver.purgeRole(ROLES.G.uuid)
      rig.setRoles(others)
      const left = rig.fga.tuples().filter((t: any) => `${t.user} ${t.object}`.includes(ROLES.G.uuid))
      assert.deepEqual(left, [erinAt(ROLES.G)], 'C2-1: tras el reintento solo queda el assignee huérfano de erin')
      assert.notExists(await db.from('authz_roles').where('uuid', ROLES.G.uuid).first())
      return rig
    }
    /** Lo que hace `syncAuthzCatalog` con el uuid fijo del spec: reinsertar la fila con ESE uuid y proyectar el rol. */
    const resync = async (rig: any) => {
      await seedSettleRoles()
      rig.setRoles(Object.values(ROLES))
      await rig.driver.projectCatalogRole(ROLES.G.uuid)
    }
    const maintenance = async (rig: any, options: { dryRun?: boolean; prune?: boolean }) => {
      const restore = await seedCatalogLinks(others)
      try {
        return await rig.driver.reconcile(maintenanceSource(rig.tree, rig.driver), options)
      } finally {
        await restore()
      }
    }

    // (i) + (ii) · Sin la receta: la red lo ve ANTES del re-sync, y después del re-sync resucita.
    const a = await purgeLeavingOrphan()
    const seen = await maintenance(a, { dryRun: true })
    assert.isAtLeast(seen.skipped['extra-fact'] ?? 0, 1, `la pasada de mantenimiento cuenta el huérfano: ${JSON.stringify(seen.skipped)}`)
    // 🟡-D del tester (cierre 3): `clean` solo no basta, el rig deja un `role-not-visible` de bob de base; la red
    // tiene que delatar AL HUÉRFANO, con su línea.
    const seenLines = reconcileLines(seen)
    assert.isFalse(seenLines.clean, 'y la pasada no es limpia: authz:reconcile --dry-run sale ≠ 0 (la red del cron)')
    assert.isTrue(
      seenLines.lines.some((l) => l.message.includes('(extra-fact)') && l.message.includes('user:erin')),
      `la red nombra la tupla de erin: ${JSON.stringify(seenLines.lines.map((l) => l.message))}`
    )
    assert.isTrue(a.fga.has(erinAt(ROLES.G)), '--dry-run no escribe')
    await resync(a)
    assert.isTrue(await a.driver.hasRole(erin, { uuid: ROLES.G.uuid }, Q), 'R2-1: erin vuelve a ser MIEMBRO sin ningún grant posterior a la purga')
    assert.isFalse(a.can('erin', 'Q'), 'todavía sin la estructura: no concede')
    await a.driver.grant(bob, { uuid: ROLES.G.uuid }, Q)
    assert.isTrue(a.can('bob', 'Q'))
    assert.isTrue(a.can('erin', 'Q'), 'R2-1: el grant de bob reescribe la estructura compartida y erin CONCEDE (residuo declarado)')

    // (iii) · La receta: `reconcile --prune` ANTES de reutilizar el uuid ⇒ nada resucita.
    const b = await purgeLeavingOrphan()
    await maintenance(b, { prune: true })
    assert.isFalse(b.fga.has(erinAt(ROLES.G)), '--prune recoge el huérfano')
    const after = await maintenance(b, { dryRun: true })
    assert.notExists(after.skipped['extra-fact'], `tras --prune el --dry-run ya no ve extra-fact: ${JSON.stringify(after.skipped)}`)
    await resync(b)
    assert.isFalse(await b.driver.hasRole(erin, { uuid: ROLES.G.uuid }, Q), 'con la receta erin NO vuelve a ser miembro')
    await b.driver.grant(bob, { uuid: ROLES.G.uuid }, Q)
    assert.isTrue(b.can('bob', 'Q'), 'anti-vacuidad: el rol reutilizado concede a quien se le asigna de nuevo')
    assert.isFalse(b.can('erin', 'Q'), 'y no arrastra al huérfano')
  })

  /**
   * C1-4 (firmada en el cierre 1 con la condición de un caso; 🟡-4 del tester): el residuo de fallo ∥ carrera con el relay
   * —`purgeRP` con un 503 en su 2.º `Write` ∥ `moveCtoP` en su I/O 7— deja una `scope#binding` de RP en C SIN
   * `role_binding#role` (ORPHAN-edge: no concede, y el reintento de `purgeRole` no la ve porque enumera por `#role`). Se
   * fija tal como se declara Y se demuestra que `authz:reconcile --prune` (la pasada de mantenimiento del store, origen =
   * él mismo) la recoge: sin `--prune` queda en `skipped` (`extra-fact`) y con `--prune` se borra.
   */
  test('C1-4 · `purgeRP!write2 ∥ moveCtoP@7` + relay: el ORPHAN-edge declarado (scope#binding sin #role) aparece y `reconcile --prune` lo recoge (sin --prune: extra-fact)', async ({ assert }) => {
    const found: string[] = []
    for (const tree of ['T1', 'T2', 'T3'] as const) {
      const r = await runSettleCase({ tree, ops: ['purgeRP', 'moveCtoP'], stale: [false, false], consistency: 'higher', policy: { kind: 'preempt', k: 7 }, fault: { actor: 0, nth: 2, when: 'before', on: 'write' }, reconcile: true })
      if (!r.fired || !r.faulted) continue
      const orphans = r.violations.filter((v) => v.kind === 'ORPHAN-edge')
      if (orphans.length === 0) continue
      found.push(tree)
      assert.isTrue(orphans.every((v) => v.detail.startsWith('RP@')), JSON.stringify(orphans))
      assert.deepEqual(r.violations.filter((v) => v.kind !== 'ORPHAN-edge' && v.kind !== 'TREE' && !v.kind.startsWith('CLOSED')), [], summary(r))
      assert.isAbove(r.reconcile!.dryRun.skipped['extra-fact'] ?? 0, 0, 'sin --prune: la pasada lo cuenta como extra-fact (no limpia)')
      assert.deepEqual(r.reconcile!.after, [], 'con --prune: recogido, y la pasada deja el store limpio (ni OPEN ni CLOSED)')
    }
    assert.isNotEmpty(found, 'el residuo C1-4 tiene que reproducirse (si deja de aparecer, el caso no juzga nada: revisar la letra de C1-4)')
  }).timeout(60_000)

  /**
   * 🟡 4 del auditor (medido: 188/26 464 OPEN en línea con la campaña `racefault`): un 503 suelto en la relectura del
   * settle de un `grant` justo después de una carrera con un `moved` ya no deja la arista rancia (mutante `settle.no-retry`).
   */
  test('🟡 4 · fallo ∥ carrera: grantR@C con un 503 en la relectura de su settle ∥ moveC fuera del owner ⇒ sin OPEN (el settle repite la vuelta)', async ({ assert }) => {
    const open: string[] = []
    let faulted = 0
    for (let k = 1; k <= 8; k++) {
      const r = await runSettleCase({ tree: 'T1', ops: ['grantR@C', 'moveC'], stale: [false, false], consistency: 'higher', policy: { kind: 'preempt', k }, fault: { actor: 0, nth: 2, when: 'before', on: 'batchCheck' }, noDrain: true })
      if (!r.fired || !r.faulted) continue
      faulted++
      if (r.violations.some((v) => isOpen(v.kind))) open.push(`@${k}: ${summary(r)}`)
    }
    assert.isAbove(faulted, 0)
    assert.deepEqual(open, [])
  })

  /**
   * Asentar · cierre 2 (🟡-4 del tester): la campaña fallo ∥ carrera con el relay REAL, ACOTADA para `npm test` (T1 y las
   * cuatro operaciones del 🟡 4 y de C1-4: 783 corridas, ~6 s). La entera (34 420, ~4 min) va en la propiedad. OPEN = 0
   * (antes del cierre 1: 188 / 26 464) y el residuo C1-4 exactamente donde se declaró.
   */
  test('fallo ∥ carrera + relay, acotada (T1 · grantR@C, moveC, purgeRP, moveCtoP): 0 corridas malas, OPEN = 0 y el residuo C1-4 solo en su firma', async ({ assert }) => {
    const r = await raceFaultCampaign({ consistency: 'higher', drain: true, trees: ['T1'], ops: ['grantR@C', 'moveC', 'purgeRP', 'moveCtoP'] })
    assert.isAbove(r.runs, 0)
    assert.equal(r.open, 0, campaignLine('racefault acotada', r))
    assert.deepEqual(r.badCases, [], campaignLine('racefault acotada', r))
    assert.deepEqual(r.residue, ['racefault T1 purgeRP!write2∥moveCtoP@7 drain'])
  }).timeout(120_000)

  /** 🟡 2 del auditor: la rendición de la cota no borra los pares que YA convergieron (CLOSED fuera del churn). */
  test('cota · la rendición borra solo la arista del par que no converge; la del par convergido (RP@P) se queda', async ({ assert }) => {
    const { error, tuples } = await settleCapCase('direct-two')
    assert.equal(error?.code, 'E_AUTHZ_WRITE_CONFLICT', error?.message)
    const binding = (node: 'C' | 'P', role: 'R' | 'RP') => `role_binding:${U[node].type}|${U[node].uuid}|${ROLES[role].uuid}`
    assert.isFalse(tuples.some((t) => t.relation === 'binding' && t.user === binding('C', 'R')), 'el par que no converge: arista borrada')
    assert.isTrue(tuples.some((t) => t.relation === 'binding' && t.user === binding('P', 'RP')), 'el par convergido conserva su arista')
  })
})
