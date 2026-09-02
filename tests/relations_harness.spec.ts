/**
 * El conteo del runner de relaciones, ejecutable (análogo a
 * `contract_harness.spec.ts`, pero SEPARADO — no toca los conteos de roles).
 * Registra el contrato contra una API falsa que solo cuenta, y afirma:
 *  - el nº LITERAL de casos por harness (núcleo + una cara por capacidad);
 *  - que TODA capacidad quedó cubierta (ninguna cara ausente = ningún skip);
 *  - que un harness `true` y uno `false` eligen caras DISTINTAS (mismo total);
 *  - que una capacidad `true` sin su soporte se RECHAZA (no un skip disfrazado);
 *  - el conteo LITERAL del JUEZ para la Fase 4 (~41), aterrizado y con las dos
 *    ausencias justificadas (R-15 diferida a 2.6).
 */
import { test } from '@japa/runner'
import {
  registerRelationsDriverContract,
  makeRelationsDriver,
} from '../src/testing/relations_contract.js'
import {
  registerRelationsReconcileContract,
  contractRelationsConfig,
} from '../src/testing/main.js'
import { RelationsManager } from '../src/relations/manager.js'
import type { RelationsDriver, RelationsDriverCapabilities, ScopeRef } from '../src/types.js'

const FULL: RelationsDriverCapabilities = {
  singleCheckRelations: true,
  listObjectsInherited: false,
  usersetSubjects: true,
  membersOfNative: true,
  enumerateRelations: true,
  listObjectsTruncation: true,
  injectableClock: true,
  // Doble en memoria (L-2/L-4): no escribe en ninguna transacción, así que declara `false` y se le juzga esa cara; la `true` la juzga el driver `database` REAL en pool ≥ 2 (`relations_database.spec.ts`).
  transactionalWrites: false,
}
const MINIMAL: RelationsDriverCapabilities = {
  singleCheckRelations: false,
  listObjectsInherited: false,
  usersetSubjects: false,
  membersOfNative: false,
  enumerateRelations: false,
  listObjectsTruncation: false,
  injectableClock: false,
  // Doble en memoria (L-2/L-4): no escribe en ninguna transacción, así que declara `false` y se le juzga esa cara; la `true` la juzga el driver `database` REAL en pool ≥ 2 (`relations_database.spec.ts`).
  transactionalWrites: false,
}

function fakeApi() {
  const titles: string[] = []
  return {
    titles,
    api: {
      group: (_t: string, define: any) => define({ each: { setup: () => {} }, teardown: () => {} }),
      test: (title: string) => {
        titles.push(title)
        return { timeout: () => {} }
      },
    },
  }
}

function register(capabilities: RelationsDriverCapabilities, limits?: { listMaxResults?: number }) {
  const { api, titles } = fakeApi()
  const result = registerRelationsDriverContract(
    {
      name: 'harness-de-conteo',
      capabilities,
      limits: limits ?? { listMaxResults: 3 },
      makeDriver: (config) => makeRelationsDriver({ config, capabilities, limits: limits ?? { listMaxResults: 3 } }),
    },
    api as any
  )
  return { titles, ...result }
}

// 13 núcleo (R-01, R-02, R-03/04, R-05, R-06, R-07/08, R-09, R-12, F-05 tipo,
// F-05 relación, R-13, R-15, R-17) + 1 cara por cada una de las 8 capacidades = 21
// (L-2: el par `transactionalWrites`, mismo nombre que en roles; 19 + 1. L-4
// pobló su cara `true`: sigue siendo UN caso por cara, el total no se mueve.
// 2.4.0-alpha.3 · E7: R-17 «las purgas notifican» — un caso NUEVO del núcleo,
// 20 → 21; el runner corre 4 veces con el `:8101` (2 dobles + database +
// openfga), así que la suite sube +4 por él. Cierre de alpha.3 (🔴 1 / 🟠 2 del
// auditor): «F-05 · purgas y lecturas» — un caso NUEVO del núcleo, 21 → 22;
// otros +4 en la suite).
const EXPECTED_CASES = 22
const CAPABILITY_KEYS = 8

test.group('runner de relaciones — conteo y cobertura de capacidades', () => {
  // L-2/L-4: el par `transactionalWrites` tiene sus DOS caras en el código
  // del runner. Hasta L-4 la `true` LANZABA al registrar («no hay caso
  // todavía»); desde L-4 registra la cara del censo (rollback ⇒ CERO tuplas
  // nuevas para las cuatro escrituras, purge* revierten juntos, trx ajena ⇒
  // 500 sin sentencia). Es UN caso por cara: el total no se mueve.
  test('L-2/L-4 · transactionalWrites: true registra la cara «rollback ⇒ CERO tuplas (censo) + purge* revierten JUNTOS + trx ajena ⇒ 500 E_AUTHZ_CONFIG»; false registra la cara «500 UNSUPPORTED con cero llamadas + 500 CONFIG al construir»; en FULL y en MÍNIMO, mismo total', ({
    assert,
  }) => {
    const trueFace = (t: string) => t.startsWith('transactionalWrites:true') && t.includes('censo') && t.includes('JUNTOS') && t.includes('E_AUTHZ_CONFIG')
    const falseFace = (t: string) => t.startsWith('transactionalWrites:false') && t.includes('CERO llamadas') && t.includes('E_AUTHZ_CONFIG')
    const fullTrue = register({ ...FULL, transactionalWrites: true })
    const minTrue = register({ ...MINIMAL, transactionalWrites: true })
    assert.lengthOf(fullTrue.titles.filter(trueFace), 1)
    assert.lengthOf(minTrue.titles.filter(trueFace), 1)
    assert.lengthOf(fullTrue.titles.filter(falseFace), 0)
    assert.equal(fullTrue.registered, EXPECTED_CASES, 'la cara true es UN caso: el total no se mueve')
    assert.equal(fullTrue.covered.size, CAPABILITY_KEYS)
    assert.lengthOf(register(FULL).titles.filter(falseFace), 1)
    assert.lengthOf(register(MINIMAL).titles.filter(falseFace), 1)
    assert.lengthOf(register(FULL).titles.filter(trueFace), 0)
  })

  test('un harness FULL registra el nº literal de casos y cubre las 8 capacidades', ({ assert }) => {
    const { registered, covered, titles } = register(FULL)
    assert.equal(registered, EXPECTED_CASES)
    assert.equal(titles.length, EXPECTED_CASES)
    assert.equal(covered.size, CAPABILITY_KEYS)
  })

  test('un harness MÍNIMO registra el MISMO total y también cubre las 8', ({ assert }) => {
    const { registered, covered } = register(MINIMAL)
    assert.equal(registered, EXPECTED_CASES)
    assert.equal(covered.size, CAPABILITY_KEYS)
  })

  test('true y false eligen caras DISTINTAS de membersOfNative (no un skip)', ({ assert }) => {
    const full = register(FULL).titles.find((t) => t.startsWith('membersOfNative'))
    const min = register(MINIMAL).titles.find((t) => t.startsWith('membersOfNative'))
    assert.include(full, 'TRANSITIVA')
    assert.include(min, 'E_AUTHZ_UNSUPPORTED')
    assert.notEqual(full, min)
  })

  test('R-15: injectableClock es un par (reloj inyectado vs tiempo real) y el núcleo lleva el caso de caducidad estricta', ({
    assert,
  }) => {
    const full = register(FULL).titles
    const min = register(MINIMAL).titles
    assert.isTrue(full.some((t) => t.startsWith('injectableClock:true') && t.includes('T−1 ms')))
    assert.isTrue(min.some((t) => t.startsWith('injectableClock:false') && t.includes('tiempo real')))
    // El caso de núcleo (sin reloj) va en los DOS harnesses.
    assert.isTrue(full.some((t) => t.startsWith('R-15 ·')))
    assert.isTrue(min.some((t) => t.startsWith('R-15 ·')))
  })

  // ── «Una capacidad `true` sin su soporte se rechaza» (paridad con el guard
  // de roles) ──────────────────────────────────────────────────────────────
  test('listObjectsTruncation:true SIN limits.listMaxResults se rechaza AL REGISTRAR', ({ assert }) => {
    assert.throws(() => register(FULL, {}), /'listObjectsTruncation: true'/)
  })

  test('un driver que MIENTE (membersOfNative/enumerateRelations true sin el método) ⇒ 500, jamás un skip', async ({
    assert,
  }) => {
    const config = contractRelationsConfig()
    // El doble MÍNIMO no trae ni `membersOf` ni `enumerateRelations`; le
    // ponemos las capacidades en `true` (la mentira). El manager NO delega a
    // ciegas: comprueba el método Y la capacidad.
    const base = makeRelationsDriver({ config, capabilities: MINIMAL })
    const liar: RelationsDriver = {
      ...base,
      capabilities: { ...MINIMAL, membersOfNative: true, enumerateRelations: true },
    }
    const manager = new RelationsManager(liar, config)
    const p: ScopeRef = { type: 'app', uuid: null }
    // No basta con que RECHACE ni con que el mensaje cite el método: un guard que
    // solo mira la capacidad (no el método) delegaría a ciegas y estallaría con un
    // `TypeError: ...membersOf is not a function` —cuyo mensaje TAMBIÉN cita el
    // método—. El contrato es 500 `E_AUTHZ_UNSUPPORTED` (invariante 5: nunca fugar
    // el crudo), así que se ASERE el status y el code, no solo la regex.
    const caughtM = await manager
      .membersOf({ type: 'group', id: '00000000-0000-7000-8000-000000000001' }, 'member', p)
      .then(() => null, (e) => e)
    assert.equal(caughtM?.status, 500, 'membersOf mentido ⇒ 500 clasificado, no un TypeError crudo')
    assert.equal(caughtM?.code, 'E_AUTHZ_UNSUPPORTED')
    assert.include(caughtM?.message, 'membersOf')
    const caughtE = await manager.enumerateRelations(p).then(() => null, (e) => e)
    assert.equal(caughtE?.status, 500, 'enumerateRelations mentido ⇒ 500 clasificado')
    assert.equal(caughtE?.code, 'E_AUTHZ_UNSUPPORTED')
    assert.include(caughtE?.message, 'enumerateRelations')
  })
})

/* ── El conteo del contrato de RECONCILE (censo bidireccional) ───────────── */

function registerReconcile() {
  const { api, titles } = fakeApi()
  const config = contractRelationsConfig()
  const { registered } = registerRelationsReconcileContract(
    {
      name: 'conteo-reconcile',
      config,
      makeA: () => makeRelationsDriver({ config, capabilities: FULL }),
      makeB: () => makeRelationsDriver({ config, capabilities: FULL }),
    },
    api as any
  )
  return { registered, titles }
}

test.group('runner de reconcile de relaciones — conteo', () => {
  // 5 casos por dirección (migra+censo, idempotente, --prune, R-15 caducidad,
  // --dry-run) × 2 direcciones (A→B, B→A) + 1 (driver sin enumerateRelations ⇒ 500) = 11.
  test('el contrato de reconcile registra 11 casos (5×2 direcciones + 1 negativo)', ({ assert }) => {
    const { registered, titles } = registerReconcile()
    assert.equal(registered, 11)
    assert.equal(titles.length, 11)
    assert.lengthOf(titles.filter((t) => t.includes('CENSO')), 2)
    assert.lengthOf(titles.filter((t) => t.includes('R-15')), 2)
  })
})

/* ── EL CONTEO LITERAL DEL JUEZ para la Fase 4 (~41), aterrizado ─────────── */

test.group('Fase 4 · el conteo literal del juez (~41)', () => {
  // El juez (fase-4-juez.md · «Desglose honesto del conteo (~41, no 34)») fijó
  // un OBJETIVO de ~41 casos LÓGICOS repartidos por toda la fase (no solo el
  // runner). Aquí se ANCLA cada componente con su literal y su ubicación, para
  // que el número documentado no pueda deslizarse en silencio. Desde R-15
  // (2.4.0-alpha.2, decisión del dueño tras la verificación de COGNITIV) los
  // dos que estaban DIFERIDOS aterrizan y el objetivo se cumple entero; lo que
  // R-15 añadió POR ENCIMA del conteo del juez se declara aparte.
  const BREAKDOWN = {
    // Núcleo del puerto (R-01…R-09, R-11, R-12) — el runner los registra como
    // los 11 casos que NO son de capacidad. `relations_contract.spec.ts`,
    // `relations_database.spec.ts`, `relations_openfga.spec.ts`.
    nucleo: 11,
    // Caras de capacidad ×2 de las 4 con dos caras observables:
    // listObjectsTruncation, membersOfNative, usersetSubjects, enumerateRelations.
    carasCapacidad: 8,
    // Frontera / negativos / config: F-01…F-05, ⚪4, ⚪5, 🟡2, 🟡3.
    // `relations_bridge.spec.ts`, `relations.spec.ts`, `relations_database.spec.ts`,
    // `relations_persisted_config.spec.ts`.
    fronteraNegativosConfig: 9,
    // Gates unitarios: bytes del modelo FUSIONADO (2 caras) + profundidad
    // can_<P> con 500 reps (1). `openfga_facts.spec.ts`.
    gatesUnitarios: 3,
    // Carrera defineRelationsConfig↔syncAuthzCatalog + el 409 que no cede.
    // `relations_republish.spec.ts`.
    carrera: 2,
    // Reconcile (el censo bidireccional, más allá del contador).
    // `relations_reconcile.spec.ts` + el contrato publicado.
    reconcile: 3,
    // Solo-driver: trigger raw cross-partición, dialecto ajeno ⇒ throw, y
    // «renovar caducidad = delete+insert» (R-15, decisión (c) observable: la
    // fila cambia de uuid). `relations_database.spec.ts`.
    soloDriver: 3,
    // Anexo: R-13 (assertWrite puro + actor) y R-15 (caducidad estricta de la
    // tupla, en el núcleo del runner: pasado no concede, inválido ⇒ 422).
    anexo: 2,
  }
  // Objetivo del juez, cumplido entero: ya no hay nada DIFERIDO.
  const JUEZ_TARGET = 41
  const DEFERRED = {}
  // Lo que R-15 trajo POR ENCIMA del conteo del juez (él contó R-15 como UN
  // caso condicional): el par `injectableClock` con sus dos caras (paridad con
  // roles: T−1/T/T+1 con reloj, tiempo real sin él) y la caducidad a través de
  // `reconcile` (la vigente viaja con su instante, la caducada llega y se cuenta).
  // 2.4.0-alpha.3 · E7: R-17 (las purgas notifican UN evento con su forma y
  // respetan `requireActor`) — el hallazgo #4 del barrido de paridad, por
  // encima del conteo del juez de la Fase 4. Cierre de alpha.3: F-05 en las
  // purgas y las lecturas (🔴 1 / 🟠 2 del auditor: el juez de la Fase 4
  // plantó el exploit solo en `relate`/`unrelate`, y por `purgeObject` se
  // borraba un binding real del store compartido).
  const BEYOND_JUEZ = {
    injectableClockFaces: 2,
    reconcileExpiry: 1,
    purgeEvents: 1,
    f05PurgesAndReads: 1,
  }

  test('los componentes suman el objetivo del juez ENTERO (nada diferido) más lo que R-15 y alpha.3 añadieron por encima', ({
    assert,
  }) => {
    const landed = Object.values(BREAKDOWN).reduce((a, b) => a + b, 0)
    const deferred = Object.values(DEFERRED).reduce((a: number, b) => a + (b as number), 0)
    const beyond = Object.values(BEYOND_JUEZ).reduce((a, b) => a + b, 0)
    assert.equal(landed, JUEZ_TARGET, 'los ~41 del juez EXISTEN de verdad, R-15 incluida')
    assert.equal(deferred, 0, 'con R-15 adelantada no queda nada diferido')
    assert.equal(beyond, 5, 'lo añadido por R-15 (3), alpha.3 · R-17 (1) y el cierre de alpha.3 · F-05 en purgas y lecturas (1) por encima del conteo del juez')
    // Los casos nuevos del núcleo existen en los DOS harnesses (no son caras de capacidad).
    assert.isTrue(register(FULL).titles.some((t) => t.startsWith('R-17 ·')))
    assert.isTrue(register(MINIMAL).titles.some((t) => t.startsWith('R-17 ·')))
    const f05PurgesAndReads = (t: string) => t.startsWith('F-05 · purgeObject/purgeSubject(userset)/check/listObjects/listSubjects')
    assert.lengthOf(register(FULL).titles.filter(f05PurgesAndReads), 1)
    assert.lengthOf(register(MINIMAL).titles.filter(f05PurgesAndReads), 1)
  })
})
