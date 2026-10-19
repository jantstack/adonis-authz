/**
 * **El intérprete del modelo FGA en proceso** (`tests/helpers/fga_interpreter.ts`) y lo que juzga (lote «antes de RC»,
 * 6b: opción E firmada por el dueño, diseño del tester en `loteRC-6b-estudio-tester.md` §1 y §3).
 *
 * - semántica determinista sobre el modelo GENERADO (c2r) y el de relaciones fusionado (`defineRelationsConfig`);
 * - contador de lecturas por `Check` (C-1: el coste por profundidad, `root`/`leaf`/`dl`, como tabla EXACTA);
 * - el comprobador del lector rasgado con su CONTROL POSITIVO: con c2r encuentra D1–D4 y el descendiente (medidos en
 *   `loteRC-me5-moved.md` y `loteRC-6b-estudio-analista.md`) y el PREFIJO arista→barrido de `moved` (🟠 del auditor,
 *   `loteRC-6b-estudio-auditor.md`); con c3u (control negativo) no encuentra nada de una sola arista;
 * - T-1 exhaustivo: 50 bosques × 256 repartos × 378 cambios de una arista × 4 destinos;
 * - con `OPENFGA_TEST_URL`: el diferencial intérprete == servidor (semilla fija, concurrencia ≤ 8), con la divergencia
 *   DECLARADA de profundidad (el intérprete no modela `resolve-node-limit`).
 */

import { test } from '@japa/runner'
import { readFile } from 'node:fs/promises'
import {
  factsBindingObject,
  factsBindingTuples,
  factsCatalogTuples,
  factsDenyTuple,
  factsParentTuple,
  factsRootTuples,
  factsScopeBindingTuple,
  factsScopeObject,
  openFgaFactsModel,
} from '../src/drivers/openfga_facts.js'
import { defineRelationsConfig } from '../src/relations/define_relations_config.js'
import {
  TupleStore,
  checkTuples,
  compileModel,
  describeUniverseCase,
  exhaustiveSingleEdge,
  impossibleTrues,
  possibleVerdicts,
  timestampNs,
  universeOperation,
} from './helpers/fga_interpreter.js'
import type {
  CheckRequest,
  CompiledModel,
  FgaTuple,
  UniverseCase,
  UniverseNode,
  UniverseTuples,
  Verdict,
  WriteStep,
} from './helpers/fga_interpreter.js'
import { c3uFactsModel } from './helpers/fga_model_variants.js'

/* ── El universo de los casos sin servidor ─────────────────────────────── */

const HOLDERS = { users: 'user' }
const PERM = 'docs:read'
const CAN = 'can_docs_read'
const ROLE = '0192f000-0000-7000-8000-000000000001'
const NOW = '2030-06-15T10:20:30.999Z'
const U = 'user:u'

const key = (node: string) => (node === 'app' ? 'app' : `unit|${node}`)
const scope = (node: string) => factsScopeObject(key(node))
const edge = (child: string, parent: string): FgaTuple => factsParentTuple(key(child), key(parent))
const deny = (node: string, user = U): FgaTuple => factsDenyTuple(key(node), PERM, user)
function grant(node: string, user = U, condition?: FgaTuple['condition']): FgaTuple[] {
  const assignee: FgaTuple = { user, relation: 'assignee', object: factsBindingObject(key(node), ROLE) }
  if (condition) assignee.condition = condition
  return [...factsBindingTuples(key(node), ROLE), assignee]
}
const FIXED: FgaTuple[] = [
  ...factsRootTuples(HOLDERS),
  ...factsCatalogTuples([{ uuid: ROLE, permissions: [PERM] }], HOLDERS),
]
const can = (node: string, user = U): CheckRequest => ({ user, relation: CAN, object: scope(node), context: { current_time: NOW } })

const C2R = compileModel(openFgaFactsModel(HOLDERS, [PERM]))
const C3U = compileModel(c3uFactsModel(HOLDERS, [PERM]))

const UNIVERSE: UniverseTuples = {
  fixed: FIXED,
  edge,
  grant: (node) => grant(node),
  deny: (node) => deny(node),
  request: (target) => can(target),
}

const verdict = (model: CompiledModel, tuples: FgaTuple[], request: CheckRequest): Verdict =>
  checkTuples(model, new TupleStore(tuples), request).verdict

/** El `Write` de un move: borra la arista vieja y escribe la nueva (como `reparent`). */
const moveStep = (child: string, from: string | null, to: string | null): WriteStep => ({
  deletes: from === null ? [] : [edge(child, from)],
  writes: to === null ? [] : [edge(child, to)],
})

/* ── 1. Semántica determinista ─────────────────────────────────────────── */

test.group('intérprete FGA · semántica determinista del modelo generado (c2r)', () => {
  test('herencia SOLO hacia abajo, desde la raíz (inv. 1); deny en la cadena gana (inv. 2); sin raíz deniega (inv. 9)', ({ assert }) => {
    const tree = [...FIXED, edge('a', 'app'), edge('b', 'a'), edge('c', 'app')]
    assert.equal(verdict(C2R, [...tree, ...grant('a')], can('b')), 'T', 'un grant en a vale en su hijo b')
    assert.equal(verdict(C2R, [...tree, ...grant('a')], can('a')), 'T')
    assert.equal(verdict(C2R, [...tree, ...grant('b')], can('a')), 'F', 'nunca hacia el ancestro')
    assert.equal(verdict(C2R, [...tree, ...grant('a')], can('c')), 'F', 'nunca en un hermano')
    assert.equal(verdict(C2R, [...tree, ...grant('b'), deny('a')], can('b')), 'F', 'un deny ARRIBA bloquea un grant abajo')
    assert.equal(verdict(C2R, [...tree, ...grant('a'), deny('app')], can('b')), 'F', 'un deny en app gana en todo el árbol')
    assert.equal(verdict(C2R, [...tree, ...grant('a'), deny('c')], can('b')), 'T', 'el deny de un hermano no alcanza')
    const detached = [...FIXED, edge('b', 'a'), ...grant('a')]
    assert.equal(verdict(C2R, detached, can('b')), 'F', 'un subárbol desgajado no concede ni dentro de sí')
    const noMarker = [...factsCatalogTuples([{ uuid: ROLE, permissions: [PERM] }], HOLDERS), edge('a', 'app'), ...grant('a')]
    assert.equal(verdict(C2R, noMarker, can('a')), 'F', 'sin marcador de raíz el store entero deniega')
  })

  test('holders polimórficos (inv. 4) y el filtro de restricciones de tipo del modelo', ({ assert }) => {
    const two = compileModel(openFgaFactsModel({ users: 'user', admins: 'admin' }, [PERM]))
    const tuples = [
      ...factsRootTuples({ users: 'user', admins: 'admin' }),
      ...factsCatalogTuples([{ uuid: ROLE, permissions: [PERM] }], { users: 'user', admins: 'admin' }),
      edge('a', 'app'),
      ...grant('a', 'user:x'),
    ]
    assert.equal(verdict(two, tuples, can('a', 'user:x')), 'T')
    assert.equal(verdict(two, tuples, can('a', 'admin:x')), 'F', 'mismo id con otro tipo no se cruza')
    // `denied_<P>` no admite comodín: una tupla `@user:*` no la declara el modelo y el servidor la ignora al leer.
    const wildDeny = [...FIXED, edge('a', 'app'), ...grant('a'), { user: 'user:*', relation: 'denied_docs_read', object: scope('a') }]
    assert.equal(verdict(C2R, wildDeny, can('a')), 'T', 'una tupla fuera de las restricciones de tipo no cuenta')
  })

  test('caducidad (inv. 3) con `not_expired` en NANOSEGUNDOS (M-b): estricta, con desfase, coma y truncado a 9', ({ assert }) => {
    const at = (validUntil: string) =>
      verdict(C2R, [...FIXED, edge('a', 'app'), ...grant('a', U, { name: 'not_expired', context: { valid_until: validUntil } })], can('a'))
    assert.equal(at('2030-06-15T10:20:30.999000001Z'), 'T', '+1 ns concede')
    assert.equal(at('2030-06-15T10:20:30.999Z'), 'F', 'lo que vence AHORA no cuenta')
    assert.equal(at('2030-06-15T12:20:30.999+02:00'), 'F', 'el mismo instante con desfase')
    assert.equal(at('2030-06-15T10:20:30,9990001Z'), 'T', 'la coma decimal se acepta')
    assert.equal(at('2030-06-15T10:20:30.9990000009Z'), 'F', 'más de 9 decimales se TRUNCAN, no se redondean')
    assert.equal(at('2030-06-16T10:20:30.999+24:00'), 'F', '±24:00 se acepta y desplaza')
    assert.equal(at('2030-06-15T10:20:30.998999999Z'), 'F', '−1 ns ya venció')
  })

  test('el parser de marcas sigue la gramática que acepta el servidor (M-b · bordes)', ({ assert }) => {
    assert.equal(timestampNs('1970-01-01T00:00:00Z'), 0n)
    assert.equal(timestampNs('1970-01-01T00:00:00.000000001Z'), 1n)
    assert.equal(timestampNs('1970-01-01T01:00:00+01:00'), 0n)
    assert.equal(timestampNs('0000-01-01T00:00:00Z'), -62_167_219_200_000_000_000n)
    assert.equal(timestampNs('9999-12-31T23:59:59.999999999Z'), 253_402_300_799_999_999_999n)
    for (const rejected of [
      '2030-06-15T23:59:60Z',
      '2030-06-15T24:00:00Z',
      '2030-02-30T00:00:00Z',
      '2030-06-15t10:20:30Z',
      '2030-06-15T10:20:30z',
      '2030-06-15 10:20:30Z',
      '2030-06-15T10:20:30',
      '2030-06-15T10:20:30+0000',
      '2030-06-15T10:20:30+99:00',
      '2030-06-15T10:20:30.Z',
      '2030-06-15',
      '',
    ]) {
      assert.isNull(timestampNs(rejected), rejected)
    }
  })

  test('errores con la semántica de los operadores: parámetro ausente ⇒ E, salvo que otra rama conceda', ({ assert }) => {
    const broken = { name: 'not_expired', context: {} }
    const only = [...FIXED, edge('a', 'app'), ...grant('a', U, broken)]
    assert.equal(verdict(C2R, only, can('a')), 'E', 'sin valid_until en la tupla el Check es un error')
    const both = [...only, ...grant('b'), edge('b', 'app')]
    assert.equal(verdict(C2R, [...FIXED, edge('a', 'app'), edge('b', 'a'), ...grant('a', U, broken), ...grant('b')], can('b')), 'T',
      'una union con una rama T concede aunque otra rama falle')
    assert.equal(verdict(C2R, both, can('a', 'user:otro')), 'F', 'quien no tiene la tupla rota no ve el error')
    assert.equal(verdict(C2R, [...only, deny('app')], can('a')), 'F', 'una difference con resta T es F aunque la base falle')
    const noTime = { user: U, relation: CAN, object: scope('a') }
    assert.equal(verdict(C2R, [...FIXED, edge('a', 'app'), ...grant('a', U, { name: 'not_expired', context: { valid_until: NOW } })], noTime), 'E',
      'sin current_time en la petición, la condición no se puede evaluar')
  })

  test('el ciclo que FGA acepta (3b-2b): la rama que vuelve sobre sí es F, no se cuelga, y concede hacia ARRIBA', ({ assert }) => {
    const base = [...FIXED, edge('o', 'app'), edge('u', 'o'), ...grant('u')]
    assert.equal(verdict(C2R, base, can('o')), 'F', 'sin ciclo, el grant de la unit no concede en la org')
    assert.equal(verdict(C2R, [...base, edge('o', 'u')], can('o')), 'T', 'con la org colgada de la unit, concede hacia arriba')
    assert.equal(verdict(C2R, [...base, edge('o', 'u')], can('app')), 'F', 'la raíz no cuelga de nadie: no la alcanza')
    assert.equal(verdict(C2R, [...base, edge('o', 'u'), edge('app', 'o')], can('app')), 'T', 'con la raíz colgada, sí')
  })

  test('el modelo de relaciones fusionado (`defineRelationsConfig`): usersets anidados, includes, deny y caducidad', ({ assert }) => {
    const config = defineRelationsConfig({
      objectTypes: [
        { type: 'note', relations: [{ name: 'owner' }, { name: 'editor', includes: ['owner'] }, { name: 'viewer', includes: ['editor'] }], deny: 'read' },
      ],
      holderTypes: ['user'],
    })
    const fused = compileModel(openFgaFactsModel(HOLDERS, [PERM], { objectTypes: config.objectTypes }))
    const rel = (user: string, relation: string, object: string, validUntil?: string): FgaTuple => ({
      user,
      relation,
      object,
      ...(validUntil ? { condition: { name: 'not_expired', context: { valid_until: validUntil } } } : {}),
    })
    const tuples = [
      rel('user:u', 'member', 'group:g0'),
      rel('group:g0#member', 'member', 'group:g1'),
      rel('group:g1#member', 'editor', 'note:n'),
      rel('user:v', 'member', 'group:g0', '2030-06-15T10:20:30.999Z'),
    ]
    const ask = (user: string, relation: string, extra: FgaTuple[] = []) =>
      verdict(fused, [...tuples, ...extra], { user, relation, object: 'note:n', context: { current_time: NOW } })
    assert.equal(ask('user:u', 'viewer'), 'T', 'editor por un grupo anidado ⇒ viewer')
    assert.equal(ask('user:u', 'owner'), 'F', 'includes solo hacia abajo')
    assert.equal(ask('user:v', 'viewer'), 'F', 'la membresía que vence AHORA no transporta')
    assert.equal(ask('user:u', 'viewer', [rel('user:u', 'denied_editor', 'note:n')]), 'F', 'deny en editor corta viewer (cierre ascendente)')
    assert.equal(ask('user:u', 'viewer', [rel('group:g0#member', 'denied_viewer', 'note:n')]), 'F', 'el deny viaja por el userset')
    assert.equal(ask('user:u', 'editor', [rel('user:u', 'denied_viewer', 'note:n')]), 'F', 'deny en viewer alcanza denied_editor (D5)')
    assert.equal(ask('user:u', 'viewer', [rel('user:u', 'denied_owner', 'note:n')]), 'T', 'deny en owner no baja a editor/viewer')
  })
})

/* ── 2. Contador de lecturas (C-1) ─────────────────────────────────────── */

/** Cadena `app ← n1 ← … ← nd`, Check en la hoja. `root`: grant en app; `leaf`: grant en n1..nd; `dl`: leaf + deny en app. */
function chainReads(model: CompiledModel, d: number, shape: 'root' | 'leaf' | 'dl') {
  const n = (i: number) => (i === 0 ? 'app' : `n${i}`)
  const tuples: FgaTuple[] = [...FIXED]
  for (let i = 1; i <= d; i++) tuples.push(edge(n(i), n(i - 1)))
  if (shape === 'root') tuples.push(...grant('app'))
  else for (let i = 1; i <= d; i++) tuples.push(...grant(n(i)))
  if (shape === 'dl') tuples.push(deny('app'))
  const r = checkTuples(model, new TupleStore(tuples), can(n(d)))
  return `${r.verdict}${r.reads}`
}

test.group('intérprete FGA · C-1: lecturas por Check según la profundidad (tabla EXACTA)', () => {
  // Cuenta: cada `this` y cada tupleset de TTU = 1 lectura, sin memoizar y SIN cortocircuito (cota superior
  // determinista; el servidor evalúa en paralelo y corta). Cambiar el modelo mueve la tabla y este caso lo dice.
  const EXPECTED = {
    c2r: { root: ['T15', 'T57', 'T99', 'T141'], leaf: ['T15', 'T78', 'T141', 'T204'], dl: ['F15', 'F78', 'F141', 'F204'] },
    c3u: { root: ['T22', 'T246', 'T715', 'T1429'], leaf: ['T22', 'T267', 'T757', 'T1492'], dl: ['F22', 'F267', 'F757', 'F1492'] },
  }
  for (const [name, model] of [['c2r', C2R], ['c3u', C3U]] as const) {
    for (const shape of ['root', 'leaf', 'dl'] as const) {
      test(`${name} · ${shape} · d ∈ {1, 8, 15, 22} ⇒ ${EXPECTED[name][shape].join(' / ')}`, ({ assert }) => {
        assert.deepEqual([1, 8, 15, 22].map((d) => chainReads(model, d, shape)), EXPECTED[name][shape])
      })
    }
  }

  test('la razón c3u/c2r a d = 22 (lo que firmaría el dueño): ×10,1 en root, ×7,3 en leaf/dl', ({ assert }) => {
    const ratio = (shape: 'root' | 'leaf' | 'dl') =>
      Number(chainReads(C3U, 22, shape).slice(1)) / Number(chainReads(C2R, 22, shape).slice(1))
    assert.closeTo(ratio('root'), 10.13, 0.01)
    assert.closeTo(ratio('leaf'), 7.31, 0.01)
    assert.closeTo(ratio('dl'), 7.31, 0.01)
  })
})

/* ── 3. Lector rasgado: control positivo, prefijo y residuo ────────────── */

/** Los escenarios del estudio, en el universo de nodos a/b/c (`D1`…`D4` del analista y el auditor). */
interface Scenario {
  name: string
  tuples: FgaTuple[]
  steps: WriteStep[]
  target: string
}

const SINGLE_EDGE: Scenario[] = [
  {
    // M-e(5): grant + deny en A (gana el deny), B vacío; C de A a B.
    name: 'D1 · grant+deny en A, B vacío, moved C A→B (nodo)',
    tuples: [...FIXED, edge('a', 'app'), edge('b', 'app'), edge('c', 'a'), ...grant('a'), deny('a')],
    steps: [moveStep('c', 'a', 'b')],
    target: 'c',
  },
  {
    name: 'D1 · descendiente: C (con hijo D) de A a app',
    tuples: [...FIXED, edge('a', 'app'), edge('b', 'a'), edge('c', 'b'), ...grant('a'), deny('a')],
    steps: [moveStep('b', 'a', 'app')],
    target: 'c',
  },
  {
    name: 'D2 · grant en C, deny en A enraizado, destino D desgajado',
    tuples: [...FIXED, edge('a', 'app'), edge('c', 'a'), ...grant('c'), deny('a')],
    steps: [moveStep('c', 'a', 'b')],
    target: 'c',
  },
  {
    name: 'D3 · A desgajado con grant, B enraizado y vacío, moved C A→B',
    tuples: [...FIXED, edge('b', 'app'), edge('c', 'a'), ...grant('a')],
    steps: [moveStep('c', 'a', 'b')],
    target: 'c',
  },
  {
    name: 'D4 · attached C bajo A con grant+deny en A',
    tuples: [...FIXED, edge('a', 'app'), ...grant('a'), deny('a')],
    steps: [moveStep('c', null, 'a')],
    target: 'c',
  },
  {
    name: 'D4 · detached C de A con grant+deny en A',
    tuples: [...FIXED, edge('a', 'app'), edge('c', 'a'), ...grant('a'), deny('a')],
    steps: [moveStep('c', 'a', null)],
    target: 'c',
  },
  {
    name: 'D4 · descendiente: attached B (con hijo C) bajo A',
    tuples: [...FIXED, edge('a', 'app'), edge('c', 'b'), ...grant('a'), deny('a')],
    steps: [moveStep('b', null, 'a')],
    target: 'c',
  },
]

const kinds = (model: CompiledModel, s: Scenario) =>
  impossibleTrues(model, new TupleStore(s.tuples), s.steps, [can(s.target)]).map((f) => f.kind)

test.group('intérprete FGA · lector rasgado · CONTROL POSITIVO sobre c2r (D1–D4 y descendiente)', () => {
  for (const s of SINGLE_EDGE) {
    test(`c2r ENCUENTRA ${s.name}`, ({ assert }) => {
      const before = new TupleStore(s.tuples)
      const after = before.apply(s.steps[0])
      assert.equal(checkTuples(C2R, before, can(s.target)).verdict, 'F', 'precondición: antes no concede')
      assert.equal(checkTuples(C2R, after, can(s.target)).verdict, 'F', 'precondición: después no concede')
      assert.deepEqual(kinds(C2R, s), ['torn'], 'el lector rasgado da un `true` que ningún estado da')
      assert.includeMembers(possibleVerdicts(C2R, [before, after], can(s.target)), ['T', 'F'])
    })
  }

  test('el MISMO control sobre el fixture congelado de c2r (sobrevive a un cambio del generador)', async ({ assert }) => {
    const fixture = compileModel(JSON.parse(await readFile(new URL('./fixtures/facts_model_c2r.json', import.meta.url), 'utf8')))
    for (const s of SINGLE_EDGE) assert.deepEqual(kinds(fixture, s), ['torn'], s.name)
  })

  test('control NEGATIVO: c3u no da `true` imposibles en ninguno de los escenarios de una arista', ({ assert }) => {
    for (const s of SINGLE_EDGE) assert.deepEqual(kinds(C3U, s), [], s.name)
  })

  test('sin cambio no hay hallazgo: una operación que no toca nada no rasga nada', ({ assert }) => {
    for (const s of SINGLE_EDGE) assert.deepEqual(impossibleTrues(C2R, new TupleStore(s.tuples), [{}], [can(s.target)]), [], s.name)
  })
})

/** El `moved` de un ROL LOCAL (owner A) asignado a u en C, con deny de P en A: arista + barrido del binding. */
function localRoleMove(order: 'edge-then-sweep' | 'sweep-then-edge'): Scenario {
  const sweep: WriteStep = { deletes: [factsScopeBindingTuple(key('c'), ROLE)] }
  const move = moveStep('c', 'a', 'b')
  return {
    name: order,
    tuples: [...FIXED, edge('a', 'app'), edge('b', 'app'), edge('c', 'a'), ...grant('c'), deny('a')],
    steps: order === 'edge-then-sweep' ? [move, sweep] : [sweep, move],
    target: 'c',
  }
}

test.group('intérprete FGA · el PREFIJO arista→barrido de `moved` (🟠 del auditor) y el residuo de dos escrituras', () => {
  test('orden del driver de hoy (arista y DESPUÉS barrido): el estado intermedio CONCEDE, en c2r y en c3u', ({ assert }) => {
    const s = localRoleMove('edge-then-sweep')
    for (const model of [C2R, C3U]) {
      const [finding, ...rest] = impossibleTrues(model, new TupleStore(s.tuples), s.steps, [can('c')])
      assert.lengthOf(rest, 0)
      assert.equal(finding?.kind, 'prefix', 'es un estado REAL del store, no una mezcla de lecturas')
      assert.deepEqual(finding?.prefixes, [1], 'el prefijo tras el primer Write')
    }
  })

  test('orden F4 (barrido y DESPUÉS arista): ningún prefijo concede; queda el residuo DECLARADO de dos `Write`', ({ assert }) => {
    const s = localRoleMove('sweep-then-edge')
    for (const model of [C2R, C3U]) {
      assert.deepEqual(kinds(model, s), ['torn'], 'binding leído antes del 1.er Write y arista después del 2.º')
    }
  })

  test('residuo de dos escrituras CUALESQUIERA con c3u (T-4): X1 move + removeDeny y D5 dos moves existen', ({ assert }) => {
    const x1: Scenario = {
      name: 'X1',
      tuples: [...FIXED, edge('a', 'app'), edge('b', 'app'), edge('c', 'a'), ...grant('a'), deny('a')],
      steps: [moveStep('c', 'a', 'b'), { deletes: [deny('a')] }],
      target: 'c',
    }
    const d5: Scenario = {
      name: 'D5',
      tuples: [...FIXED, edge('p1', 'app'), edge('p2', 'app'), edge('b', 'app'), edge('a', 'p1'), edge('c', 'a'), ...grant('p2')],
      steps: [moveStep('c', 'a', 'b'), moveStep('a', 'p1', 'p2')],
      target: 'c',
    }
    for (const s of [x1, d5]) {
      assert.deepEqual(kinds(C3U, s), ['torn'], `${s.name} con c3u`)
      assert.deepEqual(kinds(C2R, s), ['torn'], `${s.name} con c2r`)
    }
  })
})

/* ── 4. T-1 exhaustivo ─────────────────────────────────────────────────── */

const caseOf = (
  parents: Record<UniverseNode, 'app' | UniverseNode | null>,
  facts: UniverseCase['facts'],
  change: UniverseCase['change'],
  target: UniverseCase['target']
): string => describeUniverseCase({ parents, facts, change, target })

test.group('intérprete FGA · T-1: todo bosque de 3 nodos × todo reparto × todo cambio de UNA arista', () => {
  test('c2r: 50 bosques × 256 repartos × 378 cambios × 4 destinos ⇒ 14 832 `true` imposibles, D1–D4 entre ellos', ({ assert }) => {
    const report = exhaustiveSingleEdge(C2R, UNIVERSE)
    assert.deepInclude(report, { forests: 50, factAssignments: 256, changes: 378, tornEvaluations: 333_606 })
    assert.lengthOf(report.findings, 14_832)
    const found = new Set(report.findings.map(describeUniverseCase))
    const o = { app: '', a: '', b: '', c: '' } as const
    for (const literal of [
      caseOf({ a: 'app', b: 'app', c: 'a' }, { ...o, a: 'GD' }, { node: 'c', from: 'a', to: 'b', kind: 'moved' }, 'c'),
      caseOf({ a: 'app', b: 'a', c: 'b' }, { ...o, a: 'GD' }, { node: 'b', from: 'a', to: 'app', kind: 'moved' }, 'c'),
      caseOf({ a: 'app', b: null, c: 'a' }, { ...o, a: 'D', c: 'G' }, { node: 'c', from: 'a', to: 'b', kind: 'moved' }, 'c'),
      caseOf({ a: null, b: 'app', c: 'a' }, { ...o, a: 'G' }, { node: 'c', from: 'a', to: 'b', kind: 'moved' }, 'c'),
      caseOf({ a: 'app', b: null, c: null }, { ...o, a: 'GD' }, { node: 'c', from: null, to: 'a', kind: 'attached' }, 'c'),
      caseOf({ a: 'app', b: null, c: 'a' }, { ...o, a: 'GD' }, { node: 'c', from: 'a', to: null, kind: 'detached' }, 'c'),
      caseOf({ a: 'app', b: null, c: 'b' }, { ...o, a: 'GD' }, { node: 'b', from: null, to: 'a', kind: 'attached' }, 'c'),
    ]) {
      assert.isTrue(found.has(literal), `falta ${literal}`)
    }
    const byKind = report.findings.reduce<Record<string, number>>((acc, f) => ({ ...acc, [f.change.kind]: (acc[f.change.kind] ?? 0) + 1 }), {})
    assert.deepEqual(byKind, { moved: 3_156, attached: 5_838, detached: 5_838 })
  })

  test('c3u (control negativo): 0 `true` imposibles con una sola arista en el mismo universo', ({ assert }) => {
    const report = exhaustiveSingleEdge(C3U, UNIVERSE)
    assert.equal(report.tornEvaluations, 333_606)
    assert.deepEqual(report.findings.map(describeUniverseCase), [])
  })

  test('el estado del universo se construye con los helpers REALES del generador', ({ assert }) => {
    const { before, step } = universeOperation(UNIVERSE, { a: 'app', b: 'app', c: 'a' }, { app: '', a: 'GD', b: '', c: '' }, {
      node: 'c',
      from: 'a',
      to: 'b',
      kind: 'moved',
    })
    assert.sameDeepMembers(before.tuples(), [...FIXED, edge('a', 'app'), edge('b', 'app'), edge('c', 'a'), ...grant('a'), deny('a')])
    assert.deepEqual(step, moveStep('c', 'a', 'b'))
  })
})

/* ── 5. Diferencial intérprete == servidor ─────────────────────────────── */

const openFgaTestUrl = process.env.OPENFGA_TEST_URL
if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl
  test.group('intérprete FGA · diferencial intérprete == servidor (OPENFGA_TEST_URL, semilla fija)', (group) => {
    const stores: string[] = []
    group.each.teardown(async () => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      while (stores.length) await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
    })

    test('c2r y c3u fusionados con relaciones: ~800 Check, concurrencia 8; solo diverge la profundidad declarada', async ({ assert }) => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const corpus = differentialCorpus(Number(process.env.AUTHZ_INTERP_SEED ?? 11))
      const created = await new OpenFgaClient({ apiUrl }).createStore({ name: `interp-${Date.now()}` })
      stores.push(created.id!)
      const bare = new OpenFgaClient({ apiUrl, storeId: created.id })
      const ids: Record<string, string> = {}
      for (const [name, json] of Object.entries(corpus.models)) {
        ids[name] = (await bare.writeAuthorizationModel(json)).authorization_model_id!
      }
      const all = corpus.store.tuples()
      for (let i = 0; i < all.length; i += 100) await bare.write({ writes: all.slice(i, i + 100) as any })

      const compiled = Object.fromEntries(Object.entries(corpus.models).map(([name, json]) => [name, compileModel(json)]))
      const mismatches: string[] = []
      const declared: string[] = []
      const cyclic: string[] = []
      const counts = { checks: 0, T: 0, F: 0, E: 0 }
      let next = 0
      await Promise.all(
        Array.from({ length: 8 }, async () => {
          while (next < corpus.checks.length) {
            const item = corpus.checks[next++]
            const mine = checkTuples(compiled[item.model], corpus.store, item.request).verdict
            let theirs: Verdict
            let code = ''
            try {
              const r = await bare.check(item.request as any, { authorizationModelId: ids[item.model] })
              theirs = r.allowed ? 'T' : 'F'
            } catch (error: any) {
              theirs = 'E'
              code = error?.apiErrorCode ?? error?.responseData?.code ?? error?.name ?? 'error'
            }
            counts.checks++
            counts[theirs]++
            const line = `${item.model} ${item.label} ${item.request.user} ${item.request.relation} ${item.request.object}: intérprete ${mine}, servidor ${theirs}${code ? ' (' + code + ')' : ''}`
            if (mine === theirs) continue
            if (item.deep && theirs === 'E' && code === 'authorization_model_resolution_too_complex') declared.push(line)
            else if (item.cyclic && mine === 'T' && theirs === 'F') cyclic.push(line)
            else mismatches.push(line)
          }
        })
      )
      console.log(
        `[intérprete] diferencial: ${counts.checks} Check (T ${counts.T} · F ${counts.F} · E ${counts.E}); ` +
          `divergencias declaradas: profundidad ${declared.length}, ciclo (intérprete T, servidor F) ${cyclic.length}`
      )
      for (const line of cyclic) console.log(`[intérprete]   ciclo: ${line}`)
      assert.deepEqual(mismatches, [], 'intérprete == servidor fuera de la profundidad declarada')
      assert.isAbove(counts.checks, 700)
      assert.isAbove(counts.T, 50, 'el corpus concede de verdad')
      const semanticErrors = corpus.checks.filter((c) => c.label === 'error').length
      assert.isAbove(semanticErrors, 0)
      assert.isAtLeast(counts.E, semanticErrors + declared.length, 'y ejercita la semántica de error (no solo la de profundidad)')
      const deepEnd = corpus.checks.filter((c) => c.deep === 'beyond').length
      assert.lengthOf(declared, deepEnd, 'pasado el borde el servidor da resolution_too_complex y el intérprete un booleano')
    }).timeout(60_000)
  })
}

/* ── El corpus del diferencial (semilla fija) ──────────────────────────── */

interface DifferentialCheck {
  model: 'c2r' | 'c3u'
  label: string
  request: CheckRequest
  /** `within`: profundidad que el servidor resuelve; `beyond`: pasado su `resolve-node-limit` (divergencia declarada). */
  deep?: 'within' | 'beyond'
  /**
   * El escenario tiene un CICLO escrito a mano. Divergencia declarada y solo en una dirección: el servidor puede ser MÁS
   * estricto (intérprete T, servidor F) porque su resolutor clásico convierte un ciclo bajo `but not` en F.
   */
  cyclic?: boolean
}

function differentialCorpus(seed: number): { models: Record<string, any>; store: TupleStore; checks: DifferentialCheck[] } {
  let state = seed
  const rnd = () => (state = (state * 1103515245 + 12345) % 2 ** 31) / 2 ** 31
  const pick = <V>(xs: readonly V[]): V => xs[Math.floor(rnd() * xs.length)]

  const holders = { users: 'user', admins: 'admin', bots: 'bot' }
  const permissions = ['docs:read', 'docs.write']
  const relations = defineRelationsConfig({
    objectTypes: [
      { type: 'note', relations: [{ name: 'owner' }, { name: 'editor', includes: ['owner'] }, { name: 'viewer', includes: ['editor'] }], deny: 'read' },
      { type: 'doc', relations: [{ name: 'editor' }, { name: 'viewer', includes: ['editor'] }] },
    ],
    holderTypes: ['user', 'admin', 'bot'],
  })
  const objectTypes = relations.objectTypes
  const models = {
    c2r: openFgaFactsModel(holders, permissions, { objectTypes }),
    c3u: c3uFactsModel(holders, permissions, { objectTypes }),
  }
  const roles = [
    { uuid: '0192f000-0000-7000-8000-0000000000a1', permissions: ['docs:read'] },
    { uuid: '0192f000-0000-7000-8000-0000000000a2', permissions: ['docs:read', 'docs.write'] },
    { uuid: '0192f000-0000-7000-8000-0000000000a3', permissions: ['docs.write'] },
  ]
  const ct = '2030-06-15T10:20:30.999Z'
  const validUntil = [
    '2030-06-15T10:20:30.999000001Z',
    '2030-06-15T10:20:30.999Z',
    '2030-06-15T12:20:30.999+02:00',
    '2030-06-15T10:20:30,9990001Z',
    '2030-06-15T10:20:30.9990000009Z',
    '2030-06-16T10:20:30.999+24:00',
    '2029-01-01T00:00:00Z',
    '2031-01-01T00:00:00-05:30',
  ]
  const tuples = new Map<string, FgaTuple>()
  const put = (t: FgaTuple) => tuples.set(`${t.object}#${t.relation}@${t.user}`, t)
  // Marcador solo para user y admin: `bot` es un holder SIN marcador (todo lo suyo deniega).
  for (const t of factsRootTuples({ users: 'user', admins: 'admin' })) put(t)
  for (const t of factsCatalogTuples(roles, holders)) put(t)
  const checks: DifferentialCheck[] = []
  const both = (label: string, request: CheckRequest, cyclic = false) => {
    checks.push({ model: 'c2r', label, request, cyclic }, { model: 'c3u', label, request, cyclic })
  }

  // (a) Árboles aleatorios con deriva (segundo padre), desgajados, ciclos a mano, caducidades en ns, bindings barridos.
  for (let sc = 0; sc < 11; sc++) {
    const subjects = [`user:s${sc}`, `admin:s${sc}`, `bot:s${sc}`]
    const nodes: string[] = []
    const n = 2 + Math.floor(rnd() * 6)
    const grantAt = (k: string) => {
      const role = pick(roles).uuid
      const assignee: FgaTuple = { user: pick(subjects), relation: 'assignee', object: factsBindingObject(k, role) }
      if (rnd() < 0.4) assignee.condition = { name: 'not_expired', context: { valid_until: pick(validUntil) } }
      else if (rnd() < 0.05) assignee.condition = { name: 'not_expired', context: {} }
      const [toRole, toScope] = factsBindingTuples(k, role)
      const shape = rnd()
      put(toRole)
      if (shape >= 0.1) put(toScope) // < 0.1: asignación BARRIDA (sin scope#binding)
      if (shape < 0.1 || shape >= 0.15) put(assignee) // 0.1–0.15: arista sin assignee
    }
    for (let i = 0; i < n; i++) {
      const k = `unit|d${sc}n${i}`
      nodes.push(k)
      const r = rnd()
      const parents = i === 0 ? (r < 0.9 ? ['app'] : []) : r < 0.08 ? [] : [rnd() < 0.6 ? nodes[i - 1] : pick(nodes.slice(0, i))]
      if (i > 0 && rnd() < 0.25) {
        const extra = rnd() < 0.3 ? 'app' : pick(nodes.slice(0, i))
        if (!parents.includes(extra)) parents.push(extra)
      }
      for (const p of parents) put(factsParentTuple(k, p))
      const g = rnd()
      if (g < 0.4) grantAt(k)
      if (g < 0.12) grantAt(k)
      if (rnd() < 0.2) put(factsDenyTuple(k, pick(permissions), pick(subjects)))
    }
    const cycle = n > 2 && rnd() < 0.2
    if (cycle) put(factsParentTuple(nodes[0], nodes[n - 1])) // ciclo escrito a mano
    if (rnd() < 0.2) grantAt('app')
    if (rnd() < 0.1) put(factsDenyTuple('app', pick(permissions), pick(subjects)))
    for (const k of [...nodes, 'app']) {
      for (const s of subjects) {
        for (const p of permissions) {
          both(`arbol#${sc}`, { user: s, relation: `can_${p.replaceAll(':', '_')}`, object: factsScopeObject(k), context: { current_time: ct } }, cycle)
        }
      }
    }
  }

  // (b) Precedencia del contexto de la TUPLA frente al de la petición (un parámetro en los dos).
  for (const [i, tupleTime] of ['2031-01-01T00:00:00Z', '2020-01-01T00:00:00Z'].entries()) {
    const k = `unit|ctx${i}`
    put(factsParentTuple(k, 'app'))
    const [toRole, toScope] = factsBindingTuples(k, roles[0].uuid)
    put(toRole)
    put(toScope)
    put({
      user: 'user:ctx',
      relation: 'assignee',
      object: factsBindingObject(k, roles[0].uuid),
      condition: { name: 'not_expired', context: { valid_until: '2030-07-01T00:00:00Z', current_time: tupleTime } },
    })
    both('contexto', { user: 'user:ctx', relation: 'can_docs_read', object: factsScopeObject(k), context: { current_time: ct } })
  }

  // (b') Condición sin `valid_until` en la tupla: el `Check` es un error (400 `validation_error`), salvo otra rama T.
  for (const [i, alsoGood] of [false, true].entries()) {
    const k = `unit|err${i}`
    put(factsParentTuple(k, 'app'))
    for (const role of alsoGood ? [roles[0], roles[1]] : [roles[0]]) {
      const [toRole, toScope] = factsBindingTuples(k, role.uuid)
      put(toRole)
      put(toScope)
      const assignee: FgaTuple = { user: 'user:err', relation: 'assignee', object: factsBindingObject(k, role.uuid) }
      if (role === roles[0]) assignee.condition = { name: 'not_expired', context: {} }
      put(assignee)
    }
    both(alsoGood ? 'error+rama T' : 'error', { user: 'user:err', relation: 'can_docs_read', object: factsScopeObject(k), context: { current_time: ct } })
  }

  // (c) Relaciones: grupos anidados con membresías que caducan, includes, deny por userset.
  const groups = Array.from({ length: 6 }, (_, i) => `group:r${i}`)
  for (let i = 1; i < groups.length; i++) {
    if (rnd() < 0.7) put({ user: `${pick(groups.slice(0, i))}#member`, relation: 'member', object: groups[i] })
  }
  const people = ['user:p0', 'user:p1', 'admin:p2', 'bot:p3', 'user:p4']
  for (const person of people) {
    for (const g of groups) {
      if (rnd() < 0.25) {
        const t: FgaTuple = { user: person, relation: 'member', object: g }
        if (rnd() < 0.4) t.condition = { name: 'not_expired', context: { valid_until: pick(validUntil) } }
        put(t)
      }
    }
  }
  const objects = ['note:o0', 'note:o1', 'note:o2', 'doc:o3', 'doc:o4']
  for (const object of objects) {
    const isNote = object.startsWith('note:')
    const rels = isNote ? ['owner', 'editor', 'viewer'] : ['editor', 'viewer']
    for (let j = 0; j < 3; j++) {
      const subject = rnd() < 0.5 ? pick(people) : `${pick(groups)}#member`
      put({ user: subject, relation: pick(rels), object })
    }
    if (isNote && rnd() < 0.8) {
      const subject = rnd() < 0.5 ? pick(people) : `${pick(groups)}#member`
      put({ user: subject, relation: `denied_${pick(rels)}`, object })
    }
    for (const person of people) {
      for (const relation of rels) both('relaciones', { user: person, relation, object, context: { current_time: ct } })
    }
  }

  // (d) Profundidad: el servidor corta (M-c y «Cotas»); el intérprete no modela `resolve-node-limit`.
  const chain = (prefix: string, d: number) => {
    for (let i = 1; i <= d; i++) put(factsParentTuple(`unit|${prefix}${i}`, i === 1 ? 'app' : `unit|${prefix}${i - 1}`))
    return factsScopeObject(`unit|${prefix}${d}`)
  }
  const [rootRole, rootScope] = factsBindingTuples('app', roles[0].uuid)
  put(rootRole)
  put(rootScope)
  put({ user: 'user:deep', relation: 'assignee', object: factsBindingObject('app', roles[0].uuid) })
  checks.push({ model: 'c2r', label: 'facts d=22', request: { user: 'user:deep', relation: 'can_docs_read', object: chain('dA', 22), context: { current_time: ct } }, deep: 'within' })
  checks.push({ model: 'c2r', label: 'facts d=24', request: { user: 'user:deep', relation: 'can_docs_read', object: chain('dB', 24), context: { current_time: ct } }, deep: 'beyond' })
  for (let i = 1; i <= 26; i++) put({ user: `group:deep${i - 1}#member`, relation: 'member', object: `group:deep${i}` })
  put({ user: 'user:deep', relation: 'member', object: 'group:deep0' })
  for (let i = 1; i <= 3; i++) put({ user: 'user:other', relation: 'member', object: `group:other${i}` })
  for (const [d, deep] of [[22, 'within'], [24, 'within'], [26, 'beyond']] as const) {
    put({ user: `group:deep${d}#member`, relation: 'viewer', object: `doc:deep${d}` })
    checks.push({ model: 'c2r', label: `rel d=${d}`, request: { user: 'user:deep', relation: 'viewer', object: `doc:deep${d}`, context: { current_time: ct } }, deep })
  }
  checks.push({ model: 'c2r', label: 'rel neg d=22', request: { user: 'user:other', relation: 'viewer', object: 'doc:deep22', context: { current_time: ct } }, deep: 'within' })
  checks.push({ model: 'c2r', label: 'rel neg d=24', request: { user: 'user:other', relation: 'viewer', object: 'doc:deep24', context: { current_time: ct } }, deep: 'beyond' })

  return { models, store: new TupleStore(tuples.values()), checks }
}
