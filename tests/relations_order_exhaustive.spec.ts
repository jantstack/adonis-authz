/**
 * **El orden de una transición de relaciones, DEMOSTRADO por fuerza bruta** (plan 2.5 · lote D · cierre 2 de D2, 🟡 N3;
 * linaje L10 promovido). Sin servidor y sin base: `tests/helpers/order_bruteforce.ts` recorre TODOS los pares (inicial,
 * final) de un universo pequeño —y una muestra con semilla de dos universos mayores— y, en CADA prefijo del orden que da
 * `relationTransitionOrder`, comprueba:
 *
 *   concedido(prefijo) ⊆ concedido(inicial) ∪ concedido(final), y ningún sujeto denegado en los dos concede.
 *
 * La garantía que se demuestra (README «Denies migrate as denies»): **un par cuyo grafo de precedencias no tiene ciclo
 * (`residue` vacío) no concede en ningún prefijo**; el residuo es el ciclo y se mide cuánto de él NO admite ningún orden
 * seguro (inherente). Las cifras están FIJADAS: cambiar el orden cambia las cifras y pone rojo este spec — se re-miden y
 * se reescriben README/CHANGELOG/informe. También fija por qué se DESCARTARON el orden del cierre 1 de D2 y el candidato
 * del brief (cada uno con su contraejemplo).
 */
import { test } from '@japa/runner'
import { bruteForce, bruteForceVigencia, ORDER_CUTS, oracle, packageOrder, pick, universe, walkPair, walkVigencia } from './helpers/order_bruteforce.js'
import type { OrderFn } from './helpers/order_bruteforce.js'
import type { RelationOrderView } from '../src/relations/tuple_order.js'
import { denyCarrierGroups } from '../src/relations/tuple_order.js'

const isMembership = (v: RelationOrderView) => !v.deny && v.object.startsWith('group:')
const by = (a: RelationOrderView, b: RelationOrderView) => (a.object + a.user < b.object + b.user ? -1 : 1)

/** El orden del CIERRE 1 de D2: todas las escrituras (denies → portadoras → membresías → allows) y luego toda la poda. */
const closure1: OrderFn = ({ writes, deletes, context }) => {
  const carriers = denyCarrierGroups([...context, ...writes, ...deletes])
  const w = (v: RelationOrderView) => (v.deny ? 0 : isMembership(v) ? (carriers.has(v.object) ? 1 : 2) : 3)
  const d = (v: RelationOrderView) => (v.deny ? 3 : isMembership(v) ? (carriers.has(v.object) ? 2 : 1) : 0)
  return {
    steps: [
      ...[...writes].sort((a, b) => w(a) - w(b) || by(a, b)).map((item) => ({ item, op: 'write' as const })),
      ...[...deletes].sort((a, b) => d(a) - d(b) || by(a, b)).map((item) => ({ item, op: 'delete' as const })),
    ],
    residue: [],
  }
}

/** El CANDIDATO del brief: denies → allows sobrantes → membresías nuevas → membresías sobrantes → allows → denies sobrantes. */
const briefCandidate: OrderFn = ({ writes, deletes, context }) => {
  const carriers = denyCarrierGroups([...context, ...writes, ...deletes])
  const rank = (v: RelationOrderView, op: 'write' | 'delete') =>
    op === 'write'
      ? v.deny ? 0 : isMembership(v) ? (carriers.has(v.object) ? 2 : 2.5) : 4
      : v.deny ? 5 : isMembership(v) ? (carriers.has(v.object) ? 3.5 : 3) : 1
  const steps = [...writes.map((item) => ({ item, op: 'write' as const })), ...deletes.map((item) => ({ item, op: 'delete' as const }))]
  return { steps: steps.sort((a, b) => rank(a.item, a.op) - rank(b.item, b.op) || by(a.item, b.item)), residue: [] }
}

test.group('relations · orden de transición · demostración por fuerza bruta (cierre 2 de D2 · 🟡 N3, L10)', () => {
  test('el oráculo rápido decide lo MISMO que cutPathAllows del paquete en las 1 024 máscaras de E1', ({ assert }) => {
    const views = universe('E1')
    const fast = oracle(views)
    const pkg = oracle(views, { package: true })
    assert.deepEqual([...fast.granted], [...pkg.granted])
    assert.deepEqual([...fast.denied], [...pkg.denied])
  })

  test('E1 EXHAUSTIVO (10 tuplas · 4^10 pares × {--prune, sin --prune} = 2 097 152): sin residuo, ningún prefijo concede; cifras fijadas', ({ assert }) => {
    const r = bruteForce('E1', packageOrder(ORDER_CUTS))
    console.log(`  E1 exhaustivo: ${JSON.stringify({ ...r, examples: undefined })}\n  ${r.examples.join('\n  ')}`)
    assert.equal(r.pairs, 2_097_152)
    assert.equal(r.malformed, 0, 'el orden es una permutación del diff y llega al final')
    assert.equal(r.unsafeWithoutResidue, 0, `ROJO (L10): un par SIN residuo concede en un prefijo — ${r.examples.join(' ;; ')}`)
    assert.deepEqual(
      { residuePairs: r.residuePairs, unsafe: r.unsafe, inherent: r.inherent },
      // Cierre 5 de D2: el oráculo cuenta los objetos `group:` y C3/C4 cambian (antes 4 560 / 828 / 352).
      { residuePairs: 4176, unsafe: 816, inherent: 352 },
      'cifras del residuo (re-mídelas y reescribe README/CHANGELOG/informe si el orden cambia)'
    )
  }).timeout(180_000)

  test('U2 (el universo del brief: 2 usuarios, 2 grupos con 1 nivel, 2 objetos, allows y denies directos y por grupo; 21 tuplas) · MUESTRA de 30 000 pares por modo: sin residuo, ningún prefijo concede', ({ assert }) => {
    const r = bruteForce('U2', packageOrder(ORDER_CUTS), { sample: 30_000 })
    console.log(`  U2 muestra: ${JSON.stringify({ ...r, examples: undefined })}`)
    assert.equal(r.malformed, 0)
    assert.equal(r.unsafeWithoutResidue, 0, `ROJO (L10): ${r.examples.join(' ;; ')}`)
    assert.deepEqual({ residuePairs: r.residuePairs, unsafe: r.unsafe, inherent: r.inherent }, { residuePairs: 209, unsafe: 17, inherent: 0 })
  }).timeout(180_000)

  test('E3 (3 grupos con DOS niveles de anidamiento, 20 tuplas) · MUESTRA de 30 000 pares por modo: sin residuo, ningún prefijo concede', ({ assert }) => {
    const r = bruteForce('E3', packageOrder(ORDER_CUTS), { sample: 30_000 })
    console.log(`  E3 muestra: ${JSON.stringify({ ...r, examples: undefined })}`)
    assert.equal(r.malformed, 0)
    assert.equal(r.unsafeWithoutResidue, 0, `ROJO (L10): ${r.examples.join(' ;; ')}`)
    assert.deepEqual({ residuePairs: r.residuePairs, unsafe: r.unsafe, inherent: r.inherent }, { residuePairs: 4188, unsafe: 155, inherent: 0 })
  }).timeout(180_000)

  test('SIN la config del destino (sin el predicado del auto-corte) el orden sigue siendo SEGURO fuera del residuo — solo es más conservador (E1-reduced exhaustivo)', ({ assert }) => {
    const r = bruteForce('E1-reduced', packageOrder(undefined))
    assert.equal(r.malformed, 0)
    assert.equal(r.unsafeWithoutResidue, 0, `ROJO (L10): ${r.examples.join(' ;; ')}`)
    const withCuts = bruteForce('E1-reduced', packageOrder(ORDER_CUTS))
    assert.isAbove(r.residuePairs, withCuts.residuePairs, 'sin el auto-corte hay MÁS residuo (más precedencias), nunca menos garantía')
  }).timeout(60_000)

  test('DESCARTADOS: el orden del cierre 1 (escrituras y luego poda) y el candidato del brief conceden SIN residuo — cada uno con su contraejemplo', ({ assert }) => {
    const c1 = bruteForce('E1-reduced', closure1, { maxExamples: 1 })
    const brief = bruteForce('E1-reduced', briefCandidate, { maxExamples: 1 })
    console.log(`  cierre 1: ${c1.unsafeWithoutResidue} pares · ${c1.examples[0]}\n  candidato del brief: ${brief.unsafeWithoutResidue} pares · ${brief.examples[0]}`)
    assert.isAbove(c1.unsafeWithoutResidue, 0, 'el orden del cierre 1 concede (🟡 N3: el ex-miembro compone con el allow nuevo)')
    assert.isAbove(brief.unsafeWithoutResidue, 0, 'el candidato del brief concede (composición ANIDADA: U ∈ h nuevo y h ⊂ g sobrante)')
    // Los contraejemplos, literales (los del informe): C2 del auditor (🟡 N3) descarta el cierre 1; la composición ANIDADA
    // descarta el candidato del brief; el orden del paquete pasa los dos.
    const c2 = [pick('E1-reduced', 'g@u1'), pick('E1-reduced', 'x@g#member')] as const
    assert.equal(walkPair('E1-reduced', closure1, ...c2).bad, 1, 'C2: U ∈ g sobra, g#member viewer X es nuevo, --prune ⇒ concede tras la 1.ª escritura')
    assert.isNull(walkPair('E1-reduced', packageOrder(ORDER_CUTS), ...c2).bad)
    const nested = [pick('E1-reduced', 'g@h#member', 'x@g#member'), pick('E1-reduced', 'h@u1', 'x@g#member')] as const
    assert.equal(walkPair('E1-reduced', briefCandidate, ...nested).bad, 1, 'anidada: U ∈ h nuevo antes de borrar h ⊂ g ⇒ U alcanza el allow de g')
    assert.isNull(walkPair('E1-reduced', packageOrder(ORDER_CUTS), ...nested).bad)
    // 🟡 N2 (el otro grupo solo transporta un deny): el orden del cierre 1 concedía; el del paquete no.
    const n2 = [pick('E1-reduced', 'x@g#member', '¬y@g#member', '¬x@h#member'), pick('E1-reduced', 'g@u1', 'h@u1', 'x@g#member', '¬y@g#member', '¬x@h#member')] as const
    assert.equal(walkPair('E1-reduced', closure1, ...n2).bad, 1, 'N2: la portadora de g (mixto) va antes que la de h (solo deny)')
    assert.isNull(walkPair('E1-reduced', packageOrder(ORDER_CUTS), ...n2).bad)
  }).timeout(60_000)

  test('cierre 5 de D2 · contraejemplos LITERALES (tester del panel «óptimo»): C4 en U2, la membresía como concesión (C3, D4-2) y la renovación que ACORTA como arista que cambia (E3, con vigencia) — el orden del paquete no concede en ninguno', ({ assert }) => {
    // C4 (U2, --prune): U2 sale de g —que le niega Y— y entra en h —que también—. Sin C4 (`order.c4.off`) sale antes y
    // concede Y tras el 2.º paso (hasta aquí solo moría por cifras).
    const c4 = walkPair('U2', packageOrder(ORDER_CUTS), pick('U2', 'g@u2', 'g@h#member', 'y@u2', 'x@g#member', '¬y@g#member'), pick('U2', 'h@u2', 'y@u2', 'x@g#member', '¬y@h#member'))
    assert.isNull(c4.bad, c4.steps.join(' '))
    // C3 cuenta la membresía (D4-2): +U∈h antes de -h⊂g hacía a U miembro de g, que ni el inicial ni el final.
    const c3 = walkPair('E1-reduced', packageOrder(ORDER_CUTS), pick('E1-reduced', 'g@h#member'), pick('E1-reduced', 'h@u1'))
    assert.isNull(c3.bad, c3.steps.join(' '))
    // E3, 8 tuplas, --prune, atómico: la renovación que ACORTA `b ⊂ c` cuenta como arista que cambia (sin eso,
    // `c4h.order.renewals-not-changing`, concede tras el 3.er paso en el horizonte).
    const e3 = walkVigencia(
      'E3',
      packageOrder(ORDER_CUTS),
      ['a@u1:absent/same', 'b@u1:live/absent', 'b@a#member:live/absent', 'c@b#member:live/shorter', 'x@b#member:live/same', 'y@c#member:live/same', '¬y@b#member:absent/same', '¬x@c#member:live/same'],
      { prune: true, atomic: true }
    )
    assert.isTrue(e3.bad === null && !e3.finalBad, e3.steps.join(' '))
  })

  test('el RESIDUO es real: el cruce de dos grupos (cada uno deniega lo que el otro concede) no admite NINGÚN orden seguro', ({ assert }) => {
    const r = bruteForce('E1-reduced', packageOrder(ORDER_CUTS), { maxExamples: 1 })
    assert.isAbove(r.inherent, 0)
    assert.match(r.examples[0], /sin orden seguro/)
    assert.include(r.examples[0], 'residuo [')
    assert.notInclude(r.examples[0], 'residuo []')
    console.log(`  residuo inherente: ${r.examples[0]}`)
  }).timeout(60_000)
})

/**
 * **Cierre 3 de D2 · 🟡 C2-2 → cierre 4 · 🟡 HORIZONTE: la VIGENCIA en el universo.** La garantía del orden suponía que
 * toda tupla del destino estaba VIVA (cierre 3) y que bastaba con mirar `now` (cierre 4: el 🟠 C3-1 del auditor — una
 * portadora `renewal-unsafe` con su caducidad VIEJA dejaba, al vencer, una concesión diferida que `now` no ve). Ahora cada
 * tupla está en uno de OCHO estados (destino ausente/vencida/viva × origen ausente/misma/más larga/más corta), el plan se
 * deriva con `liveInDestination` y `denyCarrierGroups` (los mismos puntos de paso que `planPartition`), un deny del
 * destino con caducidad que el destino no puede rehacer es `deny-conditional` (🟡 C3-2) y, desde el cierre 5 (opción A),
 * una partición con `renewal-unsafe` o `deny-conditional` se NIEGA (cero escrituras: la única exclusión del oráculo); el
 * oráculo mira la vigencia en CADA instante del horizonte (`now`, `+30 min`, `+1 h`) y los objetos `group:`. Muestras con semilla 20261016 y cifras fijadas POR MODO; el
 * exhaustivo de E1-reduced (8^8 × 2 = 33 554 432 combinaciones por destino) se corre con
 * `AUTHZ_ORDER_VIGENCIA_EXHAUSTIVE=1`.
 */
type VigFixed = { residuePairs: number; unsafe: number; inherent: number; renewalUnsafe: number; denyConditional: number; refused: number }
test.group('relations · orden de transición · fuerza bruta con VIGENCIA y HORIZONTE (cierres 3 y 4 de D2)', () => {
  const FIXED: Record<string, { sample: number; atomic: VigFixed; twoWrites: VigFixed }> = {
    'E1-reduced': {
      sample: 300_000,
      atomic: { residuePairs: 15_140, unsafe: 1857, inherent: 454, renewalUnsafe: 0, denyConditional: 0, refused: 0 },
      twoWrites: { residuePairs: 1133, unsafe: 273, inherent: 108, renewalUnsafe: 358_414, denyConditional: 449_968, refused: 458_369 },
    },
    E1: {
      sample: 300_000,
      atomic: { residuePairs: 3731, unsafe: 448, inherent: 110, renewalUnsafe: 0, denyConditional: 0, refused: 0 },
      twoWrites: { residuePairs: 284, unsafe: 52, inherent: 18, renewalUnsafe: 420_257, denyConditional: 674_688, refused: 525_780 },
    },
    U2: {
      sample: 30_000,
      atomic: { residuePairs: 751, unsafe: 28, inherent: 0, renewalUnsafe: 0, denyConditional: 0, refused: 0 },
      twoWrites: { residuePairs: 2, unsafe: 0, inherent: 0, renewalUnsafe: 71_536, denyConditional: 180_012, refused: 59_573 },
    },
    E3: {
      sample: 30_000,
      atomic: { residuePairs: 11_022, unsafe: 326, inherent: 2, renewalUnsafe: 0, denyConditional: 0, refused: 0 },
      twoWrites: { residuePairs: 53, unsafe: 5, inherent: 0, renewalUnsafe: 86_613, denyConditional: 134_671, refused: 59_178 },
    },
  }
  const pickFixed = (r: any): VigFixed => ({
    residuePairs: r.residuePairs,
    unsafe: r.unsafe,
    inherent: r.inherent,
    renewalUnsafe: r.renewalUnsafe,
    denyConditional: r.denyConditional,
    refused: r.refused,
  })
  for (const [name, fixed] of Object.entries(FIXED)) {
    for (const atomic of [true, false]) {
      test(`${name} · MUESTRA de ${fixed.sample} combinaciones por modo · destino ${atomic ? 'ATÓMICO (database)' : 'de DOS Write (openfga)'}: en ningún instante del horizonte un prefijo concede sin residuo, el estado FINAL no concede lo que el origen niega (sin excepción: la partición con renewal-unsafe/deny-conditional se NIEGA, cierre 5) y el estado alcanzado es el final`, ({ assert }) => {
        const r = bruteForceVigencia(name as any, packageOrder(ORDER_CUTS), { atomic, sample: fixed.sample })
        console.log(`  vigencia ${name} ${atomic ? 'atómico' : 'dos Write'}: ${JSON.stringify({ ...r, examples: undefined })}`)
        assert.equal(r.malformed, 0, `el estado alcanzado no es el final — ${r.examples.join(' ;; ')}`)
        assert.equal(r.unsafeWithoutResidue, 0, `ROJO (C2-2 / C3-1 / C3-2): concede sin residuo — ${r.examples.join(' ;; ')}`)
        assert.isAbove(r.withExpired, fixed.sample, 'el universo TIENE vencidas (si no, no demuestra nada)')
        assert.isAbove(r.renewals, 0, 'y renovaciones ejecutadas')
        assert.deepEqual(pickFixed(r), atomic ? fixed.atomic : fixed.twoWrites, 'cifras fijadas (re-mídelas y reescribe README/CHANGELOG/informe si el orden o el plan cambian)')
      }).timeout(180_000)
    }
  }

  test('cierre 4 → cierre 5 (opción A) · los contraejemplos del auditor: C3-1 (portadora viva que vence ANTES que en el origen) y C3-2 (deny condicional vencido) — SIN negar la partición, el estado FINAL concede en el horizonte; negándola, no', ({ assert }) => {
    // Sin negar la partición (aplicar todo menos la renovación y el deny que no viajan): el horizonte se pone rojo.
    const none = bruteForceVigencia('E1-reduced', packageOrder(ORDER_CUTS), { atomic: false, sample: 50_000, maxExamples: 3, refuse: false })
    assert.isAbove(none.unsafeWithoutResidue, 0, 'sin negar la partición, el horizonte concede (C3-1 / C3-2)')
    assert.isTrue(none.examples.some((e) => e.includes('estado FINAL en el horizonte')), none.examples.join(' ;; '))
    // Sin el orden de las renovaciones en el horizonte (cierre 4): un destino atómico también concede en un prefijo.
    const flat: OrderFn = (t) => packageOrder(ORDER_CUTS)({ ...t, renewals: [], shortening: [] })
    const flatOrder: OrderFn = (t) => {
      const plan = flat(t)
      return { steps: [...plan.steps, ...(t.renewals ?? []).map((item) => ({ item, op: 'renew' as const }))], residue: plan.residue }
    }
    const atomicFlat = bruteForceVigencia('E1-reduced', flatOrder, { atomic: true, sample: 50_000 })
    assert.isAbove(atomicFlat.unsafeWithoutResidue, 0, 'renovaciones al final (como hasta el cierre 3): un prefijo concede en el horizonte')
  }).timeout(120_000)

  test('E1-reduced EXHAUSTIVO con vigencia y horizonte (8^8 × {--prune, sin} = 33 554 432 por destino): 0 sin residuo · solo con AUTHZ_ORDER_VIGENCIA_EXHAUSTIVE=1 (~10 min)', ({ assert }) => {
    for (const atomic of [true, false]) {
      const r = bruteForceVigencia('E1-reduced', packageOrder(ORDER_CUTS), { atomic })
      console.log(`  vigencia E1-reduced EXHAUSTIVO ${atomic ? 'atómico' : 'dos Write'}: ${JSON.stringify({ ...r, examples: undefined })}`)
      assert.equal(r.pairs, 33_554_432)
      assert.equal(r.malformed, 0)
      assert.equal(r.unsafeWithoutResidue, 0, `ROJO (C2-2 / C3-1 / C3-2): ${r.examples.join(' ;; ')}`)
      assert.deepEqual(pickFixed(r), atomic ? EXHAUSTIVE.atomic : EXHAUSTIVE.twoWrites)
    }
  })
    .skip(process.env.AUTHZ_ORDER_VIGENCIA_EXHAUSTIVE !== '1', 'exhaustivo largo: AUTHZ_ORDER_VIGENCIA_EXHAUSTIVE=1')
    .timeout(1_800_000)
})

/** Las cifras del exhaustivo (re-medidas en el cierre 5 de D2: partición negada, oráculo con `group:`, C3/C4). */
const EXHAUSTIVE: { atomic: VigFixed; twoWrites: VigFixed } = {
  atomic: { residuePairs: 836_352, unsafe: 100_512, inherent: 26_496, renewalUnsafe: 0, denyConditional: 0, refused: 0 },
  twoWrites: { residuePairs: 63_432, unsafe: 14_400, inherent: 5976, renewalUnsafe: 20_054_016, denyConditional: 25_165_824, refused: 25_632_768 },
}
