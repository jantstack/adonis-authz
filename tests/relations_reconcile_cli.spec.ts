/**
 * El comando `authz:relations:reconcile` (Fase 4, lote 4-6) — su única DECISIÓN
 * es qué imprime y si la pasada es limpia, y eso vive en la función PURA
 * `relationsReconcileLines` (el patrón de `reconcileLines` de roles). Aquí se
 * juzga sin montar un ace.
 */
import { test } from '@japa/runner'
import { relationsReconcileLines } from '../commands/authz_relations_reconcile.js'
import type { RelationsReconcileReport } from '../src/relations/reconcile.js'

function report(over: Partial<RelationsReconcileReport> = {}): RelationsReconcileReport {
  return {
    dryRun: false,
    written: 0,
    updated: 0,
    deleted: 0,
    unchanged: 0,
    extra: 0,
    modelDrift: [],
    massDelete: false,
    allowMassDelete: false,
    skipped: { expired: 0, undeclared: 0 },
    ...over,
  }
}

test.group('authz:relations:reconcile — relationsReconcileLines', () => {
  test('L-0 · skipped.undeclared SIEMPRE es deriva (exit ≠ 0) y se dice con su motivo, en dry-run y fuera', ({ assert }) => {
    // Una tupla del origen que el destino NO declara (tipo o relación) no se
    // escribe y se cuenta: no es una pérdida declarada como `expired` (que no
    // concede nada), es una relación VIVA que no llegó. Exit ≠ 0.
    const dry = relationsReconcileLines(report({ dryRun: true, skipped: { expired: 0, undeclared: 2 } }))
    assert.isFalse(dry.clean)
    assert.isTrue(dry.lines.some((l) => l.level === 'error' && l.message.includes('2 tupla(s)') && l.message.includes('skipped.undeclared')))
    const live = relationsReconcileLines(report({ written: 3, skipped: { expired: 0, undeclared: 1 } }))
    assert.isFalse(live.clean)
    assert.isTrue(live.lines.some((l) => l.level === 'error' && l.message.includes('skipped.undeclared')))
  })

  /**
   * **F-R2 (plan 2.5 · lote A; linaje L8, letra ≠ efecto)** — tabla de verdad
   * massDelete × allowMassDelete × dryRun. Observado en el lote R (R-8): con
   * `--allow-mass-delete` la pasada VACIABA el destino y la letra seguía diciendo
   * «borraría … En una pasada real es 500» con exit 1.
   */
  test('F-R2 · massDelete × allowMassDelete × dryRun: levantado y real ⇒ «se LEVANTÓ … se han borrado N» (warning, LIMPIA, exit 0); levantado y dry-run ⇒ «la pasada real las BORRARÁ» (deriva); sin levantar ⇒ el error «En una pasada real es 500»', ({ assert }) => {
    const rows: Array<{ massDelete: boolean; allow: boolean; dryRun: boolean; expect: RegExp | null; level: string | null; clean: boolean }> = [
      { massDelete: true, allow: true, dryRun: false, expect: /se LEVANTÓ con --allow-mass-delete: se han borrado 3 tupla\(s\)/, level: 'warning', clean: true },
      { massDelete: true, allow: true, dryRun: true, expect: /borraría 3 tupla\(s\).*la pasada real las BORRARÁ/, level: 'warning', clean: false },
      { massDelete: true, allow: false, dryRun: false, expect: /En una pasada real es 500 E_AUTHZ_MASS_RECONCILE_REFUSED/, level: 'error', clean: false },
      { massDelete: true, allow: false, dryRun: true, expect: /En una pasada real es 500 E_AUTHZ_MASS_RECONCILE_REFUSED/, level: 'error', clean: false },
      { massDelete: false, allow: true, dryRun: false, expect: null, level: null, clean: true },
      { massDelete: false, allow: false, dryRun: true, expect: null, level: null, clean: false },
    ]
    for (const row of rows) {
      const label = `massDelete=${row.massDelete} allow=${row.allow} dryRun=${row.dryRun}`
      const { lines, clean } = relationsReconcileLines(report({ massDelete: row.massDelete, allowMassDelete: row.allow, dryRun: row.dryRun, deleted: row.dryRun ? 0 : 3, extra: row.dryRun ? 3 : 0 }))
      const mass = lines.filter((l) => /allow-mass-delete/.test(l.message))
      if (row.expect === null) assert.lengthOf(mass, 0, `${label}: sin línea del seguro`)
      else {
        assert.lengthOf(mass, 1, `${label}: una línea del seguro — ${lines.map((l) => l.message).join(' | ')}`)
        assert.match(mass[0].message, row.expect, label)
        assert.equal(mass[0].level, row.level, label)
      }
      assert.equal(clean, row.clean, `${label}: clean`)
    }
  })

  test('una pasada sin deriva es LIMPIA y resume los contadores', ({ assert }) => {
    const { lines, clean } = relationsReconcileLines(report({ written: 3, unchanged: 2 }))
    assert.isTrue(clean)
    assert.isTrue(lines.some((l) => l.message.includes('escritas 3')))
    assert.isEmpty(lines.filter((l) => l.level === 'error'))
  })

  test('modelDrift SIEMPRE es deriva (exit ≠ 0), en dry-run y fuera', ({ assert }) => {
    const dry = relationsReconcileLines(report({ dryRun: true, modelDrift: ['space'] }))
    assert.isFalse(dry.clean)
    assert.isTrue(dry.lines.some((l) => l.level === 'error' && l.message.includes("'space'")))
    // Un tipo del origen que el destino no declara NO cabe en su modelo
    // fusionado: es deriva aunque no hubiera nada que escribir.
    const live = relationsReconcileLines(report({ modelDrift: ['key'] }))
    assert.isFalse(live.clean)
  })

  test('--dry-run: cualquier cosa que HARÍA (escribir/borrar/sobrar) es deriva; sin cambios, limpia', ({ assert }) => {
    assert.isFalse(relationsReconcileLines(report({ dryRun: true, written: 1 })).clean)
    assert.isFalse(relationsReconcileLines(report({ dryRun: true, deleted: 1 })).clean)
    assert.isFalse(relationsReconcileLines(report({ dryRun: true, extra: 1 })).clean)
    // R-15: una caducidad distinta en el destino es una reescritura que HARÍA ⇒ deriva.
    assert.isFalse(relationsReconcileLines(report({ dryRun: true, updated: 1 })).clean)
    // …y la caducada del origen es pérdida DECLARADA, no deriva (se dice, exit 0).
    const expired = relationsReconcileLines(report({ dryRun: true, skipped: { expired: 2, undeclared: 0 } }))
    assert.isTrue(expired.clean)
    assert.isTrue(expired.lines.some((l) => l.message.includes('2 tupla(s) del origen estaban CADUCADAS')))
    assert.isTrue(relationsReconcileLines(report({ dryRun: true, unchanged: 5 })).clean)
  })

  test('en una pasada que escribe, `extra` sin --prune AVISA pero no tumba', ({ assert }) => {
    const { lines, clean } = relationsReconcileLines(report({ written: 2, extra: 1 }))
    assert.isTrue(clean) // el operador eligió no podar
    assert.isTrue(lines.some((l) => l.level === 'warning' && l.message.includes('--prune')))
  })

  /**
   * **Cierre 2 del lote B · 🟡 N3 — la línea «no pasaste --prune: repite con --prune»** solo cuando NO se pasó
   * `--prune` Y hay `extra` que `--prune` borra DE VERDAD (lo que sobra menos el residuo del destino que nadie
   * borra). Hasta el cierre 2 salía con `extra > 0` a secas: con `--prune` real y un residuo (la vuelta del runbook)
   * decía «no pasaste --prune» justo debajo de «--prune NO lo borra», y sin `--prune` el consejo era falso porque
   * `--prune` tampoco lo quitaría. El reporte lleva `prune` (opcional: un reporte de terceros sin él = no pasado).
   */
  test('🟡 N3 · «no pasaste --prune: repite con --prune» × {prune} × {extra con/sin residuo}: solo sin --prune y con extra que --prune borra; con prune: true nunca; con solo residuo (invalid-identity o userset-unsupported) nunca; con 2 extra y 1 residuo dice «1 tupla(s)»', ({ assert }) => {
    const tuple = 'unit|0192f000-0000-7000-8000-000000000001 document:ABC#viewer@user:0192f000-0000-7000-8000-00000000a11c'
    const advice = (r: ReturnType<typeof report>) => relationsReconcileLines(r).lines.filter((l) => /no pasaste --prune/.test(l.message))
    assert.lengthOf(advice(report({ written: 1, extra: 1 })), 1, 'sin prune (ausente) y extra podable ⇒ el consejo')
    assert.lengthOf(advice(report({ written: 1, extra: 1, prune: false })), 1, 'prune: false ⇒ el consejo')
    assert.lengthOf(advice(report({ written: 1, extra: 1, prune: true })), 0, 'ROJO (N3): con --prune pasado el consejo contradice')
    for (const reason of ['invalid-identity', 'userset-unsupported', 'undeclared'] as const) {
      const residueOnly = report({ written: 1, extra: 1, details: [{ side: 'destino', reason, tuple, message: 'x' }] })
      assert.lengthOf(advice(residueOnly), 0, `ROJO (N3): ${reason} sin prune — --prune tampoco lo quitaría`)
      const pruned = report({ written: 1, extra: 1, prune: true, details: [{ side: 'destino', reason, tuple, message: 'x', pruned: false }] })
      assert.lengthOf(advice(pruned), 0, `ROJO (N3): ${reason} con prune real`)
      const mixed = advice(report({ written: 1, extra: 2, details: [{ side: 'destino', reason, tuple, message: 'x' }] }))
      assert.lengthOf(mixed, 1, `${reason}: queda 1 extra que --prune sí borra`)
      assert.match(mixed[0].message, /^1 tupla\(s\) del destino/, `${reason}: cuenta solo lo podable`)
    }
    // Un residuo del ORIGEN no descuenta nada del destino.
    assert.lengthOf(advice(report({ written: 1, extra: 1, details: [{ side: 'origen', reason: 'invalid-identity', tuple, message: 'x' }] })), 1)
  })

  /**
   * **⚪ R2 (cierre-2 del lote A; linaje L8)**: lo enumerado fuera de la
   * gramática se LISTA, una línea por tupla, con el lado, el motivo y el porqué;
   * la letra dice lo que la pasada hizo o hará, y el que el driver del destino
   * la rechace por el puerto es un error (sigue ahí) y no un 422 que tumbe.
   */
  /**
   * **Cierre 2 del lote B · 🟡 N3 (UNIFICACIÓN)**: la letra de `invalid-identity` del DESTINO pasa a ser la MISMA que
   * la de `userset-unsupported` —un residuo que ningún driver del paquete borra—: `error` con el prefijo ESTABLE
   * «sobra (invalid-identity) destino:», exit ≠ 0 en los CUATRO modos (hasta el cierre 2 sin `--prune` era un
   * warning con exit 0 y el consejo falso «repite con --prune»), «--prune NO la borra» con `pruned: false` (dry y
   * real) y «tampoco la borraría» sin prune, receta «a mano (SQL/SDK)», jamás «se pedirá … BORRE»/«BORRADA»/«NO se
   * pudo borrar» (la pasada ya no se la pide al driver). El origen no cambia. Tabla de verdad ejecutada aquí y en
   * `relations_reconcile.spec.ts` (🟡 N3, con el plan).
   */
  test('🟡 N3 · details (invalid-identity) destino × prune × dryRun ⇒ SIEMPRE error «sobra (invalid-identity) destino: …», no limpia (exit ≠ 0) en los cuatro modos, «--prune NO la borra» con pruned: false y «tampoco la borraría» sin prune, «a mano (SQL/SDK)», jamás «repite con --prune»; origen ⇒ error (deriva, a mano); skipped.invalid ⇒ no limpia', ({ assert }) => {
    const tuple = 'unit|0192f000-0000-7000-8000-000000000001 document:ABC#viewer@user:0192f000-0000-7000-8000-00000000a11c'
    const message = "el id del objeto 'document' inválido: 'ABC'"
    const origin = relationsReconcileLines(report({ written: 1, skipped: { expired: 0, undeclared: 0, invalid: 1 }, details: [{ side: 'origen', reason: 'invalid-identity', tuple, message }] }))
    assert.isFalse(origin.clean, 'origen: deriva')
    const o = origin.lines.find((l) => l.message.includes('(invalid-identity) origen'))
    assert.equal(o?.level, 'error')
    assert.match(o!.message, /^sin migrar \(invalid-identity\) origen: .*ABC.*a mano/)

    const rows: Array<[string, Partial<RelationsReconcileReport>, RegExp]> = [
      ['destino sin prune, real', { unchanged: 1, extra: 1, prune: false, details: [{ side: 'destino', reason: 'invalid-identity', tuple, message }] }, /tampoco la borraría/],
      ['destino sin prune, dry-run', { dryRun: true, unchanged: 1, extra: 1, prune: false, details: [{ side: 'destino', reason: 'invalid-identity', tuple, message }] }, /tampoco la borraría/],
      ['destino con prune, real', { unchanged: 1, extra: 1, prune: true, details: [{ side: 'destino', reason: 'invalid-identity', tuple, message, pruned: false }] }, /--prune NO la borra/],
      ['destino con prune, dry-run', { dryRun: true, unchanged: 1, extra: 1, prune: true, details: [{ side: 'destino', reason: 'invalid-identity', tuple, message, pruned: false }] }, /--prune NO la borra/],
    ]
    for (const [label, over, expected] of rows) {
      const { lines, clean } = relationsReconcileLines(report(over))
      assert.isFalse(clean, `ROJO (N3) ${label}: un residuo que nadie borra es deriva (exit ≠ 0)`)
      const line = lines.find((l) => /\(invalid-identity\) destino/.test(l.message))
      assert.equal(line?.level, 'error', `ROJO (N3) ${label}: era warning/log`)
      assert.match(line!.message, /^sobra \(invalid-identity\) destino: /, `${label}: prefijo estable de la rama`)
      assert.match(line!.message, expected, label)
      assert.match(line!.message, /ningún driver del paquete .*R-16/, `${label}: el porqué`)
      assert.match(line!.message, /a mano \(SQL\/SDK\)/, `${label}: la receta`)
      assert.isTrue(lines.every((l) => !/no pasaste --prune|repite con --prune/.test(l.message)), `${label}: jamás «repite con --prune»`)
      assert.isTrue(lines.every((l) => !/se pedirá|BORRADA|NO se pudo borrar/.test(l.message)), `${label}: la pasada no se la pide a nadie`)
      assert.isTrue(lines.every((l) => !/422/.test(l.message)), `${label}: nunca se vende como 422 del llamante`)
    }
    // Un reporte de terceros anterior (sin `details` ni `skipped.invalid`) sigue limpio.
    assert.isTrue(relationsReconcileLines(report({ unchanged: 3 })).clean)
  })

  /**
   * **Cierre 3 del lote B · 🟠 N9 — la letra del tercer motivo, `undeclared`**: la fila del DESTINO cuya relación (o
   * tipo) el destino YA NO declara — `unrelate` la rechaza por F-05 (422 `E_AUTHZ_RELATION_UNKNOWN` /
   * `E_AUTHZ_RELATION_TYPE_UNKNOWN`), así que es la tercera fila que «la API no admite» y lleva la MISMA regla que las
   * otras dos (N3): `error` con el prefijo ESTABLE «sobra (undeclared) destino:», deriva en los CUATRO modos, «--prune
   * NO la borra» (`pruned: false`) / «tampoco la borraría», receta «retírala a mano o vuelve a declarar la relación»,
   * jamás «repite con --prune», jamás un 422 vendido como del llamante. Hasta el cierre 3 ese 422 salía como stack
   * crudo a mitad de pasada (después de escribir) y la frase del README «one rule for every destination row the API
   * does not admit» era falsa.
   */
  test('🟠 N9 · details (undeclared) destino × prune × dryRun ⇒ SIEMPRE error «sobra (undeclared) destino: …», no limpia en los cuatro modos, «--prune NO la borra» con pruned: false y «tampoco la borraría» sin prune, receta «a mano … o vuelve a declarar», jamás «repite con --prune» ni 422', ({ assert }) => {
    const tuple = 'unit|0192f000-0000-7000-8000-000000000001 document:0192f000-0000-7000-8000-00000000d0c1#publisher@user:0192f000-0000-7000-8000-00000000a11c'
    const message = "La relación 'publisher' no está declarada para el tipo 'document' en defineRelationsConfig (F-05)."
    const rows: Array<[string, Partial<RelationsReconcileReport>, RegExp]> = [
      ['destino sin prune, real', { unchanged: 1, extra: 1, prune: false, details: [{ side: 'destino', reason: 'undeclared', tuple, message }] }, /tampoco la borraría/],
      ['destino sin prune, dry-run', { dryRun: true, unchanged: 1, extra: 1, prune: false, details: [{ side: 'destino', reason: 'undeclared', tuple, message }] }, /tampoco la borraría/],
      ['destino con prune, real', { unchanged: 1, extra: 1, prune: true, details: [{ side: 'destino', reason: 'undeclared', tuple, message, pruned: false }] }, /--prune NO la borra/],
      ['destino con prune, dry-run', { dryRun: true, unchanged: 1, extra: 1, prune: true, details: [{ side: 'destino', reason: 'undeclared', tuple, message, pruned: false }] }, /--prune NO la borra/],
    ]
    for (const [label, over, expected] of rows) {
      const { lines, clean } = relationsReconcileLines(report(over))
      assert.isFalse(clean, `ROJO (N9) ${label}: un residuo que nadie borra es deriva (exit ≠ 0)`)
      const line = lines.find((l) => /\(undeclared\) destino/.test(l.message))
      assert.equal(line?.level, 'error', `ROJO (N9) ${label}: sin línea propia`)
      assert.match(line!.message, /^sobra \(undeclared\) destino: /, `${label}: prefijo estable de la rama`)
      assert.match(line!.message, expected, label)
      assert.include(line!.message, message, `${label}: el porqué (F-05)`)
      assert.match(line!.message, /F-05/, `${label}: nombra la regla`)
      assert.match(line!.message, /a mano/, `${label}: la receta (1)`)
      assert.match(line!.message, /vuelve a declarar/, `${label}: la receta (2)`)
      assert.isTrue(lines.every((l) => !/no pasaste --prune|repite con --prune/.test(l.message)), `${label}: jamás «repite con --prune»`)
      assert.isTrue(lines.every((l) => !/decláralos en el destino/.test(l.message)), `${label}: el consejo de skipped.undeclared (del ORIGEN) no es éste`)
      assert.isTrue(lines.every((l) => !/422/.test(l.message)), `${label}: nunca se vende como 422 del llamante`)
    }
  })

  /**
   * **Cierre 1 del lote B · 🟠 1/🟠 2 — la letra del residuo pre-2.5 de B3** (`reason: 'userset-unsupported'`):
   * deriva en los DOS lados y en los CUATRO modos (prune × dry-run) — ninguna bandera lo toca (nunca un DELETE de
   * plataforma), así que la única salida es la receta SQL, y la línea la LLEVA (nombra el residuo, el lado y la
   * receta); `skipped.usersetUnsupported` ⇒ no limpia; el consejo falso de `undeclared` («decláralos en el
   * destino») no aparece; y la receta de la línea es la MISMA que publica el README (⚪ 12 la ejecuta).
   */
  test('🟠 1/🟠 2 · details (userset-unsupported) × lado × prune × dryRun: SIEMPRE error con lado, residuo y receta, nunca limpia; con prune el destino dice «--prune NO lo borra», sin prune «tampoco lo borraría»; skipped.usersetUnsupported ⇒ no limpia; la receta es la del README', async ({ assert }) => {
    const tuple = 'unit|0192f000-0000-7000-8000-000000000001 document:0192f000-0000-7000-8000-00000000d0c1#viewer@document:0192f000-0000-7000-8000-00000000d0c2#viewer'
    const message = "El userset 'document#viewer' no vale como SUJETO de una relación (B3)"
    const { RELATION_USERSET_RESIDUE_DELETE } = await import('../src/relations/define_relations_config.js')
    const rows: Array<[string, Partial<RelationsReconcileReport>, RegExp]> = [
      ['origen', { written: 1, skipped: { expired: 0, undeclared: 0, usersetUnsupported: 1 }, details: [{ side: 'origen', reason: 'userset-unsupported', tuple, message }] }, /^sin migrar \(userset-unsupported\) origen: .*ningún --prune lo toca/],
      ['destino sin prune, real', { unchanged: 1, extra: 1, details: [{ side: 'destino', reason: 'userset-unsupported', tuple, message }] }, /^sobra \(userset-unsupported\) destino: .*--prune tampoco lo borraría/],
      ['destino sin prune, dry-run', { dryRun: true, unchanged: 1, extra: 1, details: [{ side: 'destino', reason: 'userset-unsupported', tuple, message }] }, /^sobra \(userset-unsupported\) destino: .*--prune tampoco lo borraría/],
      ['destino con prune, real', { unchanged: 1, extra: 1, details: [{ side: 'destino', reason: 'userset-unsupported', tuple, message, pruned: false }] }, /^sobra \(userset-unsupported\) destino: .*--prune NO lo borra/],
      ['destino con prune, dry-run', { dryRun: true, unchanged: 1, extra: 1, details: [{ side: 'destino', reason: 'userset-unsupported', tuple, message, pruned: false }] }, /^sobra \(userset-unsupported\) destino: .*--prune NO lo borra/],
    ]
    for (const [label, over, expected] of rows) {
      const { lines, clean } = relationsReconcileLines(report(over))
      assert.isFalse(clean, `${label}: ROJO si limpia — hay un residuo que solo se borra a mano`)
      const line = lines.find((l) => /\(userset-unsupported\)/.test(l.message))
      assert.isDefined(line, `${label}: la línea del residuo`)
      assert.equal(line!.level, 'error', label)
      assert.match(line!.message, expected, label)
      assert.include(line!.message, 'residuo pre-2.5 (B3)', `${label}: nombra lo que es`)
      assert.include(line!.message, tuple, `${label}: nombra el residuo`)
      assert.include(line!.message, RELATION_USERSET_RESIDUE_DELETE, `${label}: la receta, literal`)
      assert.isTrue(lines.every((l) => !/decláralos en el destino/.test(l.message)), `${label}: el consejo falso de undeclared no sale`)
      assert.isTrue(lines.every((l) => !/422/.test(l.message)), `${label}: nunca se vende como 422 del llamante`)
      // Cierre 2 · N3: jamás «repite con --prune» en una fila con residuo (con o sin --prune).
      assert.isTrue(lines.every((l) => !/no pasaste --prune|repite con --prune/.test(l.message)), `ROJO (N3) ${label}: el consejo contradice la línea del residuo`)
    }
    // Solo el contador (un reporte de terceros sin `details`) también deja la pasada sucia.
    assert.isFalse(relationsReconcileLines(report({ skipped: { expired: 0, undeclared: 0, usersetUnsupported: 1 } })).clean)
    // La receta de la línea es la del README (⚪ 12 la ejecuta en los tres motores).
    const { readFile } = await import('node:fs/promises')
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    assert.include(readme, RELATION_USERSET_RESIDUE_DELETE, 'el README publica la MISMA sentencia que la línea')
  })
})

test.group('authz:relations:reconcile — L-1 · J1, la ventana durable en el reporte', () => {
  test('frozen.lapsed = true ⇒ la pasada NO se certifica (error + exit ≠ 0); lapsed = false se dice y es limpia', ({ assert }) => {
    const lapsed = relationsReconcileLines(
      report({ written: 2, frozen: { durable: true, lapsed: true, leaseMs: 15_000, fence: 7 } })
    )
    assert.isFalse(lapsed.clean)
    assert.isTrue(
      lapsed.lines.some((l) => l.level === 'error' && l.message.includes('LEASE') && l.message.includes('NO se certifica') && l.message.includes('fence 7'))
    )
    const held = relationsReconcileLines(report({ written: 2, frozen: { durable: true, lapsed: false, leaseMs: null, fence: 3 } }))
    assert.isTrue(held.clean)
    assert.isTrue(held.lines.some((l) => l.level === 'log' && l.message.includes('fence 3') && l.message.includes('operador')))
    // Sin `frozen` (dry-run, o una llamada a pelo) no se afirma nada sobre la ventana.
    const dry = relationsReconcileLines(report({ dryRun: true }))
    assert.isTrue(dry.clean)
    assert.isFalse(dry.lines.some((l) => l.message.includes('fence')))
  })

  test('alpha.10 · 3 · dentro de la ventana del OPERADOR con caducidad, la línea dice CUÁNDO caduca (no «ventana del operador» a secas)', ({
    assert,
  }) => {
    const untilMs = Date.parse('2030-06-15T12:01:00.000Z')
    const conLease = relationsReconcileLines(
      report({ written: 2, frozen: { durable: true, lapsed: false, leaseMs: 50_000, fence: 4, untilMs } })
    )
    const texto = conLease.lines.map((l) => l.message).join('\n')
    assert.include(texto, 'CADUCA el 2030-06-15T12:01:00.000Z')
    assert.notInclude(texto, 'sin caducidad')
    const sinLease = relationsReconcileLines(
      report({ written: 2, frozen: { durable: true, lapsed: false, leaseMs: null, fence: 4, untilMs: null } })
    )
    assert.include(sinLease.lines.map((l) => l.message).join('\n'), 'ventana del operador sin caducidad')
  })
})
