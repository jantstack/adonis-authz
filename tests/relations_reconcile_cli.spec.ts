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
   * **⚪ R2 (cierre-2 del lote A; linaje L8)**: lo enumerado fuera de la
   * gramática se LISTA, una línea por tupla, con el lado, el motivo y el porqué;
   * la letra dice lo que la pasada hizo o hará, y el que el driver del destino
   * la rechace por el puerto es un error (sigue ahí) y no un 422 que tumbe.
   */
  test('⚪ R2 · details (invalid-identity) × lado × prune × dryRun: origen ⇒ error (deriva, a mano); destino sin prune ⇒ warning «sobra»; destino + prune dry-run ⇒ «se pedirá … BORRE»; real pruned: true ⇒ «BORRADA»; pruned: false ⇒ error «NO se pudo borrar … a mano» (no limpia); skipped.invalid ⇒ no limpia', ({ assert }) => {
    const tuple = 'unit|0192f000-0000-7000-8000-000000000001 document:ABC#viewer@user:0192f000-0000-7000-8000-00000000a11c'
    const message = "el id del objeto 'document' inválido: 'ABC'"
    const origin = relationsReconcileLines(report({ written: 1, skipped: { expired: 0, undeclared: 0, invalid: 1 }, details: [{ side: 'origen', reason: 'invalid-identity', tuple, message }] }))
    assert.isFalse(origin.clean, 'origen: deriva')
    const o = origin.lines.find((l) => l.message.includes('(invalid-identity) origen'))
    assert.equal(o?.level, 'error')
    assert.match(o!.message, /sin migrar .*ABC.*a mano/)

    const noPrune = relationsReconcileLines(report({ unchanged: 1, extra: 1, details: [{ side: 'destino', reason: 'invalid-identity', tuple, message }] }))
    assert.isTrue(noPrune.clean, 'sin --prune el operador eligió no podar: sobra con motivo')
    const w = noPrune.lines.find((l) => l.message.includes('(invalid-identity) destino'))
    assert.equal(w?.level, 'warning')
    assert.match(w!.message, /^sobra .*--prune/)

    const dry = relationsReconcileLines(report({ dryRun: true, unchanged: 1, deleted: 1, details: [{ side: 'destino', reason: 'invalid-identity', tuple, message, pruned: true }] }))
    assert.isFalse(dry.clean, 'dry-run: haría algo')
    const d = dry.lines.find((l) => l.message.includes('(invalid-identity) destino'))
    assert.equal(d?.level, 'log')
    assert.match(d!.message, /se pedirá al driver del destino que la BORRE /)
    // ⚪ R2 del re-ataque al cierre-2 (cierre-3): el dry-run NO sugiere que la pasada real lo arreglará con
    // los drivers del paquete — dice que NO la borrará y que hay que borrarla a mano YA.
    assert.match(d!.message, /database\/openfga.*la pasada real NO la borrará.*exit 1.*a mano \(SQL\/SDK\): bórrala ya/)
    assert.notMatch(d!.message, /la pasada real lo dirá/)

    const real = relationsReconcileLines(report({ unchanged: 1, deleted: 1, details: [{ side: 'destino', reason: 'invalid-identity', tuple, message, pruned: true }] }))
    assert.isTrue(real.clean, 'borrada: limpia')
    assert.match(real.lines.find((l) => l.message.includes('(invalid-identity) destino'))!.message, /^BORRADA por --prune/)

    const refused = relationsReconcileLines(report({ unchanged: 1, extra: 1, details: [{ side: 'destino', reason: 'invalid-identity', tuple, message, pruned: false }] }))
    assert.isFalse(refused.clean, 'el driver la rechazó: sigue ahí, exit ≠ 0')
    const r = refused.lines.find((l) => l.message.includes('(invalid-identity) destino'))
    assert.equal(r?.level, 'error')
    assert.match(r!.message, /NO se pudo borrar con --prune .*rechaza por el puerto.*a mano/)
    for (const { lines } of [origin, noPrune, dry, real, refused]) {
      assert.isTrue(lines.every((l) => !/422/.test(l.message)), 'nunca se vende como 422 del llamante')
    }
    // Un reporte de terceros anterior (sin `details` ni `skipped.invalid`) sigue limpio.
    assert.isTrue(relationsReconcileLines(report({ unchanged: 3 })).clean)
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
