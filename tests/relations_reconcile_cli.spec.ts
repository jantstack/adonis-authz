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
    skipped: { expired: 0 },
    ...over,
  }
}

test.group('authz:relations:reconcile — relationsReconcileLines', () => {
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
    const expired = relationsReconcileLines(report({ dryRun: true, skipped: { expired: 2 } }))
    assert.isTrue(expired.clean)
    assert.isTrue(expired.lines.some((l) => l.message.includes('2 tupla(s) del origen estaban CADUCADAS')))
    assert.isTrue(relationsReconcileLines(report({ dryRun: true, unchanged: 5 })).clean)
  })

  test('en una pasada que escribe, `extra` sin --prune AVISA pero no tumba', ({ assert }) => {
    const { lines, clean } = relationsReconcileLines(report({ written: 2, extra: 1 }))
    assert.isTrue(clean) // el operador eligió no podar
    assert.isTrue(lines.some((l) => l.level === 'warning' && l.message.includes('--prune')))
  })
})
