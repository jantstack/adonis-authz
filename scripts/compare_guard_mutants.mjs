/**
 * **Equivalencia de dos pasadas del corredor de mutantes** (cierre 5 de D2 · G1/G3 del tester del panel «óptimo»):
 * compara el `status` por id de dos `--json` de `scripts/check_guard_mutants.mjs` (p. ej. `--full` frente al filtrado
 * por `expectRed`, o `:memory:` frente a `sqlite-file` para los mutantes independientes del motor). Exit 0 si los ids
 * comunes dan el MISMO veredicto y los dos cubren los mismos ids (salvo `--subset`, que solo exige que los de B estén en A).
 *
 *   node scripts/compare_guard_mutants.mjs completo.json filtrado.json
 *   node scripts/compare_guard_mutants.mjs memoria.json fichero.json --subset
 */
import fs from 'node:fs'

const [a, b, flag] = process.argv.slice(2)
if (!a || !b) {
  console.error('uso: node scripts/compare_guard_mutants.mjs <a.json> <b.json> [--subset]')
  process.exit(2)
}
const read = (file) => new Map(JSON.parse(fs.readFileSync(file, 'utf8')).results.map((r) => [r.id, r.status]))
const A = read(a)
const B = read(b)
const diffs = []
for (const [id, status] of B) {
  if (!A.has(id)) diffs.push(`${id}: falta en ${a}`)
  else if (A.get(id) !== status) diffs.push(`${id}: ${A.get(id)} (${a}) ≠ ${status} (${b})`)
}
if (flag !== '--subset') for (const id of A.keys()) if (!B.has(id)) diffs.push(`${id}: falta en ${b}`)
const same = [...B.keys()].filter((id) => A.get(id) === B.get(id)).length
console.log(`[equivalencia] ${same} id(s) con el mismo veredicto; ${diffs.length} diferencia(s)`)
for (const d of diffs) console.log(`   ✖ ${d}`)
process.exit(diffs.length ? 1 : 0)
