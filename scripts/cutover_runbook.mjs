#!/usr/bin/env node
/**
 * **El job `cutover-runbook`** (lote R del plan 2.5; `CLAUDE.md` puntos 8, 9 y 10):
 * ejecuta `tests/cutover_runbook.spec.ts` —el runbook del cutover paso a paso, por
 * el kernel de ace, con un proceso por fase— contra un motor que otro proceso pueda
 * abrir (`TEST_DB=pg | mysql | sqlite-file`) y un OpenFGA REAL (`OPENFGA_TEST_URL`).
 *
 * Es un gate, así que falla ruidoso en vez de saltarse:
 *  - sin motor válido o sin servidor que responda `/healthz` ⇒ exit 2 ANTES de correr;
 *  - el spec corre con `CUTOVER_RUNBOOK_REQUIRED=1`: si el entorno no sirve registra
 *    un caso rojo (nunca un skip);
 *  - exige ≥ 1 caso ejecutado y 0 rojos; y un presupuesto de tiempo con dientes
 *    (`CUTOVER_RUNBOOK_BUDGET_MS`, default 60 000): pasarse es rojo — se parte por
 *    fases, no se desactiva.
 *
 * Uso:
 *   TEST_DB=sqlite-file OPENFGA_TEST_URL=http://localhost:8090 npm run cutover-runbook
 *   TEST_DB=pg TEST_PG_URL=postgres://… OPENFGA_TEST_URL=http://localhost:8090 npm run cutover-runbook
 */
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const ENGINES = ['pg', 'mysql', 'sqlite-file']
const budgetMs = Number(process.env.CUTOVER_RUNBOOK_BUDGET_MS ?? 60_000)

function fail(message, code = 2) {
  process.stderr.write(`\n[cutover-runbook] ${message}\n`)
  process.exit(code)
}

const engine = process.env.TEST_DB
if (!ENGINES.includes(engine ?? '')) {
  fail(`TEST_DB='${engine ?? ''}' no vale: el runbook necesita un motor que otro PROCESO pueda abrir (${ENGINES.join(' | ')}); en :memory: un hijo no puede abrir la base.`)
}
const apiUrl = process.env.OPENFGA_TEST_URL
if (!apiUrl) fail('falta OPENFGA_TEST_URL: el runbook corre contra un OpenFGA REAL, nunca contra un doble.')
try {
  const health = await fetch(`${apiUrl}/healthz`)
  if (!health.ok) fail(`${apiUrl}/healthz respondió ${health.status}`)
} catch (error) {
  fail(`${apiUrl} no responde: ${error?.message ?? error}`)
}

process.stdout.write(`[cutover-runbook] motor ${engine} · OpenFGA ${apiUrl} · presupuesto ${budgetMs} ms\n`)
const started = Date.now()
const run = spawnSync(process.execPath, ['--import', '@poppinss/ts-exec', 'bin/test.ts', '--files=cutover_runbook'], {
  cwd: ROOT,
  stdio: ['ignore', 'pipe', 'pipe'],
  encoding: 'utf8',
  env: { ...process.env, CUTOVER_RUNBOOK_REQUIRED: '1', FORCE_COLOR: '0', NO_COLOR: '1' },
})
const elapsed = Date.now() - started
const out = `${run.stdout}\n${run.stderr}`.replace(/\x1b\[[0-9;]*m/g, '')
process.stdout.write(out)
const summary = /Tests\s+(\d+) passed(?:, (\d+) failed)?(?:, (\d+) skipped)?\s*\((\d+)\)/.exec(out)
if (!summary) fail(`la suite no imprimió su resumen (exit ${run.status}): el runbook no llegó a juzgarse.`)
const passed = Number(summary[1])
const failed = Number(summary[2] ?? 0)
const skipped = Number(summary[3] ?? 0)
process.stdout.write(`\n[cutover-runbook] ${passed} verdes · ${failed} rojos · ${skipped} saltados · ${(elapsed / 1000).toFixed(1)} s (presupuesto ${(budgetMs / 1000).toFixed(0)} s)\n`)
if (run.status !== 0 || failed > 0) fail(`ROJO: ${failed} caso(s) en rojo (exit ${run.status}).`, 1)
if (skipped > 0) fail(`ROJO: ${skipped} caso(s) saltados — el runbook no admite skips.`, 1)
if (passed < 2) fail(`ROJO: solo ${passed} caso(s) ejecutados; el runbook son al menos el recorrido y la guardia del README.`, 1)
if (elapsed > budgetMs) fail(`ROJO: ${elapsed} ms supera el presupuesto de ${budgetMs} ms. Se parte por fases, no se desactiva.`, 1)
process.stdout.write('[cutover-runbook] VERDE\n')
