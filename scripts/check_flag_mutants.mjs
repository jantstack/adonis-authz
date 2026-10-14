#!/usr/bin/env node
/**
 * **Mutantes de banderas** (lote R del plan 2.5; metodología 2026-09-13, M2 absorbida en M7;
 * `CLAUDE.md` § «Cómo se decide un cambio», puntos 6 y 9).
 *
 * Por cada bandera de cada comando de `commands/` (enumeradas por REFLEXIÓN sobre los flags
 * booteados del loader, `tests/helpers/list_flags.ts`) se ejecutan los dos ficheros de kernel
 * de la suite (`tests/command_flags*.spec.ts` y `tests/commands.spec.ts`) con ESA bandera
 * inerte —`AUTHZ_INERT_FLAG=<comando>#<propiedad>`, que el harness `tests/helpers/ace.ts`
 * convierte en el defecto de alpha.8 en ejecución: el valor cae en `this['la-bandera']` y la
 * propiedad tipada queda `undefined`— y se exige que ALGÚN caso se ponga rojo. La guardia
 * estática A-G no cuenta como muerte (no ve el mutante: mira el fuente); solo el EFECTO.
 *
 * Reglas (juez del panel: «todo script de mutantes tiene que fallar de forma ruidosa si un
 * parche no aplica o si un mutante no altera nada»):
 *  - la suite base (sin mutante) tiene que estar VERDE; si no, exit 2 y no se mide nada;
 *  - un mutante que no aplica (propiedad inexistente) hace lanzar al harness ⇒ el caso que lo
 *    tocó sale rojo con ese mensaje, y aquí se clasifica como `no-aplica`, exit 2;
 *  - un mutante VIVO (ningún caso rojo) sin una exención con razón escrita en
 *    `scripts/flag_mutants.manifest.json` ⇒ exit 1;
 *  - una exención cuyo mutante en realidad MUERE es una exención rancia ⇒ exit 1 (se retira);
 *  - `pending` del manifiesto son banderas FUTURAS (p. ej. `--allow-drop-deny`, lote D): si no
 *    existen todavía se listan como pendientes sin romper; cuando existan se juzgan como las
 *    demás (pending NO es exención).
 *
 * Uso:
 *   node scripts/check_flag_mutants.mjs                       # sqlite :memory: (TEST_DB respeta el entorno)
 *   TEST_DB=sqlite-file node scripts/check_flag_mutants.mjs
 *   OPENFGA_TEST_URL=http://localhost:8090 node scripts/check_flag_mutants.mjs
 *   node scripts/check_flag_mutants.mjs --only='authz:reconcile#dryRun' [--only=…]
 *   node scripts/check_flag_mutants.mjs --json=salida.json      # además, el informe en JSON
 */
import { spawnSync } from 'node:child_process'
import { readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const MANIFEST = path.join(ROOT, 'scripts', 'flag_mutants.manifest.json')
/**
 * Los ficheros de kernel: `tests/commands.spec.ts` y todo `tests/command_flags*.spec.ts`,
 * leídos del disco (un fichero nuevo de banderas entra solo). `--files` de Japa casa el
 * NOMBRE EXACTO sin `.spec.ts` (medido: `command_flags` NO casa `command_flags_r`).
 */
const KERNEL_FILES = readdirSync(path.join(ROOT, 'tests'))
  .filter((f) => f === 'commands.spec.ts' || (f.startsWith('command_flags') && f.endsWith('.spec.ts')))
  .map((f) => f.replace(/\.spec\.ts$/, ''))
  .sort()
const TS_EXEC = ['--import', '@poppinss/ts-exec']

const args = process.argv.slice(2)
const only = args.filter((a) => a.startsWith('--only=')).map((a) => a.slice('--only='.length))
const jsonOut = args.find((a) => a.startsWith('--json='))?.slice('--json='.length)
const verbose = args.includes('--verbose')

const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]*m/g, '')

function fail(message, code = 2) {
  process.stderr.write(`\n[flag-mutants] ${message}\n`)
  process.exit(code)
}

/* ── 1 · Enumeración por reflexión ─────────────────────────────────────────── */

function listFlags() {
  const run = spawnSync(process.execPath, [...TS_EXEC, 'tests/helpers/list_flags.ts'], {
    cwd: ROOT,
    encoding: 'utf8',
    env: process.env,
  })
  if (run.status !== 0) fail(`no se pudieron enumerar las banderas:\n${run.stdout}\n${run.stderr}`)
  const line = run.stdout.split('\n').find((l) => l.startsWith('['))
  if (!line) fail(`list_flags.ts no imprimió la lista:\n${run.stdout}`)
  return JSON.parse(line)
}

/* ── 2 · Una corrida de los ficheros de kernel ─────────────────────────────── */

function runKernelSpecs(env) {
  const started = Date.now()
  const run = spawnSync(
    process.execPath,
    [...TS_EXEC, 'bin/test.ts', ...KERNEL_FILES.map((f) => `--files=${f}`)],
    { cwd: ROOT, encoding: 'utf8', env: { ...process.env, ...env, FORCE_COLOR: '0', NO_COLOR: '1' } }
  )
  const out = stripAnsi(`${run.stdout}\n${run.stderr}`)
  const summary = /Tests\s+(\d+) passed(?:, (\d+) failed)?(?:, (\d+) skipped)?\s*\((\d+)\)/.exec(out)
  // Los fallos los imprime el reporter como `❯ <grupo> / <título>` en columna 0.
  const failed = out
    .split('\n')
    .filter((l) => l.startsWith('❯ '))
    .map((l) => l.slice(2).trim())
  const notApplied = out.includes('El mutante NO aplica')
  return {
    ms: Date.now() - started,
    exit: run.status,
    passed: summary ? Number(summary[1]) : null,
    failedCount: summary ? Number(summary[2] ?? 0) : null,
    total: summary ? Number(summary[4]) : null,
    failed,
    notApplied,
    raw: out,
  }
}

/* ── 3 · Manifiesto ────────────────────────────────────────────────────────── */

function readManifest() {
  let manifest
  try {
    manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'))
  } catch (error) {
    fail(`no se pudo leer ${MANIFEST}: ${error?.message ?? error}`)
  }
  for (const entry of manifest.exemptions ?? []) {
    if (!entry.command || !entry.flag || !entry.reason || !entry.signedBy) {
      fail(`exención incompleta en el manifiesto (command, flag, reason, signedBy son obligatorios): ${JSON.stringify(entry)}`)
    }
  }
  for (const entry of manifest.pending ?? []) {
    if (!entry.command || !entry.flag || !entry.lot) {
      fail(`pendiente incompleto en el manifiesto (command, flag, lot son obligatorios): ${JSON.stringify(entry)}`)
    }
  }
  return { exemptions: manifest.exemptions ?? [], pending: manifest.pending ?? [] }
}

/* ── 4 · Pasada ────────────────────────────────────────────────────────────── */

const totalStarted = Date.now()
const manifest = readManifest()
const flags = listFlags()
if (flags.length < 20) fail(`la enumeración por reflexión devolvió ${flags.length} banderas: algo se rompió`)

const selected = only.length ? flags.filter((f) => only.includes(`${f.command}#${f.property}`)) : flags
if (only.length && selected.length !== only.length) {
  const known = new Set(flags.map((f) => `${f.command}#${f.property}`))
  fail(`--only nombra banderas que no existen: ${only.filter((o) => !known.has(o)).join(', ')}`)
}

process.stdout.write(`[flag-mutants] ${flags.length} banderas booteadas en ${new Set(flags.map((f) => f.command)).size} comandos · ficheros ${KERNEL_FILES.join(', ')}`)
process.stdout.write(` · motor ${process.env.TEST_DB ?? 'sqlite'}${process.env.OPENFGA_TEST_URL ? ` · OpenFGA ${process.env.OPENFGA_TEST_URL}` : ' · sin OpenFGA'}\n`)

const baseline = runKernelSpecs({})
if (baseline.exit !== 0 || baseline.failedCount !== 0 || !baseline.total) {
  process.stderr.write(baseline.raw)
  fail(
    `la suite BASE (sin mutante) no está verde (${baseline.failed.length} rojos, exit ${baseline.exit}): ` +
      'no se mide nada hasta que lo esté. Si acabas de reintroducir una bandera inerte a mano, esto es el rojo que esperabas.'
  )
}
process.stdout.write(`[flag-mutants] base verde: ${baseline.total} casos en ${baseline.ms} ms\n`)

const isGuardCase = (title) => /\/\s*A-G-\d/.test(title)
const rows = []
for (const flag of selected) {
  const id = `${flag.command}#${flag.property}`
  const run = runKernelSpecs({ AUTHZ_INERT_FLAG: id })
  const killers = run.failed.filter((t) => !isGuardCase(t))
  const guardOnly = run.failed.length > 0 && killers.length === 0
  const exemption = manifest.exemptions.find((e) => e.command === flag.command && e.flag === flag.flag)
  let status
  if (run.notApplied) status = 'no-aplica'
  else if (run.total === null) status = 'suite-rota'
  else if (killers.length > 0) status = exemption ? 'exencion-rancia' : 'muerto'
  else status = exemption ? 'vivo-exento' : guardOnly ? 'vivo-solo-guardia' : 'vivo'
  rows.push({ ...flag, id, status, killers, ms: run.ms, exemption: exemption ?? null, raw: run.raw })
  const mark = status === 'muerto' ? '✔' : status === 'vivo-exento' ? '○' : '✖'
  process.stdout.write(`${mark} ${flag.command} ${flag.flag} · ${status} · ${run.ms} ms${verbose && killers.length ? ` · ${killers[0]}` : ''}\n`)
}

/* ── 5 · Pendientes (banderas futuras) ─────────────────────────────────────── */

const pendingRows = manifest.pending.map((p) => {
  const exists = flags.some((f) => f.command === p.command && f.flag === p.flag)
  return { ...p, exists }
})

/* ── 6 · Tabla e informe ───────────────────────────────────────────────────── */

const totalMs = Date.now() - totalStarted
const short = (title) => title.replace(/^.*?\/\s*/, '').slice(0, 110)
process.stdout.write('\n| comando | bandera | estado | caso que la mató (primero) · nº rojos |\n|---|---|---|---|\n')
for (const r of rows) {
  const cell =
    r.killers.length > 0
      ? `${short(r.killers[0])} · ${r.killers.length}`
      : r.exemption
        ? `exención: ${r.exemption.reason} (${r.exemption.signedBy})`
        : '—'
  process.stdout.write(`| ${r.command} | ${r.flag} | ${r.status} | ${cell} |\n`)
}
for (const p of pendingRows) {
  process.stdout.write(`| ${p.command} | ${p.flag} | ${p.exists ? 'EXISTE: se juzga arriba' : `pendiente (${p.lot})`} | ${p.note ?? ''} |\n`)
}

const count = (s) => rows.filter((r) => r.status === s).length
process.stdout.write(
  `\n[flag-mutants] ${rows.length} mutantes · muertos ${count('muerto')} · vivos ${count('vivo') + count('vivo-solo-guardia')} · ` +
    `exentos ${count('vivo-exento')} · exenciones rancias ${count('exencion-rancia')} · no aplican ${count('no-aplica')} · ` +
    `suite rota ${count('suite-rota')} · pendientes ${pendingRows.filter((p) => !p.exists).length} · ${(totalMs / 1000).toFixed(1)} s\n`
)

if (jsonOut) {
  writeFileSync(
    jsonOut,
    JSON.stringify(
      {
        engine: process.env.TEST_DB ?? 'sqlite',
        openfga: process.env.OPENFGA_TEST_URL ?? null,
        baseline: { total: baseline.total, ms: baseline.ms },
        totalMs,
        mutants: rows.map(({ raw: _raw, ...r }) => r),
        pending: pendingRows,
      },
      null,
      2
    )
  )
}

const broken = rows.filter((r) => r.status === 'no-aplica' || r.status === 'suite-rota')
if (broken.length) {
  for (const r of broken) process.stderr.write(`\n[flag-mutants] ${r.id}: ${r.status}\n${r.raw.slice(-2000)}\n`)
  fail(`${broken.length} mutante(s) no se pudieron juzgar (instrumentación rota): ${broken.map((r) => r.id).join(', ')}`)
}
const alive = rows.filter((r) => r.status === 'vivo' || r.status === 'vivo-solo-guardia')
const stale = rows.filter((r) => r.status === 'exencion-rancia')
if (alive.length || stale.length) {
  if (alive.length) {
    process.stderr.write(
      `\n[flag-mutants] ${alive.length} bandera(s) INERTES sin que ningún caso lo note (sin exención escrita): ` +
        `${alive.map((r) => `${r.command} ${r.flag}`).join(', ')}\n` +
        '  Escribe el caso que afirme el EFECTO de la bandera por el kernel (tests/command_flags*.spec.ts), ' +
        'o una exención con razón y firma en scripts/flag_mutants.manifest.json.\n'
    )
  }
  if (stale.length) {
    process.stderr.write(
      `\n[flag-mutants] ${stale.length} exención(es) RANCIAS (el mutante muere, la exención sobra): ` +
        `${stale.map((r) => `${r.command} ${r.flag}`).join(', ')}\n`
    )
  }
  process.exit(1)
}
process.stdout.write('[flag-mutants] VERDE: toda bandera booteada tiene un caso que muere cuando queda inerte.\n')
