/**
 * **Corredor de mutantes de la guardia de superficie L1** (plan 2.5 · lote 0; CLAUDE.md «Cómo se decide un
 * cambio» punto 6: «una entrada sin mutante que la mate … es rojo»; `linajes.md` L1).
 *
 * Lee `tests/fixtures/guard_mutants.json` —un mutante por celda de la tabla de `tests/fixtures/guard_manifest.ts`:
 * «quitar la guarda en ESA entrada»— y, por cada uno:
 *
 *   1. aplica el mutante sobre una COPIA del árbol en un directorio temporal (jamás sobre el working tree:
 *      regla de revisiones no concurrentes; `node_modules` va enlazado, no copiado);
 *   2. corre SOLO el spec de la guardia (`tests/guard_surface.spec.ts`) con el reporter `ndjson`;
 *   3. exige que se pongan ROJOS exactamente los casos nombrados en `expectRed` (no «algún caso»);
 *   4. restaura el fichero.
 *
 * Un mutante VIVO (el caso nombrado sigue verde), un `find` que no casa exactamente una vez o un spec que
 * no llega a ejecutar el caso ⇒ exit 1. El cruce estático «cada celda con sonda tiene mutante» lo hace el
 * propio spec (G-M) en cada `npm test`; este corredor es la prueba DINÁMICA y va en CI (job `guard-mutants`).
 *
 *   node scripts/check_guard_mutants.mjs                 # todos, con el motor de TEST_DB (default sqlite :memory:)
 *   node scripts/check_guard_mutants.mjs --db sqlite-file
 *   node scripts/check_guard_mutants.mjs --only manager.relate.f05,openfga.enumerate.whitelist
 *   node scripts/check_guard_mutants.mjs --json out.json # además escribe el resultado por mutante
 *   node scripts/check_guard_mutants.mjs --keep          # no borra la copia temporal (para inspeccionar)
 */
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const MANIFEST = 'tests/fixtures/guard_mutants.json'
const SPEC = 'tests/guard_surface.spec.ts'
/** Lo que se copia al directorio temporal: `package.json` (exports), `CLAUDE.md` (el caso «el LÍMITE está escrito» lee el punto 6, cierre-2 🟡 D) y, SI EXISTE, el fichero de decisiones (G-X lo cruza en local con el extracto versionado `tests/fixtures/exemptions_d6.json`; en CI no está y vale el extracto solo — cierre 🟠 1). */
const COPY = ['src', 'providers', 'services', 'commands', 'tests', 'bin', 'stubs', 'index.ts', 'configure.ts', 'package.json', 'tsconfig.json', 'tsconfig.test.json', 'CLAUDE.md', '.claude/contexto/decisiones-dueno-2026-08-28.md']

function parseArgs(argv) {
  const out = { only: null, db: process.env.TEST_DB, json: null, keep: false }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--only') out.only = new Set(argv[++i].split(',').map((s) => s.trim()).filter(Boolean))
    else if (a.startsWith('--only=')) out.only = new Set(a.slice(7).split(',').map((s) => s.trim()).filter(Boolean))
    else if (a === '--db') out.db = argv[++i]
    else if (a.startsWith('--db=')) out.db = a.slice(5)
    else if (a === '--json') out.json = argv[++i]
    else if (a.startsWith('--json=')) out.json = a.slice(7)
    else if (a === '--keep') out.keep = true
    else if (a === '--help' || a === '-h') {
      console.log('uso: node scripts/check_guard_mutants.mjs [--db <sqlite|sqlite-file|pg|mysql>] [--only id,id] [--json <fichero>] [--keep]')
      process.exit(0)
    } else {
      console.error(`argumento desconocido: ${a}`)
      process.exit(2)
    }
  }
  return out
}

function copyTree(target) {
  for (const entry of COPY) {
    const from = path.join(ROOT, entry)
    if (!fs.existsSync(from)) continue
    const to = path.join(target, entry)
    fs.mkdirSync(path.dirname(to), { recursive: true })
    fs.cpSync(from, to, { recursive: true })
  }
  fs.symlinkSync(path.join(ROOT, 'node_modules'), path.join(target, 'node_modules'), 'dir')
}

function editsOf(mutant) {
  return Array.isArray(mutant.edits) ? mutant.edits : [{ find: mutant.find, replace: mutant.replace }]
}

/**
 * Aplica el mutante sobre la copia en `cwd` (cada edit en su fichero: `edit.file ?? mutant.file`). Devuelve los
 * originales para restaurar, o `error` si algún `find` no casa exactamente una vez (entonces no toca nada).
 */
function apply(cwd, mutant) {
  const texts = new Map()
  for (const edit of editsOf(mutant)) {
    const file = path.join(cwd, edit.file ?? mutant.file)
    if (!texts.has(file)) texts.set(file, { original: fs.readFileSync(file, 'utf8'), mutated: null })
    const entry = texts.get(file)
    const current = entry.mutated ?? entry.original
    const occurrences = current.split(edit.find).length - 1
    if (occurrences !== 1) return { error: `'find' casa ${occurrences} veces en ${edit.file ?? mutant.file} (tiene que casar exactamente una)` }
    // Función, no cadena: un `$&`/`$1` dentro de `replace` sería un patrón de String.replace, no texto.
    entry.mutated = current.replace(edit.find, () => edit.replace)
  }
  for (const [file, entry] of texts) fs.writeFileSync(file, entry.mutated)
  return { restore: () => texts.forEach((entry, file) => fs.writeFileSync(file, entry.original)) }
}

/** Corre el spec de la guardia en `cwd` y devuelve { ok, failed: Set<título>, seen: Set<título>, raw }. */
function runGuard(cwd, db) {
  const env = { ...process.env }
  if (db) env.TEST_DB = db
  else delete env.TEST_DB
  const result = spawnSync(
    process.execPath,
    ['--import', '@poppinss/ts-exec', 'bin/test.ts', `--files=${SPEC}`, '--reporters=ndjson'],
    { cwd, env, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 10 * 60_000 }
  )
  const failed = new Set()
  const seen = new Set()
  for (const line of `${result.stdout}\n${result.stderr}`.split('\n')) {
    if (!line.startsWith('{')) continue
    let event
    try {
      event = JSON.parse(line)
    } catch {
      continue
    }
    if (event.event !== 'test:end') continue
    const title = event.title?.expanded ?? event.title?.original ?? String(event.title)
    seen.add(title)
    if (Array.isArray(event.errors) && event.errors.length > 0) failed.add(title)
  }
  return { status: result.status, failed, seen, raw: `${result.stdout}\n${result.stderr}` }
}

function main() {
  const args = parseArgs(process.argv.slice(2))
  const mutants = JSON.parse(fs.readFileSync(path.join(ROOT, MANIFEST), 'utf8'))
  const selected = args.only ? mutants.filter((m) => args.only.has(m.id)) : mutants
  if (args.only) {
    const missing = [...args.only].filter((id) => !mutants.some((m) => m.id === id))
    if (missing.length) {
      console.error(`mutantes desconocidos en --only: ${missing.join(', ')}`)
      process.exit(2)
    }
  }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'authz-guard-mutants-'))
  copyTree(tmp)
  console.log(`[mutantes] copia del árbol en ${tmp}; motor: ${args.db ?? 'sqlite (:memory:)'}; ${selected.length} mutante(s)`)

  // Línea base: la guardia tiene que estar VERDE sin mutar (si no, «rojo» no significa nada).
  const baseline = runGuard(tmp, args.db)
  if (baseline.failed.size > 0 || baseline.seen.size === 0) {
    console.error(`[mutantes] la guardia NO está verde sin mutar (${baseline.failed.size} rojos de ${baseline.seen.size}); corrige eso antes:`)
    for (const t of baseline.failed) console.error(`   ✖ ${t}`)
    if (baseline.seen.size === 0) console.error(baseline.raw.slice(-4000))
    process.exit(1)
  }
  console.log(`[mutantes] línea base verde: ${baseline.seen.size} casos`)

  const results = []
  let alive = 0
  const started = Date.now()
  for (const mutant of selected) {
    const applied = apply(tmp, mutant)
    const row = { id: mutant.id, cells: mutant.cells, file: mutant.file, expectRed: mutant.expectRed }
    if (applied.error) {
      row.status = 'NO-CASA'
      row.detail = applied.error
      alive += 1
      results.push(row)
      console.log(`✖ ${mutant.id} — NO CASA: ${applied.error}`)
      continue
    }
    let run
    try {
      run = runGuard(tmp, args.db)
    } finally {
      applied.restore()
    }
    const notSeen = mutant.expectRed.filter((t) => !run.seen.has(t))
    const stillGreen = mutant.expectRed.filter((t) => run.seen.has(t) && !run.failed.has(t))
    // Colaterales: otros casos que el mutante también pone rojos. El cruce estático G-M («el find casa exactamente
    // una vez») se pone rojo SIEMPRE en el árbol mutado —es su trabajo— y no cuenta como colateral.
    const collateral = [...run.failed].filter((t) => !mutant.expectRed.includes(t) && !t.includes('casa EXACTAMENTE una vez'))
    row.collateral = collateral
    if (notSeen.length) {
      row.status = 'SIN-CASO'
      row.detail = `casos no ejecutados: ${notSeen.join(' | ')}`
      alive += 1
      console.log(`✖ ${mutant.id} — SIN CASO: ${row.detail}`)
    } else if (stillGreen.length) {
      row.status = 'VIVO'
      row.detail = `siguen verdes: ${stillGreen.join(' | ')}`
      alive += 1
      console.log(`✖ ${mutant.id} — VIVO: ${row.detail}`)
    } else {
      row.status = 'muerto'
      console.log(`✔ ${mutant.id} — muerto (${mutant.expectRed.length} rojo(s)${collateral.length ? `, +${collateral.length} colateral(es)` : ''})`)
    }
    results.push(row)
  }
  const seconds = Math.round((Date.now() - started) / 1000)
  const dead = results.filter((r) => r.status === 'muerto').length
  console.log(`\n[mutantes] ${dead} muertos / ${results.length} (${alive} vivos o sin casar) en ${seconds} s; motor ${args.db ?? 'sqlite (:memory:)'}`)
  if (args.json) {
    fs.writeFileSync(args.json, JSON.stringify({ db: args.db ?? 'sqlite', seconds, results }, null, 2))
    console.log(`[mutantes] resultado escrito en ${args.json}`)
  }
  if (args.keep) console.log(`[mutantes] copia conservada en ${tmp}`)
  else fs.rmSync(tmp, { recursive: true, force: true })
  process.exit(alive > 0 ? 1 : 0)
}

main()
