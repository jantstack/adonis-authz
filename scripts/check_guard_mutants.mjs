/**
 * **Corredor de mutantes de la guardia de superficie L1** (plan 2.5 · lote 0; CLAUDE.md «Cómo se decide un
 * cambio» punto 6: «una entrada sin mutante que la mate … es rojo»; `linajes.md` L1).
 *
 * Lee `tests/fixtures/guard_mutants.json` —un mutante por celda de la tabla de `tests/fixtures/guard_manifest.ts`:
 * «quitar la guarda en ESA entrada»; desde el cierre 2 de D1 (⚪ N2) también los mutantes de las PROPIEDADES de
 * `GUARD_PROPERTIES` (`properties` en vez de `cells`: p. ej. los cinco de orden de la purga de `openfga`)— y, por cada uno:
 *
 *   1. aplica el mutante sobre una COPIA del árbol en un directorio temporal (jamás sobre el working tree:
 *      regla de revisiones no concurrentes; `node_modules` va enlazado, no copiado);
 *   2. corre el spec de la guardia (`tests/guard_surface.spec.ts`) con el reporter `ndjson` — por defecto SOLO los casos
 *      de su `expectRed` (Japa `--tests=<título>` EXACTO, repetible; cierre 5 de D2 · G1 del tester del panel «óptimo»:
 *      el criterio de muerte solo mira esos títulos, y correr el spec entero por mutante costaba ~17 min); con `--full`, el
 *      spec ENTERO (la pasada nocturna: recupera `collateral`, que es informativo y no decide nada);
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
 *   node scripts/check_guard_mutants.mjs --full          # el spec ENTERO por mutante (nocturna; da `collateral`)
 *   node scripts/check_guard_mutants.mjs --jobs 4        # N workers, cada uno con SU copia del árbol (G2)
 *   node scripts/check_guard_mutants.mjs --skip-db-independent   # G3: sin los mutantes de `DB_INDEPENDENT_FILES`
 *
 * **Línea base FILTRADA** (cierre 6 de D2 · ⚪ D5-5 del auditor): en el modo filtrado (G1) cada mutante se juzga por sus
 * títulos AISLADOS, así que la línea base entera no basta — un caso de `expectRed` que esté ROJO al correr aislado SIN
 * mutar (dependencia de orden, estado compartido) «mataría» siempre a sus mutantes. Antes de juzgar, el corredor corre
 * cada conjunto DISTINTO de `expectRed` sin mutar, aislado, con el mismo `--tests=`: todos tienen que salir verdes y
 * ejecutados, o exit 1 sin juzgar nada. (`--full` no la necesita: juzga sobre el spec entero, como su línea base.)
 * `--manifest`/`--spec` (solo para el caso que lo fija, `tests/guard_corridor.spec.ts`) cambian el manifiesto y el spec.
 *
 * **Paralelo (G2)**: `--jobs=N` (por defecto `min(availableParallelism − 1, memoria libre / 400 MB, 8)`: la guardia
 * medida ocupa ~345 MB de RSS por proceso). Cada worker tiene su directorio temporal (la copia está aislada; en
 * `sqlite-file` cada proceso abre su propio fichero `mkdtemp`); la salida se reordena por el orden del manifiesto.
 * **G3**: los mutantes cuyos ficheros son TODOS de `DB_INDEPENDENT_FILES` (`tuple_order.ts`, `reconcile.ts`: funciones
 * puras y el plan, sin SQL) dan el mismo veredicto en cualquier motor —se demostró una vez, informe del cierre 5 de D2—,
 * así que la pierna `sqlite-file` de CI los salta con `--skip-db-independent`.
 * **Equivalencia filtrado ⇔ completo** (condición de aceptación de G1, una vez): `--json` en los dos modos y comparar el
 * `status` por id — `scripts/compare_guard_mutants.mjs a.json b.json`.
 */
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const MANIFEST = 'tests/fixtures/guard_mutants.json'
const SPEC = 'tests/guard_surface.spec.ts'
let manifestPath = MANIFEST
let specPath = SPEC
/** Lo que se copia al directorio temporal: `package.json` (exports), `CLAUDE.md` (el caso «el LÍMITE está escrito» lee el punto 6, cierre-2 🟡 D) y, SI EXISTE, el fichero de decisiones (G-X lo cruza en local con el extracto versionado `tests/fixtures/exemptions_d6.json`; en CI no está y vale el extracto solo — cierre 🟠 1). */
const COPY = ['src', 'providers', 'services', 'commands', 'tests', 'bin', 'stubs', 'index.ts', 'configure.ts', 'package.json', 'tsconfig.json', 'tsconfig.test.json', 'CLAUDE.md', '.claude/contexto/decisiones-dueno-2026-08-28.md']
/** G3: ficheros sin SQL (el orden puro y el plan del reconcile): sus mutantes no dependen del motor. */
export const DB_INDEPENDENT_FILES = ['src/relations/tuple_order.ts', 'src/relations/reconcile.ts']

function defaultJobs() {
  const cpus = typeof os.availableParallelism === 'function' ? os.availableParallelism() : os.cpus().length
  const byMemory = Math.floor(os.freemem() / (400 * 1024 * 1024))
  return Math.max(1, Math.min(cpus - 1, byMemory, 8))
}

function parseArgs(argv) {
  const out = { only: null, db: process.env.TEST_DB, json: null, keep: false, full: false, jobs: null, skipDbIndependent: false, manifest: MANIFEST, spec: SPEC }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--only') out.only = new Set(argv[++i].split(',').map((s) => s.trim()).filter(Boolean))
    else if (a.startsWith('--only=')) out.only = new Set(a.slice(7).split(',').map((s) => s.trim()).filter(Boolean))
    else if (a === '--db') out.db = argv[++i]
    else if (a.startsWith('--db=')) out.db = a.slice(5)
    else if (a === '--json') out.json = argv[++i]
    else if (a.startsWith('--json=')) out.json = a.slice(7)
    else if (a === '--jobs') out.jobs = Number(argv[++i])
    else if (a.startsWith('--jobs=')) out.jobs = Number(a.slice(7))
    else if (a === '--keep') out.keep = true
    else if (a === '--full') out.full = true
    else if (a === '--skip-db-independent') out.skipDbIndependent = true
    else if (a.startsWith('--manifest=')) out.manifest = a.slice(11)
    else if (a.startsWith('--spec=')) out.spec = a.slice(7)
    else if (a === '--help' || a === '-h') {
      console.log('uso: node scripts/check_guard_mutants.mjs [--db <sqlite|sqlite-file|pg|mysql>] [--only id,id] [--json <fichero>] [--jobs N] [--full] [--skip-db-independent] [--keep] [--manifest=<json>] [--spec=<spec>]')
      process.exit(0)
    } else {
      console.error(`argumento desconocido: ${a}`)
      process.exit(2)
    }
  }
  if (out.jobs !== null && (!Number.isInteger(out.jobs) || out.jobs < 1)) {
    console.error(`--jobs tiene que ser un entero ≥ 1`)
    process.exit(2)
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

function filesOf(mutant) {
  return [...new Set(editsOf(mutant).map((edit) => edit.file ?? mutant.file))]
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

/**
 * Corre el spec de la guardia en `cwd` —entero, o SOLO los títulos de `titles` (G1)— y devuelve
 * { status, failed: Set<título>, seen: Set<título>, raw }.
 */
function runGuard(cwd, db, titles) {
  const env = { ...process.env }
  if (db) env.TEST_DB = db
  else delete env.TEST_DB
  const args = ['--import', '@poppinss/ts-exec', 'bin/test.ts', `--files=${specPath}`, '--reporters=ndjson']
  for (const title of titles ?? []) args.push(`--tests=${title}`)
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, { cwd, env })
    let out = ''
    child.stdout.on('data', (chunk) => (out += chunk))
    child.stderr.on('data', (chunk) => (out += chunk))
    const timer = setTimeout(() => child.kill('SIGKILL'), 10 * 60_000)
    child.on('close', (status) => {
      clearTimeout(timer)
      const failed = new Set()
      const seen = new Set()
      for (const line of out.split('\n')) {
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
      resolve({ status, failed, seen, raw: out })
    })
  })
}

/** Juzga UN mutante en la copia `cwd` (que el worker usa en exclusiva). */
async function judge(cwd, mutant, args) {
  const row = { id: mutant.id, cells: mutant.cells, file: mutant.file, expectRed: mutant.expectRed }
  const applied = apply(cwd, mutant)
  if (applied.error) {
    row.status = 'NO-CASA'
    row.detail = applied.error
    return row
  }
  let run
  try {
    run = await runGuard(cwd, args.db, args.full ? null : mutant.expectRed)
  } finally {
    applied.restore()
  }
  const notSeen = mutant.expectRed.filter((t) => !run.seen.has(t))
  const stillGreen = mutant.expectRed.filter((t) => run.seen.has(t) && !run.failed.has(t))
  // Colaterales (solo con `--full`): otros casos que el mutante también pone rojos. El cruce estático G-M («el find casa
  // exactamente una vez») se pone rojo SIEMPRE en el árbol mutado —es su trabajo— y no cuenta como colateral.
  if (args.full) row.collateral = [...run.failed].filter((t) => !mutant.expectRed.includes(t) && !t.includes('casa EXACTAMENTE una vez'))
  if (notSeen.length) {
    row.status = 'SIN-CASO'
    row.detail = `casos no ejecutados: ${notSeen.join(' | ')}`
  } else if (stillGreen.length) {
    row.status = 'VIVO'
    row.detail = `siguen verdes: ${stillGreen.join(' | ')}`
  } else row.status = 'muerto'
  return row
}

/** Los conjuntos DISTINTOS de `expectRed` de los mutantes seleccionados (la línea base filtrada, D5-5). */
export function filteredBaselineSets(mutants) {
  const seen = new Map()
  for (const m of mutants) {
    const titles = [...new Set(m.expectRed)].sort()
    const key = JSON.stringify(titles)
    if (!seen.has(key)) seen.set(key, titles)
  }
  return [...seen.values()]
}

function line(row) {
  if (row.status === 'muerto') {
    const extra = row.collateral?.length ? `, +${row.collateral.length} colateral(es)` : ''
    return `✔ ${row.id} — muerto (${row.expectRed.length} rojo(s)${extra})`
  }
  return `✖ ${row.id} — ${row.status}: ${row.detail}`
}

async function main() {
  const args = parseArgs(process.argv.slice(2))
  manifestPath = args.manifest
  specPath = args.spec
  const mutants = JSON.parse(fs.readFileSync(path.join(ROOT, manifestPath), 'utf8'))
  if (args.only) {
    const missing = [...args.only].filter((id) => !mutants.some((m) => m.id === id))
    if (missing.length) {
      console.error(`mutantes desconocidos en --only: ${missing.join(', ')}`)
      process.exit(2)
    }
  }
  let selected = args.only ? mutants.filter((m) => args.only.has(m.id)) : mutants
  let skipped = 0
  if (args.skipDbIndependent) {
    const before = selected.length
    selected = selected.filter((m) => !filesOf(m).every((file) => DB_INDEPENDENT_FILES.includes(file)))
    skipped = before - selected.length
  }
  const jobs = Math.min(args.jobs ?? defaultJobs(), Math.max(1, selected.length))
  const dirs = []
  for (let k = 0; k < jobs; k++) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'authz-guard-mutants-'))
    copyTree(tmp)
    dirs.push(tmp)
  }
  const mode = args.full ? 'spec ENTERO por mutante (--full)' : 'solo los casos de expectRed (G1)'
  console.log(
    `[mutantes] ${jobs} copia(s) del árbol (${dirs.join(', ')}); motor: ${args.db ?? 'sqlite (:memory:)'}; ${selected.length} mutante(s); ${mode}` +
      (skipped ? `; ${skipped} independiente(s) del motor saltado(s) (--skip-db-independent)` : '')
  )

  // Línea base: la guardia ENTERA tiene que estar VERDE sin mutar (si no, «rojo» no significa nada). Una vez.
  const baseline = await runGuard(dirs[0], args.db, null)
  if (baseline.failed.size > 0 || baseline.seen.size === 0) {
    console.error(`[mutantes] la guardia NO está verde sin mutar (${baseline.failed.size} rojos de ${baseline.seen.size}); corrige eso antes:`)
    for (const t of baseline.failed) console.error(`   ✖ ${t}`)
    if (baseline.seen.size === 0) console.error(baseline.raw.slice(-4000))
    if (!args.keep) for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true })
    process.exit(1)
  }
  console.log(`[mutantes] línea base verde: ${baseline.seen.size} casos`)

  // Cierre 6 de D2 · ⚪ D5-5: la línea base FILTRADA — cada conjunto distinto de `expectRed`, sin mutar y AISLADO, verde.
  if (!args.full) {
    const sets = filteredBaselineSets(selected)
    const t0 = Date.now()
    const broken = []
    let cursor = 0
    await Promise.all(
      dirs.map(async (cwd) => {
        while (cursor < sets.length) {
          const titles = sets[cursor++]
          const run = await runGuard(cwd, args.db, titles)
          const bad = titles.filter((t) => !run.seen.has(t) || run.failed.has(t))
          if (bad.length) broken.push(...bad.map((t) => `${run.seen.has(t) ? 'ROJO aislado' : 'sin ejecutar aislado'}: ${t}`))
        }
      })
    )
    if (broken.length > 0) {
      console.error(`[mutantes] la línea base FILTRADA no está verde (${broken.length} caso(s) de expectRed fallan AISLADOS sin mutar: sus mutantes «morirían» siempre en filtrado); corrige eso antes:`)
      for (const b of [...new Set(broken)]) console.error(`   ✖ ${b}`)
      if (!args.keep) for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true })
      process.exit(1)
    }
    console.log(`[mutantes] línea base FILTRADA verde: ${sets.length} conjunto(s) de expectRed aislados, en ${Math.round((Date.now() - t0) / 1000)} s`)
  }

  const started = Date.now()
  const results = new Array(selected.length)
  let next = 0
  await Promise.all(
    dirs.map(async (cwd) => {
      while (next < selected.length) {
        const i = next++
        results[i] = await judge(cwd, selected[i], args)
        console.log(line(results[i]))
      }
    })
  )
  const seconds = Math.round((Date.now() - started) / 1000)
  const dead = results.filter((r) => r.status === 'muerto').length
  const alive = results.length - dead
  console.log(`\n[mutantes] resumen en el orden del manifiesto:`)
  for (const row of results) if (row.status !== 'muerto') console.log(`   ${line(row)}`)
  console.log(`[mutantes] ${dead} muertos / ${results.length} (${alive} vivos o sin casar) en ${seconds} s; motor ${args.db ?? 'sqlite (:memory:)'}; ${jobs} worker(s); ${args.full ? 'completo' : 'filtrado'}`)
  if (args.json) {
    fs.writeFileSync(args.json, JSON.stringify({ db: args.db ?? 'sqlite', mode: args.full ? 'full' : 'filtered', jobs, seconds, results }, null, 2))
    console.log(`[mutantes] resultado escrito en ${args.json}`)
  }
  if (args.keep) console.log(`[mutantes] copias conservadas en ${dirs.join(', ')}`)
  else for (const dir of dirs) fs.rmSync(dir, { recursive: true, force: true })
  process.exit(alive > 0 ? 1 : 0)
}

main()
