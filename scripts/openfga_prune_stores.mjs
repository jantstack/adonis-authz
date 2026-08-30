/**
 * Borra los stores de OpenFGA que dejó una suite de tests.
 *
 *   node scripts/openfga_prune_stores.mjs --prefix contract- --prefix regrant- --prefix spies-           # dry-run
 *   node scripts/openfga_prune_stores.mjs --prefix contract- --prefix regrant- --prefix spies- --force   # borra
 *
 * Los harness de `tests/contract.spec.ts` y `tests/spies.spec.ts` ya borran
 * los suyos al terminar (F0.6), pero una ejecución interrumpida con Ctrl-C
 * deja stores huérfanos, y antes de la Fase 0 nunca se borraban.
 *
 * Es destructivo, así que por defecto solo LISTA; borra únicamente con
 * `--force`, y solo stores cuyo nombre empieza por alguno de los prefijos
 * dados (mínimo 4 caracteres: un prefijo vacío o de una letra es "todo" con
 * otro nombre). Sin `--prefix` no hace nada, a propósito.
 *
 * Usa `fetch` contra la API HTTP directamente (sin `@openfga/sdk`): es una
 * herramienta de mantenimiento, no del paquete, y así corre sin instalar el
 * peer opcional.
 */

const options = { url: process.env.OPENFGA_TEST_URL ?? 'http://localhost:8101', prefixes: [], force: false }

function fail(message) {
  console.error(message)
  process.exit(2)
}

function takeValue(argv, index, flag) {
  const value = argv[index + 1]
  if (value === undefined || value.startsWith('--')) fail(`${flag} necesita un valor`)
  return value
}

const args = process.argv.slice(2)
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--prefix') options.prefixes.push(takeValue(args, i++, '--prefix'))
  else if (args[i] === '--url') options.url = takeValue(args, i++, '--url')
  else if (args[i] === '--force') options.force = true
  else if (args[i] === '--dry-run') options.force = false
  else fail(`Argumento desconocido: ${args[i]}`)
}

if (options.prefixes.length === 0) fail('Indica al menos un --prefix; este script nunca borra sin filtro.')
for (const prefix of options.prefixes) {
  if (typeof prefix !== 'string' || prefix.length < 4) {
    fail(`Prefijo '${prefix}' demasiado corto (mínimo 4 caracteres): sería borrar casi todo.`)
  }
}
const dryRun = !options.force

async function listAllStores(base) {
  const stores = []
  let token = ''
  do {
    const query = `page_size=100${token ? `&continuation_token=${encodeURIComponent(token)}` : ''}`
    const response = await fetch(`${base}/stores?${query}`)
    if (!response.ok) throw new Error(`GET /stores → ${response.status}`)
    const body = await response.json()
    stores.push(...(body.stores ?? []))
    token = body.continuation_token ?? ''
  } while (token)
  return stores
}

const all = await listAllStores(options.url)
const targets = all.filter((store) => options.prefixes.some((prefix) => store.name.startsWith(prefix)))

console.log(
  `${options.url}: ${all.length} stores, ${targets.length} con prefijo ${options.prefixes.map((p) => `'${p}'`).join('/')}` +
    (dryRun ? ' (dry-run: no se borra nada; usa --force para borrar)' : '')
)

if (dryRun) {
  const byPrefix = {}
  for (const store of targets) {
    const prefix = options.prefixes.find((p) => store.name.startsWith(p))
    byPrefix[prefix] = (byPrefix[prefix] ?? 0) + 1
  }
  if (targets.length) console.log(byPrefix)
  process.exit(0)
}

let deleted = 0
for (const store of targets) {
  const response = await fetch(`${options.url}/stores/${store.id}`, { method: 'DELETE' })
  if (!response.ok) {
    console.error(`✖ ${store.name} (${store.id}) → ${response.status}`)
    continue
  }
  deleted += 1
}
console.log(`✔ borrados ${deleted}/${targets.length}; quedan ${all.length - deleted} stores`)
