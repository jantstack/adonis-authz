/**
 * Borra los stores de OpenFGA que una ejecución de la suite creó y no llegó a
 * borrar (3b-4 · C5). Lo dispara el **guard de salida** de
 * `tests/helpers/openfga_stores.ts` desde un `spawnSync`, porque
 * `process.on('exit')` solo admite trabajo SÍNCRONO — el mismo patrón que
 * `drop_database.mjs` para la base SQL.
 *
 *   node tests/helpers/delete_stores.mjs '<json>'
 *
 * El JSON es `{ url, baseline: string[], since: string }`. Se borra un store
 * si y solo si (a) no estaba en la foto de `baseline` que se tomó al arrancar
 * la suite y (b) su `created_at` es POSTERIOR a `since`. Las dos condiciones,
 * y no una: en el `:8101` de esta máquina puede haber otra suite corriendo, y
 * un guard que borra por prefijo se lleva los stores de quien esté al lado.
 *
 * Usa `fetch` contra la API HTTP (sin `@openfga/sdk`): es una herramienta del
 * harness y tiene que correr aunque el peer opcional no esté instalado.
 */

const payload = JSON.parse(process.argv[2] ?? '{}')
const { url, baseline = [], since } = payload
if (!url) {
  console.error('[stores] falta la url')
  process.exit(2)
}
const known = new Set(baseline)
const floor = since ? Date.parse(since) : 0

async function listAll() {
  const stores = []
  let token = ''
  do {
    const query = `page_size=100${token ? `&continuation_token=${encodeURIComponent(token)}` : ''}`
    const response = await fetch(`${url}/stores?${query}`)
    if (!response.ok) throw new Error(`GET /stores → ${response.status}`)
    const body = await response.json()
    stores.push(...(body.stores ?? []))
    token = body.continuation_token ?? ''
  } while (token)
  return stores
}

try {
  const all = await listAll()
  const mine = all.filter((store) => !known.has(store.id) && Date.parse(store.created_at ?? 0) >= floor)
  let deleted = 0
  for (const store of mine) {
    const response = await fetch(`${url}/stores/${store.id}`, { method: 'DELETE' })
    if (response.ok) deleted += 1
    else console.error(`[stores] ✖ ${store.name} (${store.id}) → ${response.status}`)
  }
  if (mine.length) {
    console.error(`[stores] borrados ${deleted}/${mine.length} stores de esta ejecución; quedan ${all.length - deleted}`)
  }
  process.exit(deleted === mine.length ? 0 : 1)
} catch (error) {
  console.error(`[stores] no se pudieron borrar: ${error?.message ?? error}`)
  process.exit(1)
}
