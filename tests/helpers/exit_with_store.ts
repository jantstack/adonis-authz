/**
 * Proceso hijo para `harness_cleanup.spec` (3b-4 · C5): arma la red de los
 * stores de OpenFGA, crea uno y sale con `process.exit(0)` SIN barrerlo — el
 * patrón de una corrida interrumpida (`Ctrl-C`, `pkill`, un `.spec.ts` que
 * revienta al importarse), que es de donde salen los stores huérfanos.
 * Imprime `store:<id>` para que el caso compruebe que el guard lo borró.
 */
import { armOpenFgaStoreGuard } from './openfga_stores.js'

const apiUrl = process.env.OPENFGA_TEST_URL
if (!apiUrl) {
  console.error('sin OPENFGA_TEST_URL')
  process.exit(2)
}

await armOpenFgaStoreGuard(apiUrl)
const response = await fetch(`${apiUrl}/stores`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ name: `harness-leak-${Date.now()}` }),
})
const store: any = await response.json()
console.log(`store:${store.id}`)
process.exit(0)
