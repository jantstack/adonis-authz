/**
 * Proceso hijo para `harness_cleanup.spec` (3b-1): bootea el harness y sale
 * con `process.exit(0)` SIN llamar a `teardown()` — el patrón de todos los
 * scripts de reproducción de `.claude/reproducciones/`, y la causa medida de
 * la fuga de bases en PostgreSQL. Imprime `db:<lo que provisionó>` para que
 * el caso compruebe que el guard de salida lo destruyó igualmente.
 */
import { bootApp } from './app.js'

const app = await bootApp()
console.log(`db:${app.database}`)
process.exit(0)
