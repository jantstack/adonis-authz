/**
 * Script para un proceso hijo: bootea la app mínima de la suite (Lucid
 * necesita una app para `services/db`), bloquea `@openfga/sdk` con un hook
 * de resolución y carga el módulo que se le pasa por argumento. Imprime
 * `loaded:<módulo>` si cargó; si no, el error sale por stderr y el proceso
 * termina con código ≠ 0.
 *
 *   node --import @poppinss/ts-exec tests/helpers/load_without_sdk.ts ../../index.ts
 */
import { register } from 'node:module'

register('./block_openfga_hook.mjs', import.meta.url)

const target = process.argv[2]
if (!target) {
  console.error('uso: load_without_sdk.ts <módulo relativo a tests/helpers>')
  process.exit(2)
}

// Hereda `TEST_DB`: con PG/MySQL provisiona SU base con sufijo y la destruye
// al salir (`teardown`, no solo `closeAll`): sin esto cada `npm run test:pg`
// dejaba una base huérfana en el servidor (2.5 · J2, hallazgo).
const { bootApp } = await import('./app.js')
const app = await bootApp()
try {
  await import(target)
  console.log(`loaded:${target}`)
} finally {
  await app.teardown()
}
