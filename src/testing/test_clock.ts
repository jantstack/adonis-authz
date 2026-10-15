/**
 * **`createTestClock` — el reloj controlable para los tests del CONSUMIDOR**
 * (plan 2.5 · lote A, P5 del 7.º informe de COGNITIV: «no podemos probar la
 * caducidad sin dormir»). El motor lee la hora de pared por UN solo reloj
 * inyectable (`config.clock`, 2.5 · J1): el provider se lo pasa al manager de
 * roles Y al de relaciones (`providers/authz_provider.ts`), y los dos lo
 * aplican a sus drivers con `withClock`. Este helper fabrica ese reloj como
 * **una función ESTABLE sobre un valor MUTABLE**: la misma referencia vive en
 * el config durante todo el proceso de test, y `set`/`advance` mueven lo que
 * devuelve.
 *
 *   // config/authorization.ts
 *   import { createTestClock } from '@jantstack/adonis-authz/testing/clock'
 *   export const testClock = createTestClock('2030-01-01T00:00:00.000Z')
 *   export default defineConfig({ …, clock: app.inTest ? testClock : undefined })
 *
 *   // en un test
 *   await relations.relate(u, 'viewer', doc, tenant, { expiresAt: testClock.at(+3_600_000) })
 *   testClock.advance(3_600_000)          // la compartición acaba de caducar (estricta)
 *   assert.isFalse(await relations.check(u, 'viewer', doc, tenant))
 *
 * **Lo que también decide este reloj** (y por eso va escrito en el README): la
 * BARRERA del freeze (`RelationsManager.#assertNotFrozen` y la de roles) y el
 * lease de una pasada de `authz:reconcile` leen `nowMs` de ESTE reloj: con el
 * reloj parado un freeze con lease no caduca nunca para este proceso, y
 * adelantarlo 16 s hace que una pasada vea su lease vencido. No muta
 * `systemClock` ni nada global: lo que no reciba este reloj sigue en la hora
 * de pared (los sellos `created_at`, por diseño).
 *
 * **Módulo LIGERO, subpath propio `/testing/clock`** (🟡 A5 del auditor del
 * lote A): el README lo pone en `config/authorization.ts`, que producción
 * carga, y `/testing` (`main.ts`) importa estáticamente `@japa/runner`,
 * `@japa/assert` y `@adonisjs/lucid/services/db` — en un despliegue con
 * `--omit=dev` el config no cargaba y la app no arrancaba
 * (`ERR_MODULE_NOT_FOUND`). Este fichero solo importa `../clock.js` (que no
 * importa nada), `/testing` lo re-exporta, y `tests/clock.spec.ts` (P5-4)
 * afirma por análisis de imports que el grafo del subpath no toca japa ni
 * lucid y que `package.json` lo publica.
 */
import { systemClock } from '../clock.js'

export interface TestClock {
  /** El reloj: `() => Date` con el instante actual del test (una copia nueva en cada lectura). */
  (): Date
  /** Fija el instante. */
  set(at: Date | number | string): void
  /** Avanza (o retrocede, con negativo) `ms` milisegundos. */
  advance(ms: number): void
  /** El instante actual del test (copia). */
  now(): Date
  /** Un instante RELATIVO al actual (`at(+60_000)` = dentro de un minuto): para `expiresAt`. */
  at(offsetMs: number): Date
}

function toInstant(value: Date | number | string, what: string): number {
  const ms = value instanceof Date ? value.getTime() : typeof value === 'number' ? value : Date.parse(value)
  if (!Number.isFinite(ms)) {
    throw new TypeError(`createTestClock: ${what} no es un instante válido (llegó ${JSON.stringify(value)})`)
  }
  return ms
}

/** Un reloj de test parado en `start` (default: la hora de pared al crearlo), controlable con `set`/`advance`. */
export function createTestClock(start: Date | number | string = systemClock()): TestClock {
  let current = toInstant(start, 'start')
  const clock = (() => new Date(current)) as TestClock
  clock.set = (at) => {
    current = toInstant(at, 'set(at)')
  }
  clock.advance = (ms) => {
    if (typeof ms !== 'number' || !Number.isFinite(ms)) {
      throw new TypeError(`createTestClock: advance(ms) espera un número de milisegundos (llegó ${JSON.stringify(ms)})`)
    }
    current += ms
  }
  clock.now = () => new Date(current)
  clock.at = (offsetMs) => new Date(current + offsetMs)
  return clock
}
