/**
 * Reloj inyectable (2.5 · J1): la hora de pared se lee en UN solo sitio
 * (`src/clock.ts`, `systemClock`). Cualquier otro `new Date()` o `Date.now()`
 * en las fuentes del paquete sería una decisión temporal que ningún test
 * puede fijar sin dormir —exactamente lo que este lote elimina—. El juez
 * (`src/testing/`) queda fuera: sus casos de tiempo real (`Date.now() -
 * 60_000`) son deliberados y los del reloj usan el `now` inyectado.
 *
 * `new Date(valor)` (parsear una fecha) no es leer el reloj y no cuenta.
 */

import { test } from '@japa/runner'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const SRC = fileURLToPath(new URL('../src/', import.meta.url))
const WALL_CLOCK = /\bnew Date\(\s*\)|\bDate\.now\(\s*\)/g
const ALLOWED = new Set(['clock.ts'])

function* sources(dir: string): Generator<string> {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === 'testing') continue
      yield* sources(full)
    } else if (entry.name.endsWith('.ts')) {
      yield full
    }
  }
}

/** Quita comentarios `//` y `/* … *​/` para no contar una mención en prosa. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1')
}

test.group('reloj inyectable (2.5 · J1)', () => {
  test('la hora de pared se lee solo en src/clock.ts: cero new Date()/Date.now() sueltos en src/ (fuera de src/testing)', ({
    assert,
  }) => {
    const offenders: string[] = []
    for (const file of sources(SRC)) {
      const relative = path.relative(SRC, file)
      if (ALLOWED.has(relative)) continue
      const code = stripComments(fs.readFileSync(file, 'utf8'))
      const lines = code.split('\n')
      lines.forEach((line, index) => {
        if (WALL_CLOCK.test(line)) offenders.push(`${relative}:${index + 1}: ${line.trim()}`)
        WALL_CLOCK.lastIndex = 0
      })
    }
    assert.deepEqual(offenders, [], `lecturas del reloj fuera de src/clock.ts:\n${offenders.join('\n')}`)
    // Y el sitio permitido existe y lo lee de verdad (el grep no puede ser vacío por accidente).
    const clock = stripComments(fs.readFileSync(path.join(SRC, 'clock.ts'), 'utf8'))
    assert.match(clock, WALL_CLOCK)
  })
})
