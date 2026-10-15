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

/**
 * **P5-3 (plan 2.5 · lote A, A-3)**: ningún método de DECISIÓN de `src/relations/`
 * ni de los drivers de relaciones llama a `systemClock()`. Las ÚNICAS menciones
 * admitidas son los DEFAULTS (`x ?? systemClock`) y van en lista LITERAL: un
 * método nuevo con `const now = systemClock()` —o un `?? systemClock` nuevo que
 * no esté aquí— es rojo. Es el gemelo del grep de arriba, un nivel más abajo:
 * aquel caza `new Date()`; este caza el atajo de saltarse el reloj inyectado.
 */
const RELATIONS_SOURCES = ['relations/manager.ts', 'relations/reconcile.ts', 'drivers/database_relations_driver.ts', 'drivers/openfga_relations_driver.ts']
const ALLOWED_SYSTEM_CLOCK_MENTIONS: Record<string, string[]> = {
  'relations/manager.ts': ['(this.#options.clock ?? systemClock)()'],
  'relations/reconcile.ts': ['(options.now ?? systemClock)()'],
  // `created_at` es un SELLO de auditoría, no una decisión (2.5-B · K5): va con la hora de pared a propósito.
  'drivers/database_relations_driver.ts': ['this.#now = options.now ?? systemClock', 'created_at: systemClock(),'],
  'drivers/openfga_relations_driver.ts': ['this.#now = options.now ?? systemClock'],
}

test.group('reloj inyectable (2.5 · J1)', () => {
  /**
   * **P5-4 · 🟡 A5 (auditor del lote A)**: `createTestClock` va en un fichero
   * de config que PRODUCCIÓN carga, y `/testing` importa Japa y Lucid. El
   * subpath `/testing/clock` apunta a `src/testing/test_clock.ts`, cuyo grafo
   * de imports RELATIVOS (cerrado transitivamente) no toca `@japa/*`,
   * `@adonisjs/lucid`, `@adonisjs/core` ni ningún módulo de `src/testing/`
   * que los traiga; `/testing` sigue re-exportándolo; y el README importa el
   * ligero en el ejemplo de `config/authorization.ts`.
   */
  test('P5-4 · el subpath /testing/clock existe en package.json, su grafo de imports no toca japa/lucid/core (ni src/testing/main.ts), /testing lo re-exporta y el README importa el ligero en el config', ({ assert }) => {
    const pkg = JSON.parse(fs.readFileSync(path.join(SRC, '..', 'package.json'), 'utf8'))
    assert.equal(pkg.exports['./testing/clock'], './build/src/testing/test_clock.js', 'ROJO (A5): sin subpath ligero')
    assert.equal(pkg.exports['./testing'], './build/src/testing/main.js')
    // Cierre transitivo de los imports relativos desde test_clock.ts.
    const seen = new Set<string>()
    const bare: string[] = []
    const walk = (file: string) => {
      const relative = path.relative(SRC, file)
      if (seen.has(relative)) return
      seen.add(relative)
      const code = stripComments(fs.readFileSync(file, 'utf8'))
      for (const m of code.matchAll(/(?:^|\n)\s*(?:import|export)\b[^'"]*?from\s+['"]([^'"]+)['"]/g)) {
        const spec = m[1]
        if (spec.startsWith('.')) walk(path.resolve(path.dirname(file), spec.replace(/\.js$/, '.ts')))
        else bare.push(`${relative} → ${spec}`)
      }
      for (const m of code.matchAll(/(?:^|\n)\s*import\s+['"]([^'"]+)['"]/g)) bare.push(`${relative} → ${m[1]} (efecto)`)
    }
    walk(path.join(SRC, 'testing', 'test_clock.ts'))
    assert.deepEqual([...seen].sort(), ['clock.ts', 'testing/test_clock.ts'], `el grafo del reloj ligero es exactamente clock.ts + test_clock.ts: ${[...seen].join(', ')}`)
    assert.deepEqual(bare, [], `ROJO (A5): el módulo ligero importa paquetes: ${bare.join('; ')}`)
    assert.isFalse(seen.has('testing/main.ts'))
    // El control: /testing SÍ trae japa y lucid (por eso hace falta el subpath), y re-exporta el ligero.
    const main = fs.readFileSync(path.join(SRC, 'testing', 'main.ts'), 'utf8')
    assert.match(main, /export \{ createTestClock \} from '\.\/test_clock\.js'/)
    const contract = fs.readFileSync(path.join(SRC, 'testing', 'contract.ts'), 'utf8')
    assert.match(contract, /from '@japa\/runner'/, 'el control: /testing tira de Japa')
    // README: el ejemplo del config importa el ligero, nunca /testing.
    const readme = fs.readFileSync(path.join(SRC, '..', 'README.md'), 'utf8')
    const section = readme.slice(readme.indexOf('### Testing expiry from your app'), readme.indexOf('### Testing expiry from your app') + 4000)
    assert.include(section, "import { createTestClock } from '@jantstack/adonis-authz/testing/clock'")
    assert.notInclude(section, "import { createTestClock } from '@jantstack/adonis-authz/testing'\n")
  })

  test('P5-3 · ningún método de src/relations ni de los drivers de relaciones llama a systemClock(): solo los defaults `?? systemClock`, en lista literal', ({ assert }) => {
    for (const relative of RELATIONS_SOURCES) {
      const code = stripComments(fs.readFileSync(path.join(SRC, relative), 'utf8'))
      const lines = code.split('\n').filter((line) => line.includes('systemClock') && !/^\s*import\b/.test(line))
      const mentions = lines.map((line) => line.trim())
      const allowed = ALLOWED_SYSTEM_CLOCK_MENTIONS[relative]
      const direct = mentions.filter((line) => /\bsystemClock\(\)/.test(line) && !allowed.some((a) => line.includes(a)))
      assert.deepEqual(direct, [], `${relative}: llamada DIRECTA a systemClock() en una decisión (usa el reloj inyectado):\n${direct.join('\n')}`)
      const unexpected = mentions.filter((line) => !allowed.some((a) => line.includes(a)))
      assert.deepEqual(unexpected, [], `${relative}: mención de systemClock fuera de la lista literal de defaults:\n${unexpected.join('\n')}`)
      assert.equal(mentions.length, allowed.length, `${relative}: ${allowed.length} default(s) esperado(s), ${mentions.length} mención(es)`)
    }
  })


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
