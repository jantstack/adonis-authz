/**
 * **El corredor de mutantes de la guardia, juzgado** (cierre 6 de D2 · ⚪ D5-5 del auditor). En el modo filtrado (G1) cada
 * mutante se juzga por los títulos de su `expectRed` AISLADOS; un caso que esté rojo aislado sin mutar «mataría» siempre a
 * sus mutantes. La línea base FILTRADA lo caza: con la sonda (`tests/fixtures/guard_baseline_probe.*`: un caso verde en
 * el spec entero y rojo aislado, y un mutante que no cambia nada) el corredor tiene que salir ≠ 0 SIN declararlo
 * «muerto»; hasta el cierre 6 salía 0 con «1 muertos / 1».
 */
import { test } from '@japa/runner'
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('..', import.meta.url))

test.group('corredor de mutantes · línea base FILTRADA (cierre 6 de D2 · D5-5)', () => {
  test('un caso de expectRed ROJO aislado sin mutar (verde en el spec entero) ⇒ el corredor filtrado sale ≠ 0 nombrándolo, y no juzga el mutante como «muerto»', ({ assert }) => {
    const env: NodeJS.ProcessEnv = { ...process.env, AUTHZ_GUARD_BASELINE_PROBE: '1' }
    delete env.TEST_DB
    const run = spawnSync(
      process.execPath,
      [
        'scripts/check_guard_mutants.mjs',
        '--manifest=tests/fixtures/guard_baseline_probe.mutants.json',
        '--spec=tests/fixtures/guard_baseline_probe.spec.ts',
        '--jobs=1',
      ],
      { cwd: ROOT, env, encoding: 'utf8', timeout: 120_000 }
    )
    const out = `${run.stdout}\n${run.stderr}`
    assert.include(out, 'línea base verde: 2 casos', `la línea base ENTERA está verde (el caso solo falla aislado): ${out.slice(-1500)}`)
    assert.notEqual(run.status, 0, `ROJO (D5-5): el corredor filtrado da por muerto un mutante que no cambia nada: ${out.slice(-1500)}`)
    assert.include(out, 'la línea base FILTRADA no está verde')
    assert.include(out, 'ROJO aislado: sonda · B depende de A')
    assert.notInclude(out, '✔ probe.noop — muerto')
  }).timeout(150_000)
})

test.group('CI · el schedule nocturno lanza SOLO guard-mutants-full (cierre 6 de D2)', () => {
  test('cada job del workflow lleva su condición de evento: guard-mutants-full solo en schedule/workflow_dispatch, todos los demás con `if: github.event_name != \'schedule\'`', ({ assert }) => {
    const text = readFileSync(new URL('../.github/workflows/ci.yml', import.meta.url), 'utf8')
    assert.match(text, /\n  schedule:\n    - cron: /, 'el disparador nocturno existe')
    const lines = text.split('\n')
    const start = lines.indexOf('jobs:')
    const jobs = new Map<string, string[]>()
    let current: string | null = null
    for (const line of lines.slice(start + 1)) {
      const key = /^  ([a-z0-9-]+):$/.exec(line)
      if (key) jobs.set((current = key[1]), [])
      else if (current && /^\S/.test(line)) current = null
      else if (current) jobs.get(current)!.push(line)
    }
    assert.isAbove(jobs.size, 2)
    const ifOf = (body: string[]) => body.find((l) => /^    if: /.test(l))?.trim()
    for (const [name, body] of jobs) {
      if (name === 'guard-mutants-full') {
        assert.equal(ifOf(body), "if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'")
      } else {
        assert.equal(ifOf(body), "if: github.event_name != 'schedule'", `ROJO: el job ${name} corre también en el schedule nocturno`)
      }
    }
  })
})
