/**
 * `scripts/check_purity.mjs` es parte de la suite, no solo del build: si el
 * paquete importa algo del consumidor o un módulo se acopla al manager/driver,
 * `npm test` tiene que caer. Como no se puede dejar una violación en el repo
 * para comprobarlo, cada caso construye un mini-paquete en un directorio
 * temporal y apunta el script allí con `--root`.
 */

import { test } from '@japa/runner'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const SCRIPT = fileURLToPath(new URL('../scripts/check_purity.mjs', import.meta.url))

/** Crea un árbol de archivos `{ 'src/x.ts': 'contenido' }` en un tmp nuevo. */
function fixture(files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'authz-purity-'))
  for (const [relative, content] of Object.entries(files)) {
    const target = path.join(root, relative)
    fs.mkdirSync(path.dirname(target), { recursive: true })
    fs.writeFileSync(target, content)
  }
  return root
}

/** Ejecuta el script como lo hace `npm test`; devuelve exit code y salida. */
function runPurity(root: string, args: string[] = []): { status: number; output: string } {
  try {
    const output = execFileSync(process.execPath, [SCRIPT, '--root', root, ...args], {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    return { status: 0, output }
  } catch (error: any) {
    return { status: error.status, output: `${error.stdout ?? ''}${error.stderr ?? ''}` }
  }
}

test.group('purity', (group) => {
  const roots: string[] = []
  group.teardown(() => {
    for (const root of roots) fs.rmSync(root, { recursive: true, force: true })
  })

  test('un paquete limpio pasa', ({ assert }) => {
    const root = fixture({
      'src/types.ts': `export interface Port {}\n`,
      'src/manager.ts': `import type { Port } from './types.js'\nexport class Manager {}\n`,
    })
    roots.push(root)
    const result = runPurity(root)
    assert.equal(result.status, 0, result.output)
  })

  test('importar un alias del consumidor (#config) hace fallar el script', ({ assert }) => {
    const root = fixture({
      'src/drivers/x.ts': `import config from '#config/authorization'\nexport const x = config\n`,
    })
    roots.push(root)
    const result = runPurity(root)
    assert.equal(result.status, 1)
    assert.include(result.output, 'src/drivers/x.ts')
    assert.include(result.output, '#config/authorization')
  })

  test('un alias con comillas dobles o en import dinámico también falla', ({ assert }) => {
    const root = fixture({
      'src/a.ts': `import config from "#config/authorization"\nexport const a = config\n`,
      'src/b.ts': `export const b = () => import('#services/authz')\n`,
      'src/c.ts': `import '#start/kernel'\n`,
    })
    roots.push(root)
    const result = runPurity(root)
    assert.equal(result.status, 1)
    assert.include(result.output, 'src/a.ts')
    assert.include(result.output, 'src/b.ts')
    assert.include(result.output, 'src/c.ts')
  })

  test('un módulo conocido bajo src/ se vigila sin declararlo; sin extensión y dinámico también', ({
    assert,
  }) => {
    // `catalog` está en la lista de módulos conocidos: basta con que exista.
    const root = fixture({
      'src/manager.ts': `export class Manager {}\n`,
      'src/drivers/openfga_driver.ts': `export class D {}\n`,
      'src/catalog/index.ts': [
        `import { Manager } from "../manager"`,
        `export const load = () => import('../drivers/openfga_driver.js')`,
        `export const m = Manager`,
        ``,
      ].join('\n'),
    })
    roots.push(root)
    const result = runPurity(root)
    assert.equal(result.status, 1)
    assert.include(result.output, 'src/catalog/index.ts')
    assert.include(result.output, 'src/manager')
    assert.include(result.output, 'src/drivers/openfga_driver')
  })

  test('un módulo que importa el manager o un driver hace fallar el script', ({ assert }) => {
    const root = fixture({
      'src/manager.ts': `export class Manager {}\n`,
      'src/drivers/database_driver.ts': `export class DatabaseDriver {}\n`,
      'src/relations/index.ts': [
        `import { Manager } from '../manager.js'`,
        `import { DatabaseDriver } from '../drivers/database_driver.js'`,
        `export const r = [Manager, DatabaseDriver]`,
        ``,
      ].join('\n'),
    })
    roots.push(root)
    const result = runPurity(root, ['--module', 'relations'])
    assert.equal(result.status, 1)
    assert.include(result.output, 'src/relations/index.ts')
    // Se reporta el destino sin extensión (`../manager` ≡ `../manager.js`).
    assert.include(result.output, 'src/manager')
    assert.include(result.output, 'src/drivers/database_driver')
  })

  test('un módulo que solo depende del puerto, errores y shared pasa', ({ assert }) => {
    const root = fixture({
      'src/types.ts': `export interface Port {}\n`,
      'src/errors.ts': `export class E extends Error {}\n`,
      'src/shared/keys.ts': `export const k = 1\n`,
      'src/manager.ts': `export class Manager {}\n`,
      'src/relations/index.ts': [
        `import type { Port } from '../types.js'`,
        `import { E } from '../errors.js'`,
        `import { k } from '../shared/keys.js'`,
        `export const r = [E, k] as [E, number] & { port?: Port }`,
        ``,
      ].join('\n'),
    })
    roots.push(root)
    const result = runPurity(root, ['--module', 'relations'])
    assert.equal(result.status, 0, result.output)
  })
})
