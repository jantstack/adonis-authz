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

  test('un import dinámico con template literal también es un import (pendiente de Fase 0)', ({ assert }) => {
    // `import(\`#config/${name}\`)` es la forma natural de cargar algo del
    // consumidor por nombre: la regex solo miraba comillas simples y dobles.
    const root = fixture({
      'src/a.ts': 'export const a = (name: string) => import(`#config/${name}`)\n',
      'src/b.ts': 'export const b = () => import(`#services/authz`)\n',
    })
    roots.push(root)
    const result = runPurity(root)
    assert.equal(result.status, 1)
    assert.include(result.output, 'src/a.ts')
    assert.include(result.output, '#config/${name}')
    assert.include(result.output, 'src/b.ts')
  })

  test('un alias mencionado solo en comentarios no es una importación (pendiente de Fase 0)', ({ assert }) => {
    // Explicar en un comentario cómo NO hacerlo (`// nunca import '#config'`)
    // no debe romper el build. Pero un import real detrás de una URL con `//`
    // en la misma línea sí tiene que verse: el stripper respeta strings,
    // template literals y regex, y se prueba en los dos sentidos.
    const clean = fixture({
      'src/a.ts': [
        `// Nunca: import config from '#config/authorization'`,
        `/* Tampoco: import('#services/authz')`,
        `   ni require("#start/kernel") */`,
        `const url = 'http://x/#models/no-es-import' // import '#config/en-comentario'`,
        `const tpl = \`ruta #services/en-template\``,
        `const re = /#config\\//`,
        `export const a = [url, tpl, re]`,
        ``,
      ].join('\n'),
    })
    roots.push(clean)
    const ok = runPurity(clean)
    assert.equal(ok.status, 0, ok.output)

    const dirty = fixture({
      'src/b.ts': [
        `// import x from '#config/comentado'`,
        `const re = /https?:\\/\\//; import y from '#services/real' // import '#models/cola'`,
        `export const b = [re, y]`,
        ``,
      ].join('\n'),
    })
    roots.push(dirty)
    const bad = runPurity(dirty)
    assert.equal(bad.status, 1)
    assert.include(bad.output, '#services/real')
    assert.notInclude(bad.output, '#config/comentado')
    assert.notInclude(bad.output, '#models/cola')
  })

  test('invocado a través de un symlink sigue siendo invocación directa (pendiente de Fase 0)', ({ assert }) => {
    // nvm y `npm link` ponen symlinks en la ruta; si `process.argv[1]` y
    // `import.meta.url` se compararan sin realpath, el script se importaría
    // en silencio y no comprobaría nada. Se demuestra con una violación: a
    // través del symlink tiene que FALLAR con exit 1.
    const root = fixture({
      'src/x.ts': `import config from '#config/authorization'\nexport const x = config\n`,
    })
    roots.push(root)
    const link = path.join(root, 'check_purity_link.mjs')
    fs.symlinkSync(SCRIPT, link)
    let status = 0
    let output = ''
    try {
      output = execFileSync(process.execPath, [link, '--root', root], {
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'pipe'],
      })
    } catch (error: any) {
      status = error.status
      output = `${error.stdout ?? ''}${error.stderr ?? ''}`
    }
    assert.equal(status, 1, output)
    assert.include(output, '#config/authorization')
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

/**
 * Regla 3 (D9): `@openfga/sdk` es un peer OPCIONAL. Solo la entrada del
 * subpath (`src/openfga.ts`), el driver (`src/drivers/openfga_driver.ts`) y
 * los comandos `openfga:*` pueden importarlo o importar el driver; todo lo
 * demás —`index.ts`, el manager, el driver database, el catálogo, la config,
 * providers, services— es la ruta de un consumidor solo-database y no puede
 * tirar de él ni por un import estático ni por un `import()`.
 */
test.group('purity — regla 3: la ruta database no importa openfga', (group) => {
  const roots: string[] = []
  group.teardown(() => {
    for (const root of roots) fs.rmSync(root, { recursive: true, force: true })
  })

  test('index.ts, manager, database_driver, catalog o define_config importando el driver o el SDK hacen fallar el script', ({
    assert,
  }) => {
    const root = fixture({
      'src/drivers/openfga_driver.ts': `import { OpenFgaClient } from '@openfga/sdk'\nexport const D = OpenFgaClient\n`,
      'src/openfga.ts': `export { D } from './drivers/openfga_driver.js'\n`,
      'commands/openfga_import.ts': `export const run = () => import('../src/openfga.js')\n`,
      'index.ts': `export { D } from './src/drivers/openfga_driver.js'\n`,
      'src/manager.ts': `import type { D } from './openfga.js'\nexport const m: D | null = null\n`,
      'src/drivers/database_driver.ts': `export const load = () => import('@openfga/sdk')\n`,
      'src/catalog.ts': `import '@openfga/sdk'\n`,
      'src/define_config.ts': `import type { HolderTypeMap } from './drivers/openfga_driver'\nexport type H = HolderTypeMap\n`,
      'services/main.ts': `export const s = () => import('../src/drivers/openfga_driver.js')\n`,
    })
    roots.push(root)
    const result = runPurity(root)
    assert.equal(result.status, 1)
    for (const file of ['index.ts', 'src/manager.ts', 'src/drivers/database_driver.ts', 'src/catalog.ts', 'src/define_config.ts', 'services/main.ts']) {
      assert.include(result.output, file)
    }
    // Los tres sitios permitidos no aparecen como infractores.
    assert.notInclude(result.output, 'src/openfga.ts →')
    assert.notInclude(result.output, 'src/drivers/openfga_driver.ts →')
    assert.notInclude(result.output, 'commands/openfga_import.ts →')
  })

  test('3E · Q3: index.ts exporta TODOS los errores de src/errors.ts (el 422 que el README manda capturar no puede quedarse dentro)', ({ assert }) => {
    // `AmbiguousRoleError` (3D · M1) se quedó sin exportar: el README pide
    // capturarlo por tipo y el consumidor no lo tenía. La regla se fija aquí
    // en vez de en una lista a mano: cada error nuevo entra o el test falla.
    const root = fileURLToPath(new URL('..', import.meta.url))
    const errors = [...fs.readFileSync(path.join(root, 'src/errors.ts'), 'utf8').matchAll(/^export class (\w+) extends/gm)].map((m) => m[1])
    const index = fs.readFileSync(path.join(root, 'index.ts'), 'utf8')
    const exported = new Set(
      [...index.matchAll(/export \{([^{}]*?)\} from '\.\/src\/errors\.js'/g)]
        .flatMap((m) => m[1].split(','))
        .map((name) => name.trim())
        .filter(Boolean)
    )
    assert.isAbove(errors.length, 20)
    assert.deepEqual(errors.filter((name) => !exported.has(name)), [], 'errores de src/errors.ts que index.ts no exporta')
  })

  test('el paquete real cumple la regla 3 (index.ts no importa el driver openfga)', async ({ assert }) => {
    // Sin comentarios (index.ts EXPLICA en uno por qué no exporta el driver).
    const { stripComments } = (await import(SCRIPT)) as { stripComments(source: string): string }
    const source = stripComments(
      fs.readFileSync(path.join(fileURLToPath(new URL('..', import.meta.url)), 'index.ts'), 'utf8')
    )
    assert.notInclude(source, 'openfga_driver')
    assert.notInclude(source, 'openfga.js')
    assert.notInclude(source, '@openfga/sdk')
  })
})

/**
 * La prueba de carga (D9): un consumidor sin `@openfga/sdk` instalado tiene
 * que poder arrancar con el driver `database`. Se carga `index.ts` en un
 * proceso hijo con el SDK bloqueado por un hook de resolución. La cara de
 * control —`src/openfga.ts` con el mismo bloqueo DEBE fallar— demuestra que
 * el bloqueo actúa y que el subpath es el único que tira del SDK.
 */
test.group('purity — index.ts carga sin @openfga/sdk (D9)', () => {
  const HELPER = fileURLToPath(new URL('../tests/helpers/load_without_sdk.ts', import.meta.url))

  function load(target: string): { status: number; output: string } {
    try {
      const output = execFileSync(process.execPath, ['--import', '@poppinss/ts-exec', HELPER, target], {
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 60_000,
        cwd: fileURLToPath(new URL('..', import.meta.url)),
      })
      return { status: 0, output }
    } catch (error: any) {
      return { status: error.status ?? 1, output: `${error.stdout ?? ''}${error.stderr ?? ''}` }
    }
  }

  test('index.ts (la entrada principal) carga con el SDK bloqueado', ({ assert }) => {
    const result = load('../../index.ts')
    assert.equal(result.status, 0, result.output)
    assert.include(result.output, 'loaded:../../index.ts')
  }).timeout(90_000)

  test('control: src/openfga.ts NO carga con el SDK bloqueado (el bloqueo actúa)', ({ assert }) => {
    const result = load('../../src/openfga.ts')
    assert.notEqual(result.status, 0)
    assert.include(result.output, '@openfga/sdk')
    assert.notInclude(result.output, 'loaded:')
  }).timeout(90_000)
})
