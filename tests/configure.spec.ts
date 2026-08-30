/**
 * Lo que `node ace configure` publica en el proyecto consumidor tiene que
 * compilar contra el paquete tal como está, y cablear el árbol de scopes en
 * los tres sitios que lo necesitan (C4). Un stub no se ejecuta en ninguna
 * otra parte de la suite: si `defineConfig` gana una clave obligatoria o un
 * driver cambia de opciones, el primero en enterarse sería el consumidor.
 *
 * Se renderizan los dos stubs de config (sin la cabecera de `exports`), se
 * sustituye `#start/env` por un shim mínimo y `@jantstack/adonis-authz` por
 * el `index.ts` del repo, y se pasa `tsc --noEmit` sobre el resultado.
 */

import { test } from '@japa/runner'
import { execFile } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)
const REPO = fileURLToPath(new URL('..', import.meta.url))
const STUBS = path.join(REPO, 'stubs', 'config')

/** El cuerpo del stub: todo lo que sigue a la cabecera `{{{ … }}}`. */
function renderStub(name: string): string {
  const source = fs.readFileSync(path.join(STUBS, name), 'utf8')
  return source.replace(/^\{\{\{[\s\S]*?\}\}\}\n/, '')
}

test.group('configure — stubs publicados', (group) => {
  const authorization = renderStub('authorization.stub')
  let tmp: string
  group.teardown(() => {
    if (tmp) fs.rmSync(tmp, { recursive: true, force: true })
  })

  test('el stub cablea resolveChain en el manager y en los dos drivers, con la misma función', ({
    assert,
  }) => {
    // La costura del árbol es una sola: `scopes.resolveChain` para el
    // manager (validar aristas) y `resolveChain` para cada driver.
    const seam = /scopes:\s*\{\s*resolveChain:\s*(\w+)\s*\}/.exec(authorization)
    assert.exists(seam, 'el stub no declara scopes.resolveChain')
    const fn = seam![1]
    assert.match(authorization, new RegExp(`async function ${fn}\\(scope: ScopeRef\\): Promise<ScopeRef\\[\\] \\| null>`))
    assert.match(authorization, new RegExp(`new DatabaseAuthorizationDriver\\(\\{ resolveChain: ${fn} \\}\\)`))
    assert.match(authorization, new RegExp(`new OpenFgaAuthorizationDriver\\(\\{[\\s\\S]*?resolveChain: ${fn},[\\s\\S]*?\\}\\)`))
    // Y la misma función no aparece con otro nombre en ningún sitio.
    assert.lengthOf(authorization.match(/resolveChain:\s*\w+/g) ?? [], 3)
    // Lo retirado no vuelve: el stub no ofrece `appAccess({ role })`.
    assert.notInclude(authorization, 'role:')
    // El driver openfga entra por su subpath y solo dentro de la factory (D9).
    assert.include(authorization, "await import('@jantstack/adonis-authz/openfga')")
    assert.notMatch(authorization, /^import .*OpenFgaAuthorizationDriver/m)
    assert.include(authorization, 'catalogs: [async () => appAclCatalog()]')
  })

  test('los dos stubs de config compilan contra el paquete (tsc --noEmit)', async ({ assert }) => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'authz-configure-'))
    const write = (relative: string, content: string) => {
      const target = path.join(tmp, relative)
      fs.mkdirSync(path.dirname(target), { recursive: true })
      fs.writeFileSync(target, content)
    }
    write('config/authorization.ts', authorization)
    write('config/app_acl.ts', renderStub('app_acl.stub'))
    // `#start/env` del consumidor: solo `get`, con la firma que usa el stub.
    write(
      'start/env.ts',
      [
        `function get(key: string): string | undefined`,
        `function get(key: string, fallback: string): string`,
        `function get(key: string, fallback?: string): string | undefined {`,
        `  return process.env[key] ?? fallback`,
        `}`,
        `export default { get }`,
        ``,
      ].join('\n')
    )
    write(
      'tsconfig.json',
      JSON.stringify(
        {
          compilerOptions: {
            target: 'ES2022',
            module: 'NodeNext',
            moduleResolution: 'NodeNext',
            strict: true,
            noEmit: true,
            skipLibCheck: true,
            experimentalDecorators: true,
            emitDecoratorMetadata: true,
            baseUrl: '.',
            paths: {
              '#start/env': ['./start/env.ts'],
              '#config/app_acl': ['./config/app_acl.ts'],
              '@jantstack/adonis-authz': [path.join(REPO, 'index.ts')],
              '@jantstack/adonis-authz/openfga': [path.join(REPO, 'src', 'openfga.ts')],
            },
          },
          include: ['config/*.ts', 'start/*.ts'],
        },
        null,
        2
      )
    )

    const tsc = path.join(REPO, 'node_modules', 'typescript', 'bin', 'tsc')
    let output = ''
    let status = 0
    try {
      const result = await execFileAsync(process.execPath, [tsc, '-p', path.join(tmp, 'tsconfig.json')], {
        encoding: 'utf-8',
        timeout: 60_000,
      })
      output = `${result.stdout}${result.stderr}`
    } catch (error: any) {
      status = error.code
      output = `${error.stdout ?? ''}${error.stderr ?? ''}`
    }
    assert.equal(status, 0, output)
  }).timeout(90_000)
})
