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
import { AuthorizationManager } from '../src/manager.js'
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
    const seam = /scopes:\s*\{\s*resolveChain:\s*(\w+)\s*[,}]/.exec(authorization)
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

  /**
   * **3b-8 · C1 — el stub firma la mitigación DONDE EL MANAGER LA LEE.** El
   * gate de la deriva del árbol está en el manager (3b-2e · E3) y mira
   * `config.scopes.outbox` / `config.scopes.acceptScopeDriftRisk`; el stub
   * la firmaba solo DENTRO de la factory del driver openfga (que es el gate
   * del driver, otro). Resultado: una app recién scaffoldeada con
   * AUTHZ_DRIVER=openfga daba 500 `E_AUTHZ_SCOPE_DRIFT_UNGUARDED` en CADA
   * request, hasta editar a mano una config que los comentarios del stub ni
   * mencionaban.
   */
  test('3b-8 · C1: la sección `scopes` del stub lleva una mitigación del gate del MANAGER (arrancar en modo openfga no es un 500 por request)', ({
    assert,
  }) => {
    // Solo el objeto `scopes: { … }` (sin llaves anidadas): la firma dentro
    // de la factory del driver NO cuenta — esa es la confusión del hallazgo.
    const scopesBlock = /scopes:\s*\{[^{}]*\}/.exec(authorization)
    assert.exists(scopesBlock, 'el stub declara la sección scopes')
    assert.match(
      scopesBlock![0],
      /acceptScopeDriftRisk:\s*true|outbox:/,
      'el gate del manager lee config.scopes, no las opciones del driver: la firma tiene que estar AQUÍ (3b-8 · C1)'
    )
    // Y el mecanismo que el stub tiene que satisfacer, demostrado: la MISMA
    // forma de `scopes` que publica el stub pasa el gate; sin la firma, no.
    const factsDriver = () =>
      ({
        capabilities: { hierarchyFacts: true },
        withClock() {
          return this
        },
      }) as any
    const conFirma = new AuthorizationManager({
      default: 'openfga',
      drivers: { openfga: factsDriver },
      holderTypes: { users: 'user' },
      scopes: { resolveChain: async () => null, acceptScopeDriftRisk: true },
      warnOnOptInSecurity: false,
    } as any)
    const sinFirma = new AuthorizationManager({
      default: 'openfga',
      drivers: { openfga: factsDriver },
      holderTypes: { users: 'user' },
      scopes: { resolveChain: async () => null },
      warnOnOptInSecurity: false,
    } as any)
    return conFirma.driver().then(
      () =>
        sinFirma.driver().then(
          () => assert.fail('sin la firma en config.scopes el gate tenía que dar 500'),
          (error: any) => assert.equal(error.code, 'E_AUTHZ_SCOPE_DRIFT_UNGUARDED')
        ),
      (error: any) => assert.fail(`la forma del stub tiene que pasar el gate del manager: ${error.message}`)
    )
  })

  /**
   * **alpha.3 · A5 — un solo home para los hooks de relaciones (D-4).** El
   * stub declara `assertWrite` (de ejemplo, comentado), `onRelationWrite` y
   * `requireActor` DENTRO del bloque `relations`, y NO en `hooks`: dos homes
   * obligan a una regla de precedencia (fábrica de bugs). Que compile lo fija
   * el caso de `tsc --noEmit` de abajo (si `defineConfig` no gana las claves,
   * no compila: el diente de TIPOS del lote).
   */
  test('alpha.3 · A5: el stub declara assertWrite / onRelationWrite / requireActor en el bloque `relations` y NO en `hooks` (un solo home, D-4)', ({
    assert,
  }) => {
    // El bloque `relations: { … }` del `defineConfig` (con llaves anidadas: drivers, factories).
    const start = authorization.search(/^  relations:\s*\{/m)
    assert.isAbove(start, -1, 'el stub declara la sección relations')
    const hooksStart = authorization.search(/^  hooks:\s*\{/m)
    assert.isAbove(hooksStart, start, 'hooks va después de relations en el stub')
    const relationsBlock = authorization.slice(start, hooksStart)
    const hooksBlock = authorization.slice(hooksStart)
    assert.match(relationsBlock, /^\s*onRelationWrite:\s*(\w+)\s*,?$/m, 'relations.onRelationWrite cableado en el stub')
    const hook = /^\s*onRelationWrite:\s*(\w+)\s*,?$/m.exec(relationsBlock)![1]
    assert.match(authorization, new RegExp(`async function ${hook}\\(event: RelationWriteEvent\\)`), 'el hook de ejemplo recibe RelationWriteEvent')
    assert.include(relationsBlock, 'assertWrite', 'relations.assertWrite documentado (de ejemplo) en el bloque')
    assert.include(relationsBlock, 'requireActor', 'relations.requireActor documentado en el bloque')
    // Un solo home: nada de relaciones en `hooks`.
    assert.notInclude(hooksBlock, 'onRelationWrite', 'hooks.onRelationWrite NO existe (dos homes = regla de precedencia)')
    assert.notInclude(hooksBlock, 'assertWrite')
    // Y `onRelationWrite:` aparece UNA vez en todo el stub.
    assert.lengthOf(authorization.match(/onRelationWrite:/g) ?? [], 1)
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
