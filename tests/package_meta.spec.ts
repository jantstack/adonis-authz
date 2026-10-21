/**
 * **Lote «antes de RC» · 7.1–7.3 — los metadatos del paquete** (decisión del dueño 2026-10-17 (7.1–7.3); plan del juez
 * `loteRC-plan-juez.md` §5, puntos 5 y 7). Lo que `package.json`/`tsconfig.json` prometen, fijado: Node ≥ 22, el SDK de
 * OpenFGA como peer OPCIONAL con rango acotado, y el build sin mapas. El tarball real (`npm pack --dry-run` sin `*.map`
 * ni `sourceMappingURL`) lo comprueba el job `compat` de CI sobre el build que emite; aquí, la fuente que lo decide.
 */
import { test } from '@japa/runner'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const ROOT = fileURLToPath(new URL('../', import.meta.url))
const json = (file: string) => JSON.parse(readFileSync(`${ROOT}${file}`, 'utf8'))

test.group('7.1–7.3 · metadatos del paquete', () => {
  test('7.1 · engines.node es >=22 (lo que corren COGNITIV, la suite y CI); package-lock.json dice lo mismo', ({ assert }) => {
    assert.equal(json('package.json').engines?.node, '>=22')
    assert.equal(json('package-lock.json').packages[''].engines?.node, '>=22')
  })

  test('7.2 · @openfga/sdk es peer OPCIONAL con rango >=0.9.6 <0.10.0 (0.9.5 corrige authorizationModelId en batchCheck; 0.9.6 es lo probado); la devDependency cae dentro', ({ assert }) => {
    const pkg = json('package.json')
    assert.equal(pkg.peerDependencies?.['@openfga/sdk'], '>=0.9.6 <0.10.0')
    assert.deepEqual(pkg.peerDependenciesMeta?.['@openfga/sdk'], { optional: true })
    assert.equal(json('package-lock.json').packages[''].peerDependencies?.['@openfga/sdk'], '>=0.9.6 <0.10.0')
    const installed = json('node_modules/@openfga/sdk/package.json').version as string
    const [major, minor, patch] = installed.split('.').map(Number)
    assert.isTrue(major === 0 && minor === 9 && patch >= 6, `el SDK instalado (${installed}) está en el rango declarado`)
  })

  test('7.3 · el build no emite mapas: tsconfig.json sin sourceMap ni declarationMap (y nadie los reactiva en tsconfig.test.json)', ({ assert }) => {
    for (const file of ['tsconfig.json', 'tsconfig.test.json']) {
      const options = json(file).compilerOptions ?? {}
      assert.notProperty(options, 'sourceMap', `${file}: sourceMap`)
      assert.notProperty(options, 'declarationMap', `${file}: declarationMap`)
      assert.notProperty(options, 'inlineSourceMap', `${file}: inlineSourceMap`)
    }
  })
})
