/**
 * **R3 · la letra con dientes** (lote «antes de RC» · R3, decisiones del dueño 2026-10-17 (3) y (4)): el README dice la
 * clasificación que hace el código —la tabla de clases, el código propio de `resolution_too_complex`, «no es
 * transitorio» para el despliegue y transitorio para el relay— y ya no dice la frase vieja («a per-check `error` …
 * is a 503 too»), que R3 hizo falsa. Y el código nuevo sale por la raíz del paquete.
 */
import { test } from '@japa/runner'
import { readFile } from 'node:fs/promises'
import * as root from '../index.js'
import { ResolutionLimitError } from '../src/errors.js'

const read = (path: string) => readFile(new URL(`../${path}`, import.meta.url), 'utf8')

test.group('R3 · letra de la clasificación de fallos de OpenFGA', () => {
  test('README: la sección de clases, la fila E_AUTHZ_RESOLUTION_LIMIT, el despliegue 500 «not transient» y transitorio para el relay, «Limits» con el código; fuera la frase «a per-check error … is a 503 too»', async ({ assert }) => {
    const readme = await read('README.md')
    assert.include(readme, '### How OpenFGA failures are classified (2.5.0-alpha.4)')
    assert.include(readme, '| `E_AUTHZ_RESOLUTION_LIMIT` | 503 |')
    assert.include(readme, 'never by the message')
    assert.include(readme, '500 `E_AUTHZ_CONFIG`, "not transient"')
    assert.include(readme, 'does **not** consume an attempt')
    assert.include(readme, '`authorize` is 503 `E_AUTHZ_RESOLUTION_LIMIT`')
    assert.include(readme, 'answers 503 `E_AUTHZ_RESOLUTION_LIMIT` — never `false` — past it')
    assert.include(readme, '(#how-openfga-failures-are-classified-250-alpha4)')
    assert.notInclude(readme, 'a per-check `error` inside a 200 `batchCheck` is a 503 too', 'la frase vieja del invariante 5 es falsa desde R3')
    assert.notInclude(readme, 'A 503 that is not a timeout (connection refused) means the write did not happen', 'la conexión rechazada es timeout (conservadora) desde R3')
    // Cierre de R3 (🟡 R3-A2): la frase de README:284 dice QUÉ 5xx de una escritura son indeterminados.
    assert.include(readme, 'on a **write**, the server\'s own deadline (`deadline_exceeded`) and a **504** from a gateway or proxy in front of it are timeouts too')
    assert.include(readme, 'Every other 5xx on a write (500, 502, 503, 501) keeps "did not happen"')
    // Cierre de R3 (🟠 R3-A1): la carrera NO consume intento; y lo transitorio para siempre no aparca (⚪ R3-A5).
    assert.include(readme, '| race with another writer | 409; 400 `write_failed_due_to_invalid_input` | handled by the driver (re-read and re-apply); if it escapes, 409 `E_AUTHZ_WRITE_CONFLICT` | does **not** consume an attempt either')
    assert.notInclude(readme, '| consumes an attempt |', 'ninguna clase de OpenFGA consume intento en el relay')
    assert.include(readme, 'An alert that watches only `dead()` does not see it.')
  })

  test('CHANGELOG (alpha.4) y CLAUDE.md (invariante 5, letra aprobada por el dueño)', async ({ assert }) => {
    const changelog = await read('CHANGELOG.md')
    const unreleased = changelog.slice(0, changelog.indexOf('## [2.5.0-alpha.3]'))
    assert.include(unreleased, '### Sub-lot 2 · R3')
    assert.include(unreleased, '`E_AUTHZ_RESOLUTION_LIMIT`')
    const guide = await read('CLAUDE.md')
    assert.include(guide, 'despliegue mal configurado ⇒ 500 `E_AUTHZ_CONFIG` (transitorio para el relay); grafo demasiado profundo ⇒ 503')
  })

  test('ResolutionLimitError sale por la raíz: 503, E_AUTHZ_RESOLUTION_LIMIT, subclase de AuthorizationBackendError', ({ assert }) => {
    assert.strictEqual((root as any).ResolutionLimitError, ResolutionLimitError)
    const error = new ResolutionLimitError('openfga', 'check')
    assert.equal(error.status, 503)
    assert.equal(error.code, 'E_AUTHZ_RESOLUTION_LIMIT')
    assert.instanceOf(error, root.AuthorizationBackendError)
    assert.include(error.message, 'Limits')
    // R1 (decisión 5: el 503 de lectura «con la misma letra» que el 422 de escritura; cierre, R del tester): nombra el
    // mando de la app y el del servidor.
    assert.include(error.message, 'maxGroupDepth')
    assert.include(error.message, 'OPENFGA_RESOLVE_NODE_LIMIT')
  })
})
