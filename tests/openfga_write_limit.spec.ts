/**
 * **Plan 2.5 · lote D · D2 — el gemelo de ROLES de N3** (cierre 2 de D1 · ⚪ N3 lo cerró solo en relaciones; addendum del
 * coordinador para D2). Un OpenFGA arrancado con `--max-tuples-per-write` < 100 rechaza con un 400
 * `exceeded_entity_limit` los `Write` que el driver de ROLES parte en lotes de 100 (`projectCatalog`, `reconcile`,
 * `purgeScope`). Hasta D2 salía como 503 `E_AUTHZ_BACKEND_UNAVAILABLE` — «reintenta» — y repetido fallaba igual para
 * siempre. Ahora es 500 `E_AUTHZ_CONFIG` con la letra del requisito, decidido en el PUNTO DE PASO ÚNICO del cliente
 * (`guardBackendErrors`), con la MISMA función que relaciones (`isServerWriteLimit`, `src/shared/backend_guard.ts`).
 *
 * Sin servidor: un HTTP falso que responde a `POST /stores/:id/write` con el 400 en la forma MEDIDA en v1.19.0, de modo
 * que el error que llega es el `FgaApiValidationError` REAL que construye el SDK.
 */
import { test } from '@japa/runner'
import http from 'node:http'
import { v7 as uuidv7 } from 'uuid'
import { isServerWriteLimit } from '../src/shared/backend_guard.js'
import { OpenFgaAuthorizationDriver } from '../src/drivers/openfga_driver.js'

const STORE = '01ARZ3NDEKTSV4RRFFQ69G5FAV'

async function limitedServer(tuples: Array<{ user: string; relation: string; object: string }>) {
  const seen: string[] = []
  const server = http.createServer((req, res) => {
    let body = ''
    req.on('data', (c) => (body += c))
    req.on('end', () => {
      const path = req.url?.split('?')[0]
      seen.push(`${req.method} ${path}`)
      res.setHeader('content-type', 'application/json')
      if (req.method === 'POST' && path === `/stores/${STORE}/read`) {
        const filter = JSON.parse(body || '{}').tuple_key ?? {}
        const out = tuples.filter((t) => (!filter.object || t.object === filter.object) && (!filter.relation || t.relation === filter.relation))
        res.statusCode = 200
        return res.end(JSON.stringify({ tuples: out.map((key) => ({ key, timestamp: new Date().toISOString() })), continuation_token: '' }))
      }
      if (req.method === 'POST' && path === `/stores/${STORE}/write`) {
        res.statusCode = 400
        return res.end(JSON.stringify({ code: 'exceeded_entity_limit', message: 'The number of write operations exceeds the allowed limit of 50' }))
      }
      res.statusCode = 404
      res.end(JSON.stringify({ code: 'undefined_endpoint', message: 'fake' }))
    })
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  return { url: `http://127.0.0.1:${(server.address() as any).port}`, seen, close: () => new Promise<void>((r) => server.close(() => r())) }
}

test.group('D2 · gemelo de roles de N3 · el tope de operaciones por Write del servidor ⇒ 500 E_AUTHZ_CONFIG con letra (no un 503 «transitorio»)', () => {
  test('isServerWriteLimit (compartida por los DOS puertos): el error del SDK o envuelto en su cause; un 400 cualquiera no', ({ assert }) => {
    const sdk = { statusCode: 400, apiErrorCode: 'exceeded_entity_limit' }
    assert.isTrue(isServerWriteLimit(sdk))
    assert.isTrue(isServerWriteLimit({ status: 503, cause: sdk }))
    assert.isFalse(isServerWriteLimit({ statusCode: 400, apiErrorCode: 'validation_error' }))
    assert.isFalse(isServerWriteLimit(null))
  })

  test('purgeScope de roles contra un servidor con --max-tuples-per-write < 100 ⇒ 500 E_AUTHZ_CONFIG que nombra el requisito; el SDK llegó a la red (es el error REAL)', async ({ assert }) => {
    const scope = { type: 'unit', uuid: uuidv7() }
    const server = await limitedServer([{ user: 'user:u1', relation: 'denied_docs_read', object: `scope:unit|${scope.uuid}` }])
    try {
      const driver = new OpenFgaAuthorizationDriver({
        apiUrl: server.url,
        storeId: STORE,
        holderTypes: { users: 'user' },
        acceptScopeDriftRisk: true,
        logger: { warn: () => {} },
      } as any)
      const error = await driver.purgeScope(scope).then(
        () => null,
        (e) => e
      )
      assert.isTrue(server.seen.includes(`POST /stores/${STORE}/write`), `el Write llegó al servidor: ${server.seen.join(', ')}`)
      assert.equal(error?.status, 500, `ROJO (gemelo N3): ${error?.code} ${error?.message}`)
      assert.equal(error?.code, 'E_AUTHZ_CONFIG')
      for (const phrase of ['exceeded_entity_limit', 'The number of write operations exceeds the allowed limit of 50', '--max-tuples-per-write ≥ 100', 'No es transitorio']) {
        assert.include(String(error?.message), phrase)
      }
    } finally {
      await server.close()
    }
  })
})
