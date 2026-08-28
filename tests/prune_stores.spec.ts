/**
 * `scripts/openfga_prune_stores.mjs` es destructivo (borra stores) y hasta
 * ahora no tenía test: "por defecto solo lista" y "solo con --force y solo
 * por prefijo" eran promesas del comentario de cabecera. Aquí se ejecuta
 * el script real contra un servidor HTTP efímero que imita `GET /stores`
 * (paginado, para que la paginación también se vea) y `DELETE /stores/:id`,
 * y se afirma sobre lo que el servidor recibió.
 */

import { test } from '@japa/runner'
import { execFile } from 'node:child_process'
import http from 'node:http'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

const SCRIPT = fileURLToPath(new URL('../scripts/openfga_prune_stores.mjs', import.meta.url))

const STORES = [
  { id: 'S1', name: 'contract-1' },
  { id: 'S2', name: 'regrant-7' },
  { id: 'S3', name: 'produccion' },
  { id: 'S4', name: 'contract-2' },
  { id: 'S5', name: 'cont' }, // empieza igual, pero no lleva el prefijo entero
]

interface FakeServer {
  url: string
  deleted: string[]
  lists: string[]
  close(): Promise<void>
}

/** Sirve los stores en dos páginas y anota cada DELETE. */
async function fakeOpenFga(): Promise<FakeServer> {
  const deleted: string[] = []
  const lists: string[] = []
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x')
    if (req.method === 'GET' && url.pathname === '/stores') {
      lists.push(url.search)
      const token = url.searchParams.get('continuation_token')
      const body = token
        ? { stores: STORES.slice(3), continuation_token: '' }
        : { stores: STORES.slice(0, 3), continuation_token: 'pagina-2' }
      res.setHeader('content-type', 'application/json')
      res.end(JSON.stringify(body))
      return
    }
    const match = /^\/stores\/([^/]+)$/.exec(url.pathname)
    if (req.method === 'DELETE' && match) {
      deleted.push(match[1])
      res.statusCode = 204
      res.end()
      return
    }
    res.statusCode = 404
    res.end()
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address() as import('node:net').AddressInfo
  return {
    url: `http://127.0.0.1:${port}`,
    deleted,
    lists,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  }
}

/**
 * Asíncrono a propósito: el servidor falso vive en ESTE proceso, y un
 * `execFileSync` bloquearía el event loop mientras el hijo espera su
 * respuesta — un deadlock, no un test lento.
 */
async function runPrune(args: string[]): Promise<{ status: number; output: string }> {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [SCRIPT, ...args], {
      encoding: 'utf-8',
      timeout: 10_000,
      // El script cae a OPENFGA_TEST_URL si no hay --url: que no herede el
      // del entorno de la suite y borre stores de verdad.
      env: { ...process.env, OPENFGA_TEST_URL: 'http://127.0.0.1:9' },
    })
    return { status: 0, output: `${stdout}${stderr}` }
  } catch (error: any) {
    return { status: error.code, output: `${error.stdout ?? ''}${error.stderr ?? ''}` }
  }
}

test.group('openfga_prune_stores', (group) => {
  let server: FakeServer
  group.each.setup(async () => {
    server = await fakeOpenFga()
  })
  group.each.teardown(() => server.close())

  test('sin --force es dry-run: lista (paginando) y no borra nada', async ({ assert }) => {
    const result = await runPrune(['--url', server.url, '--prefix', 'contract-', '--prefix', 'regrant-'])
    assert.equal(result.status, 0, result.output)
    assert.include(result.output, '5 stores, 3 con prefijo')
    assert.include(result.output, 'dry-run')
    assert.lengthOf(server.lists, 2)
    assert.deepEqual(server.deleted, [])
  })

  test('--force borra solo los stores cuyo nombre empieza por un prefijo, en todas las páginas', async ({
    assert,
  }) => {
    const result = await runPrune(['--url', server.url, '--prefix', 'contract-', '--prefix', 'regrant-', '--force'])
    assert.equal(result.status, 0, result.output)
    assert.deepEqual([...server.deleted].sort(), ['S1', 'S2', 'S4'])
    assert.include(result.output, 'borrados 3/3')
  })

  test('--dry-run después de --force gana el último: no borra', async ({ assert }) => {
    const result = await runPrune(['--url', server.url, '--prefix', 'contract-', '--force', '--dry-run'])
    assert.equal(result.status, 0, result.output)
    assert.deepEqual(server.deleted, [])
  })

  test('un prefijo de menos de 4 caracteres se rechaza antes de tocar el servidor', async ({ assert }) => {
    const result = await runPrune(['--url', server.url, '--prefix', 'con', '--force'])
    assert.equal(result.status, 2)
    assert.include(result.output, 'demasiado corto')
    assert.deepEqual(server.lists, [])
    assert.deepEqual(server.deleted, [])
  })

  test('sin ningún --prefix no hace nada', async ({ assert }) => {
    const result = await runPrune(['--url', server.url, '--force'])
    assert.equal(result.status, 2)
    assert.include(result.output, 'al menos un --prefix')
    assert.deepEqual(server.lists, [])
  })

  test('un flag sin valor (--prefix seguido de otro flag, o al final) se rechaza', async ({ assert }) => {
    for (const args of [
      ['--url', server.url, '--prefix', '--force'],
      ['--url', server.url, '--prefix', 'contract-', '--url'],
    ]) {
      const result = await runPrune(args)
      assert.equal(result.status, 2, args.join(' '))
      assert.include(result.output, 'necesita un valor')
    }
    assert.deepEqual(server.lists, [])
  })

  test('un argumento desconocido se rechaza', async ({ assert }) => {
    const result = await runPrune(['--url', server.url, '--prefix', 'contract-', '--all'])
    assert.equal(result.status, 2)
    assert.include(result.output, 'Argumento desconocido')
  })
})
