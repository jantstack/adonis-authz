/**
 * **La red de los stores de OpenFGA** (3b-4 · C5) — la misma que `bootApp`
 * tiene para la base SQL, y que faltaba aquí.
 *
 * El goteo de stores en el `:8101` **no viene del uso normal**: una corrida
 * que termina no deja nada (medido por el tester de la fase: 1 store antes,
 * 754 casos, 1 store después). Viene de las corridas **INTERRUMPIDAS** —un
 * `Ctrl-C`, un `pkill`, un `.spec.ts` que revienta al importarse—, donde el
 * `teardown` de los grupos no llega a correr y cada store creado se queda.
 * Así se llegó a 60 stores y 7,9 GB de RAM en el servidor de desarrollo.
 *
 * `bin/test.ts` ya tenía red para la base SQL (`run().finally(app.teardown)`)
 * y ninguna para los stores. Esta es esa red, con la misma forma que el guard
 * síncrono que el lote 3b-1 metió en `bootApp`:
 *
 *  - al arrancar se toma una FOTO de los stores que ya existían;
 *  - `process.on('exit')` —lo único que corre cuando alguien llama a
 *    `process.exit()`, y solo admite trabajo SÍNCRONO— lanza un `spawnSync`
 *    de `delete_stores.mjs`, que borra los que NO estaban en la foto **y**
 *    se crearon después de arrancar. Las dos condiciones: un guard que
 *    borrase por prefijo se llevaría los stores de otra suite corriendo al
 *    lado en el mismo servidor.
 *  - y AVISA por stderr, para que una fuga no vuelva a ser silenciosa.
 */

import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const SCRIPT = fileURLToPath(new URL('./delete_stores.mjs', import.meta.url))

export interface OpenFgaStoreGuard {
  /** Los que ya estaban: esos no se tocan pase lo que pase. */
  baseline: string[]
  /** Borra lo que esta ejecución dejó y desarma el guard. Idempotente. */
  sweep(): Promise<number>
  /** Desarma sin borrar (para cuando ya se ha barrido). */
  disarm(): void
}

async function listStoreIds(apiUrl: string): Promise<string[]> {
  const ids: string[] = []
  let token = ''
  do {
    const query = `page_size=100${token ? `&continuation_token=${encodeURIComponent(token)}` : ''}`
    const response = await fetch(`${apiUrl}/stores?${query}`)
    if (!response.ok) throw new Error(`GET /stores → ${response.status}`)
    const body: any = await response.json()
    for (const store of body.stores ?? []) ids.push(store.id)
    token = body.continuation_token ?? ''
  } while (token)
  return ids
}

/**
 * Arma la red. Devuelve `undefined` si el servidor no responde: la suite
 * corre sin OpenFGA a propósito, y una red que no se puede armar no puede
 * tumbar la ejecución — pero se dice por stderr.
 */
export async function armOpenFgaStoreGuard(apiUrl: string): Promise<OpenFgaStoreGuard | undefined> {
  let baseline: string[]
  const since = new Date(Date.now() - 1000).toISOString()
  try {
    baseline = await listStoreIds(apiUrl)
  } catch (error: any) {
    process.stderr.write(`[stores] no se pudo tomar la foto de ${apiUrl}: ${error?.message ?? error}\n`)
    return undefined
  }
  const payload = JSON.stringify({ url: apiUrl, baseline, since })
  let armed = true
  const onExit = () => {
    if (!armed) return
    armed = false
    process.stderr.write(
      `\n[stores] el proceso salió SIN barrer los stores de OpenFGA (¿process.exit? ¿Ctrl-C?): ` +
        `borrándolos desde el guard de salida.\n`
    )
    const done = spawnSync(process.execPath, [SCRIPT, payload], { stdio: 'inherit', timeout: 30_000 })
    if (done.status !== 0) {
      process.stderr.write(
        `[stores] NO se pudieron borrar: pásale el prefijo a scripts/openfga_prune_stores.mjs --force.\n`
      )
    }
  }
  process.on('exit', onExit)
  return {
    baseline,
    disarm() {
      armed = false
      process.off('exit', onExit)
    },
    async sweep() {
      if (!armed) return 0
      armed = false
      process.off('exit', onExit)
      let left: string[]
      try {
        left = (await listStoreIds(apiUrl)).filter((id) => !baseline.includes(id))
      } catch {
        return 0
      }
      for (const id of left) {
        await fetch(`${apiUrl}/stores/${id}`, { method: 'DELETE' }).catch(() => {})
      }
      if (left.length) {
        process.stderr.write(`[stores] la suite dejó ${left.length} store(s) sin borrar; barridos.\n`)
      }
      return left.length
    },
  }
}
