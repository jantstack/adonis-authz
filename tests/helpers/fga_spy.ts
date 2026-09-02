/**
 * Espía sobre el cliente FGA REAL de un driver `openfga` (L-5): sustituye
 * `driver.client` por un Proxy que cuenta CADA método invocado (`write`,
 * `writeTuples`, `deleteTuples`, `read`, `check`, `batchCheck`, `listObjects`…)
 * y delega en el cliente original, así que lo que cuenta son llamadas al
 * servidor (`:8101`), no a un doble. «Cero llamadas» = ni un `Write`, ni un
 * `Read`, ni un `Check`.
 *
 * Los dos drivers guardan el cliente en una propiedad `client` (privada por
 * TypeScript, no por runtime): el driver de roles la envuelve ya con
 * `guardBackendErrors` (otro Proxy), y envolver un Proxy con otro es legal.
 */
export interface FgaClientSpy {
  /** Llamadas por método, en orden. */
  readonly calls: string[]
  /** Total de llamadas al cliente desde el último `reset()`. */
  total(): number
  reset(): void
}

export function spyFgaClient(driver: object): FgaClientSpy {
  const holder = driver as { client: object }
  const original = holder.client
  const calls: string[] = []
  holder.client = new Proxy(original, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver)
      if (typeof value !== 'function' || typeof prop !== 'string') return value
      return (...args: unknown[]) => {
        calls.push(prop)
        return (value as (...a: unknown[]) => unknown).apply(target, args)
      }
    },
  })
  return {
    calls,
    total: () => calls.length,
    reset: () => {
      calls.length = 0
    },
  }
}
