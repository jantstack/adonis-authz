/**
 * Espías de backend para la suite del paquete.
 *
 * Sirven para dos preguntas que las aserciones de resultado no responden:
 * "¿qué pasa si esta llamada falla?" (`withFailing`) y "¿cuántas veces se
 * tocó el backend?" (`countCalls`). La segunda documenta el COSTE de cada
 * operación: cuando una fase lo cambie (memo de catálogo, batch único, modo
 * facts) el test correspondiente cambiará a sabiendas, no por accidente.
 *
 * Trabajan sobre propiedades de un objeto y las restauran al terminar: valen
 * para el cliente FGA (`driver['client']`, un Proxy cuyas propiedades son
 * asignables), para un `db` envuelto o para un contenedor `{ resolveAncestors }`
 * que el driver invoque de forma tardía (`(s) => holder.resolveAncestors(s)`).
 */

type AnyFn = (...args: any[]) => any

/** Hace que `obj[method]` lance durante `fn`; luego lo restaura. */
export async function withFailing<T>(
  obj: any,
  method: string,
  fn: () => Promise<T>,
  error: Error = new Error(`${method} caído`)
): Promise<T> {
  const original = obj[method]
  obj[method] = async () => {
    throw error
  }
  try {
    return await fn()
  } finally {
    obj[method] = original
  }
}

export interface CallCounter {
  counts: Record<string, number>
  /** Vuelve a cero sin dejar de contar. */
  reset(): void
  /** Devuelve los métodos originales al objeto. */
  restore(): void
}

/** Cuenta las llamadas a `methods` de `obj` hasta `restore()`. */
export function countCalls(obj: any, methods: string[]): CallCounter {
  const counts: Record<string, number> = Object.fromEntries(methods.map((m) => [m, 0]))
  const originals: Record<string, AnyFn> = {}
  for (const method of methods) {
    const original: AnyFn = obj[method]
    originals[method] = original
    obj[method] = function (this: any, ...args: any[]) {
      counts[method] += 1
      return original.apply(this === undefined ? obj : this, args)
    }
  }
  return {
    counts,
    reset() {
      for (const method of methods) counts[method] = 0
    },
    restore() {
      for (const method of methods) obj[method] = originals[method]
    },
  }
}

/**
 * Cuenta las consultas SQL que knex ejecuta mientras corre `fn`, anotando el
 * `timeout` con el que se lanzó cada una. Sirve para afirmar "0 consultas"
 * (una pregunta mal formada no toca la base) y "todas con deadline".
 */
export async function countQueries<T>(
  fn: () => Promise<T>
): Promise<{ result: T; queries: Array<{ sql: string; timeout: number | false }> }> {
  const { default: db } = await import('@adonisjs/lucid/services/db')
  const knex = db.connection().getWriteClient()
  const queries: Array<{ sql: string; timeout: number | false }> = []
  const listener = (query: any) => queries.push({ sql: query.sql, timeout: query.timeout ?? false })
  knex.on('query', listener)
  try {
    const result = await fn()
    return { result, queries }
  } finally {
    knex.removeListener('query', listener)
  }
}
