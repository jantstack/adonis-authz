import {
  AuthorizationBackendError,
  AuthorizationBackendTimeoutError,
  ScopeResolverError,
} from '../errors.js'
import type { ScopeAncestorsResolver, ScopeRef } from '../types.js'

/**
 * Clasificación de fallos de dependencias, compartida por ambos drivers.
 *
 * Tres dependencias participan en una pregunta: el catálogo (SQL, en ambos
 * drivers), el árbol del consumidor (`resolveAncestors`) y el backend de
 * hechos (SQL o FGA). Las tres se clasifican igual: 503 con código propio,
 * la causa original conservada, y NUNCA un `false` ni un error crudo — el
 * invariante 5 tal como está publicado (L0.11, N3).
 *
 * Lo que ya es un error del paquete (422 de catálogo, 500 de programación)
 * pasa intacto: un rol inexistente no es una caída.
 */

/** ¿Es un error que este paquete ya clasificó (tiene `code` E_AUTHZ_*)? */
export function isAuthzError(error: unknown): boolean {
  return typeof (error as any)?.code === 'string' && (error as any).code.startsWith('E_AUTHZ_')
}

/**
 * ¿El error viene de un deadline vencido? knex lanza `KnexTimeoutError` (o, si
 * además falló la cancelación, el error de cancelación con `timeout` puesto);
 * axios usa `ECONNABORTED`/`ETIMEDOUT`, a veces envuelto por el SDK como
 * `cause`. Se mira la cadena entera de causas.
 */
export function isTimeoutLike(error: unknown): boolean {
  let current: any = error
  for (let depth = 0; current && depth < 6; depth++) {
    if (current.name === 'KnexTimeoutError' || typeof current.timeout === 'number') return true
    if (current.code === 'ECONNABORTED' || current.code === 'ETIMEDOUT') return true
    current = current.cause
  }
  return false
}

/**
 * Ejecuta una consulta SQL con deadline y traduce su fallo. El builder de
 * Lucid es perezoso (se ejecuta al hacer `await`), así que el `timeout` se
 * fija aquí, en el ÚNICO punto por el que pasan todas las consultas: un
 * call-site nuevo lo hereda sin saberlo. `cancel: true` pide a knex que
 * cancele la consulta en el servidor cuando el dialecto lo permite.
 */
export async function guardSql<T>(
  driver: string,
  operation: string,
  timeoutMs: number,
  fn: () => Promise<T>
): Promise<T> {
  try {
    const query: any = fn()
    if (typeof query?.timeout === 'function') {
      try {
        query.timeout(timeoutMs, { cancel: true })
      } catch {
        // knex rechaza `cancel` al CONSTRUIR la consulta en los dialectos que
        // no saben cancelar (SQLite). El deadline sigue valiendo: vencido, la
        // promesa rechaza y la conexión se descarta; solo no se manda un
        // "cancela" al servidor.
        query.timeout(timeoutMs)
      }
    }
    return await query
  } catch (error: any) {
    if (isAuthzError(error)) throw error
    if (isTimeoutLike(error)) {
      throw new AuthorizationBackendTimeoutError(driver, operation, timeoutMs, error)
    }
    throw new AuthorizationBackendError(driver, operation, error)
  }
}

/**
 * Deadline TOTAL de una llamada al backend: vencido ⇒ rechaza con el error
 * que fabrique `onTimeout`. El timer no retiene el event loop y se limpia al
 * resolver. La promesa original sigue su curso (el SDK puede reintentar por
 * su cuenta), pero el llamante ya fue liberado.
 */
export function withDeadline<T>(promise: Promise<T>, ms: number, onTimeout: () => Error): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(onTimeout()), ms)
    timer.unref?.()
  })
  return Promise.race([promise, deadline]).finally(() => clearTimeout(timer))
}

/**
 * Cadena `[scope, ...ancestros]` con el resolutor del consumidor envuelto: si
 * lanza, sale como `ScopeResolverError` (503). El árbol es una dependencia
 * más y su caída no es un bug del paquete ni un "sin permiso".
 */
export async function resolveChain(
  resolveAncestors: ScopeAncestorsResolver,
  scope: ScopeRef,
  operation: string
): Promise<ScopeRef[]> {
  let ancestors: ScopeRef[]
  try {
    ancestors = await resolveAncestors(scope)
  } catch (error) {
    if (isAuthzError(error)) throw error
    throw new ScopeResolverError(operation, error)
  }
  return [scope, ...ancestors]
}
