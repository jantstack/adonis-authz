import { ScopeCycleError, ScopeTooDeepError } from './errors.js'
import { APP_SCOPE, APP_SCOPE_TYPE } from './types.js'
import type { ScopeAncestorsResolver, ScopeRef } from './types.js'

/**
 * `parentOf` del consumidor: el padre directo de un scope.
 *  - `ScopeRef`: el padre (si es `app`, la cadena termina ahí);
 *  - `null`: el scope es de primer nivel ⇒ cuelga de `app`;
 *  - `undefined`: el scope NO existe ⇒ el resolutor devuelve `null` y el
 *    motor deniega/rechaza escribir (L0.3). Vale también a mitad de cadena:
 *    un hijo cuyo padre ya no existe es un árbol roto, no un nodo de `app`.
 * Si lanza, el error se propaga tal cual y el driver lo clasifica como 503
 * `E_AUTHZ_RESOLVER_FAILED` (nunca `[]`, nunca `false`).
 */
export type ParentOf = (scope: ScopeRef) => Promise<ScopeRef | null | undefined>

export interface HierarchicalResolverOptions {
  parentOf: ParentOf
  /**
   * Longitud máxima de la cadena de ancestros (`app` incluida). Default 64.
   * Superada ⇒ lanza 500 `E_AUTHZ_SCOPE_TOO_DEEP`: truncar devolvería una
   * cadena sin la raíz y el deny de `app` dejaría de verse (fail-open).
   */
  maxDepth?: number
}

/**
 * Construye un `ScopeAncestorsResolver` a partir de un `parentOf` (2.1, B4):
 * sube padre a padre hasta `app`, con conjunto de visitados (un ciclo lanza
 * 422 `E_AUTHZ_SCOPE_CYCLE`: FGA evaluaría el ciclo y un grant en cualquier
 * nodo concedería en la raíz, S2) y cota de profundidad que lanza. Cuesta
 * una llamada a `parentOf` por nivel: envuélvelo con `memoizeAncestors` (o
 * usa `forRequest()`) para que una request no lo pague por cada pregunta.
 */
export function hierarchicalScopeResolver(options: HierarchicalResolverOptions): ScopeAncestorsResolver {
  const { parentOf } = options
  const maxDepth = options.maxDepth ?? 64
  if (typeof parentOf !== 'function') {
    throw new TypeError('hierarchicalScopeResolver: parentOf debe ser una función')
  }
  if (!Number.isInteger(maxDepth) || maxDepth < 1) {
    throw new TypeError(`hierarchicalScopeResolver: maxDepth debe ser un entero >= 1 (llegó ${String(maxDepth)})`)
  }
  const key = (s: ScopeRef) => `${s.type}${s.uuid ?? ''}`

  return async (scope) => {
    if (scope.type === APP_SCOPE_TYPE) return []
    const chain: ScopeRef[] = []
    const visited = new Set<string>([key(scope)])
    let current = scope
    for (;;) {
      const parent = await parentOf(current)
      if (parent === undefined) return null
      if (parent === null || parent.type === APP_SCOPE_TYPE) {
        chain.push(APP_SCOPE)
        return chain
      }
      const k = key(parent)
      if (visited.has(k)) {
        throw new ScopeCycleError(
          `hierarchicalScopeResolver: ciclo al resolver ${scope.type}:${scope.uuid} — ` +
            `${parent.type}:${parent.uuid} ya está en la cadena (${chain.map((s) => `${s.type}:${s.uuid}`).join(' → ') || 'vacía'})`
        )
      }
      visited.add(k)
      chain.push(parent)
      // Aún falta `app`: si con ella la cadena superaría la cota, se lanza
      // ahora — nunca se devuelve una cadena corta.
      if (chain.length + 1 > maxDepth) {
        throw new ScopeTooDeepError(
          `hierarchicalScopeResolver: la cadena de ${scope.type}:${scope.uuid} supera maxDepth=${maxDepth} ` +
            `(truncarla dejaría fuera la raíz y sus denies)`
        )
      }
      current = parent
    }
  }
}
