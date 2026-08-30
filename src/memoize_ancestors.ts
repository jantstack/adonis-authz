import type { ScopeChainResolver, ScopeRef } from './types.js'

/**
 * Envuelve un `ScopeChainResolver` con un memo de UNA instancia: la
 * primera pregunta por un scope llama al resolutor del consumidor; las
 * siguientes por el mismo scope devuelven lo mismo sin llamarlo. Sin reloj
 * ni TTL: la vida del memo es la vida del objeto, y el patrón es crearlo
 * por request (`authorization.forRequest()` lo hace por ti).
 *
 * Qué memoiza: la RESPUESTA del árbol —la cadena canónica—, incluido `null`
 * (scope desconocido).
 * Qué no: un resolutor que lanza no deja nada cacheado — la siguiente
 * pregunta vuelve a intentarlo, y el error sale clasificado como siempre
 * (503 `E_AUTHZ_RESOLVER_FAILED`) por `resolveChain`.
 *
 * SOLO para el camino de lectura (auditor C3/E3): `authorize`, `hasRole`,
 * `list*`. Una escritura (`grant`, `deny`, `scopes.*`) tiene que resolver
 * ancestros en fresco, porque una lectura obsoleta caduca sola y un grant
 * sobre una cadena que ya no existe queda escrito para siempre. El manager
 * respeta esa frontera por construcción; si envuelves un driver a mano,
 * respétala tú.
 */
export function memoizeAncestors(resolver: ScopeChainResolver): ScopeChainResolver {
  const memo = new Map<string, Promise<ScopeRef[] | null>>()
  return (scope) => {
    // La raíz no se pregunta nunca (`resolveChain` la corta antes), pero si
    // alguien llama al memo directo con ella, se comporta igual que el
    // resolutor de abajo: se delega.
    // Separador no imprimible, escrito como escape (nunca como carácter literal).
    const key = `${scope.type}\u001f${scope.uuid ?? ''}`
    const hit = memo.get(key)
    if (hit) return hit
    const pending = Promise.resolve()
      .then(() => resolver(scope))
      .catch((error) => {
        memo.delete(key)
        throw error
      })
    memo.set(key, pending)
    return pending
  }
}
