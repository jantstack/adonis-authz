import { ScopeCycleError, ScopeResolverError, ScopeTooDeepError } from './errors.js'
import { assertScope } from './identity.js'
import { APP_SCOPE, APP_SCOPE_TYPE } from './types.js'
import type { ScopeChainResolver, ScopeRef } from './types.js'

/**
 * Un nodo del árbol del consumidor, tal como está en SU tabla (2.5-B · K1):
 *  - `self`: el propio scope CANÓNICO (la fila leída: su `type` y su `uuid`
 *    tal como están guardados, no tal como llegó la pregunta);
 *  - `parent`: el padre directo (`ScopeRef`; si es `app`, la cadena termina
 *    ahí), o `null` si el nodo es de primer nivel ⇒ cuelga de `app`.
 */
export interface ScopeNode {
  self: ScopeRef
  parent: ScopeRef | null
}

/**
 * `nodeOf` del consumidor: la fila de un scope.
 *  - `ScopeNode`: el nodo existe; `self` es su identidad canónica y `parent`
 *    su padre (`null` = primer nivel);
 *  - `undefined`: el scope NO existe ⇒ el resolutor devuelve `null` y el
 *    motor deniega/rechaza escribir (L0.3). Vale también a mitad de cadena:
 *    un hijo cuyo padre ya no existe es un árbol roto, no un nodo de `app`.
 * Si lanza, el error se propaga tal cual y el driver lo clasifica como 503
 * `E_AUTHZ_RESOLVER_FAILED` (nunca `[]`, nunca `false`). Un `self` o un
 * padre mal formado (`{app, uuid}`, tipo en mayúsculas…) es 503
 * `E_AUTHZ_RESOLVER_FAILED` del propio resolutor (F6): nunca se normaliza en
 * silencio. Un `self` que no sea el scope preguntado (otro tipo, o un uuid
 * que no es el mismo id salvo mayúsculas/guiones) también es 503: la fila
 * que devuelves tiene que ser la del scope que se te pidió.
 *
 * Por qué devuelve el nodo entero y no solo el padre (`parentOf` de 2.1): con
 * el tipo `uuid` de PostgreSQL o una collation `*_ci`, `SELECT … WHERE uuid =
 * ?` encuentra la fila para un ALIAS del id (mayúsculas, sin guiones); si el
 * resolutor solo devolvía el padre, la cadena se construía con el alias del
 * llamante y los hechos —guardados canónicos— no casaban (el deny se evadía).
 */
export type NodeOf = (scope: ScopeRef) => Promise<ScopeNode | undefined>

export interface HierarchicalResolverOptions {
  nodeOf: NodeOf
  /**
   * Número máximo de ANCESTROS (`app` incluida; el propio scope no cuenta).
   * Default 64. Superado ⇒ lanza 500 `E_AUTHZ_SCOPE_TOO_DEEP`: truncar
   * devolvería una cadena sin la raíz y el deny de `app` dejaría de verse
   * (fail-open).
   */
  maxDepth?: number
}

/**
 * Construye un `ScopeChainResolver` a partir de un `nodeOf` (2.1, B4; 2.5-B ·
 * K1): lee el nodo (canónico), sube padre a padre hasta `app`, con conjunto
 * de visitados (un ciclo lanza 422 `E_AUTHZ_SCOPE_CYCLE`: FGA evaluaría el
 * ciclo y un grant en cualquier nodo concedería en la raíz, S2) y cota de
 * profundidad que lanza. Cuesta una llamada a `nodeOf` por nivel: envuélvelo
 * con `memoizeAncestors` (o usa `forRequest()`) para que una request no lo
 * pague por cada pregunta. La cadena que devuelve es `[self canónico,
 * ...padres canónicos, APP_SCOPE]`: cada nivel es la fila leída.
 */
export function hierarchicalScopeResolver(options: HierarchicalResolverOptions): ScopeChainResolver {
  const { nodeOf } = options
  const maxDepth = options.maxDepth ?? 64
  if (typeof nodeOf !== 'function') {
    throw new TypeError('hierarchicalScopeResolver: nodeOf debe ser una función')
  }
  if (!Number.isInteger(maxDepth) || maxDepth < 1) {
    throw new TypeError(`hierarchicalScopeResolver: maxDepth debe ser un entero >= 1 (llegó ${String(maxDepth)})`)
  }
  // Separador no imprimible, escrito como escape (nunca como carácter
  // literal): sin él `org`+`a-1` y `o`+`rga-1` colisionaban y un árbol
  // legítimo era un 422 falso de ciclo (F6, CR4).
  const key = (s: ScopeRef) => `${s.type}\u001f${s.uuid ?? ''}`
  const fold = (uuid: string | null) => (uuid ?? '').toLowerCase().replaceAll('-', '')

  return async (scope) => {
    if (scope.type === APP_SCOPE_TYPE) return [APP_SCOPE]
    const label = `hierarchicalScopeResolver(${scope.type}:${scope.uuid ?? ''})`
    const chain: ScopeRef[] = []
    const visited = new Set<string>()
    let asked = scope
    for (;;) {
      const node = await nodeOf(asked)
      if (node === undefined) return null
      // La RESPUESTA del árbol se valida (D13, F6, K1): un `self` o un padre
      // mal formado no es un nodo, es un fallo de la dependencia ⇒ 503 con la
      // causa; y `self` tiene que ser la fila del scope que se pidió.
      if (!node || typeof node !== 'object' || !('self' in node) || !('parent' in node)) {
        throw new ScopeResolverError(label, new TypeError(`nodeOf devolvió ${typeof node} en vez de { self, parent } | undefined`))
      }
      try {
        assertScope(node.self)
      } catch (error) {
        throw new ScopeResolverError(label, error)
      }
      if (node.self.type !== asked.type || fold(node.self.uuid) !== fold(asked.uuid)) {
        throw new ScopeResolverError(
          label,
          new TypeError(
            `nodeOf(${asked.type}:${asked.uuid ?? ''}) devolvió self = ${node.self.type}:${node.self.uuid ?? ''}: no es la fila del scope pedido`
          )
        )
      }
      const self = node.self
      const k = key(self)
      if (visited.has(k)) {
        throw new ScopeCycleError(
          `hierarchicalScopeResolver: ciclo al resolver ${scope.type}:${scope.uuid} — ` +
            `${self.type}:${self.uuid} ya está en la cadena (${chain.map((s) => `${s.type}:${s.uuid}`).join(' → ') || 'vacía'})`
        )
      }
      visited.add(k)
      chain.push(self)
      // Los ancestros serán (nodos leídos − 1) + `app` = nodos leídos: si ya
      // superan la cota, se lanza ahora — nunca se devuelve una cadena corta.
      if (chain.length > maxDepth) {
        throw new ScopeTooDeepError(
          `hierarchicalScopeResolver: la cadena de ${scope.type}:${scope.uuid} supera maxDepth=${maxDepth} ` +
            `(truncarla dejaría fuera la raíz y sus denies)`
        )
      }
      const parent = node.parent
      if (parent === null) {
        chain.push(APP_SCOPE)
        return chain
      }
      try {
        assertScope(parent)
      } catch (error) {
        throw new ScopeResolverError(label, error)
      }
      if (parent.type === APP_SCOPE_TYPE) {
        chain.push(APP_SCOPE)
        return chain
      }
      asked = parent
    }
  }
}
