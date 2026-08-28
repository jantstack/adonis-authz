import type { ScopeAncestorsResolver, ScopeRef } from '../types.js'
import { APP_SCOPE, APP_SCOPE_TYPE } from '../types.js'

/**
 * El árbol de scopes visto por el JUEZ.
 *
 * El contrato no sabe (ni debe saber) quién materializa la jerarquía: en un
 * driver con `resolveAncestors` es un mapa del consumidor; en un driver que
 * guarda el árbol como hechos propios (Fase 3b) son tuplas del backend. La
 * suite escribe siempre `await tree.attach(org, APP_SCOPE)` y el harness
 * decide qué hay detrás. Cero condicionales en los casos.
 */
export interface ContractScopeTree {
  /** Cuelga `child` de `parent`. Si `child` ya existía, equivale a `move`. */
  attach(child: ScopeRef, parent: ScopeRef): Promise<void>
  move(child: ScopeRef, newParent: ScopeRef): Promise<void>
  /** Quita el nodo Y sus descendientes. */
  detach(child: ScopeRef): Promise<void>
  /** Ancestros del más cercano a la raíz (`app` incluida). `null` = scope desconocido. */
  ancestorsOf(scope: ScopeRef): Promise<ScopeRef[] | null>
  edges(): AsyncIterable<{ child: ScopeRef; parent: ScopeRef }>
}

/** Separador no imprimible: un `type` con ':' no puede colisionar con otro. */
function key(scope: ScopeRef): string {
  return `${scope.type}\u001f${scope.uuid ?? ''}`
}

/**
 * El resolutor que un harness inyecta al driver para que vea el árbol del
 * juez. Un scope que el árbol NO conoce resuelve a `[]`: sin ancestros, sin
 * herencia de `app`. Es lo que hace que los casos de herencia dependan de
 * verdad de `tree.attach` — con un fallback a `[APP_SCOPE]` un driver que
 * ignorase el árbol seguiría pasando. (El driver aún no entiende `null`;
 * L0.3, Fase 1, lo convertirá en denegación explícita.)
 */
export function resolveAncestorsFrom(tree: ContractScopeTree): ScopeAncestorsResolver {
  return (scope) => tree.ancestorsOf(scope).then((ancestors) => ancestors ?? [])
}

/**
 * Árbol en memoria para harness de test: un `Map` hijo→padre.
 *
 * Es el árbol de TEST el que garantiza ser árbol (anti-ciclo, raíz única,
 * padre existente): el paquete lo hará por su cuenta en Fase 1/3b, y hasta
 * entonces un test que construyera un ciclo por error pasaría en falso o se
 * colgaría subiendo ancestros. Por eso aquí se lanza.
 */
export function memoryScopeTree(): ContractScopeTree {
  const parents = new Map<string, { child: ScopeRef; parent: ScopeRef }>()

  function isKnown(scope: ScopeRef): boolean {
    return scope.type === APP_SCOPE_TYPE || parents.has(key(scope))
  }

  function descendantsOf(scope: ScopeRef): Set<string> {
    const result = new Set<string>()
    let frontier = [key(scope)]
    while (frontier.length) {
      const next: string[] = []
      for (const entry of parents.values()) {
        const childKey = key(entry.child)
        if (frontier.includes(key(entry.parent)) && !result.has(childKey)) {
          result.add(childKey)
          next.push(childKey)
        }
      }
      frontier = next
    }
    return result
  }

  function link(child: ScopeRef, parent: ScopeRef): void {
    if (child.type === APP_SCOPE_TYPE) {
      throw new Error('memoryScopeTree: la raíz `app` no puede colgar de nada')
    }
    if (!isKnown(parent)) {
      throw new Error(`memoryScopeTree: el padre ${key(parent)} no existe en el árbol`)
    }
    if (key(parent) === key(child) || descendantsOf(child).has(key(parent))) {
      throw new Error(`memoryScopeTree: ciclo — ${key(parent)} desciende de ${key(child)}`)
    }
    parents.set(key(child), { child, parent })
  }

  return {
    async attach(child, parent) {
      link(child, parent)
    },
    async move(child, newParent) {
      if (!parents.has(key(child))) {
        throw new Error(`memoryScopeTree: no se puede mover ${key(child)}, no existe`)
      }
      link(child, newParent)
    },
    async detach(child) {
      for (const k of descendantsOf(child)) parents.delete(k)
      parents.delete(key(child))
    },
    async ancestorsOf(scope) {
      if (scope.type === APP_SCOPE_TYPE) return []
      if (!parents.has(key(scope))) return null
      const chain: ScopeRef[] = []
      // `link` ya impide ciclos; el conjunto de visitados es el cinturón por
      // si alguien manipula el mapa por otra vía.
      const visited = new Set<string>([key(scope)])
      let current = parents.get(key(scope))
      while (current) {
        chain.push(current.parent)
        const parentKey = key(current.parent)
        if (visited.has(parentKey)) {
          throw new Error(`memoryScopeTree: ciclo detectado al resolver ${key(scope)}`)
        }
        visited.add(parentKey)
        current = parents.get(parentKey)
      }
      return chain
    },
    async *edges() {
      for (const entry of parents.values()) yield { child: entry.child, parent: entry.parent }
    },
  }
}

export { APP_SCOPE }
