import type { ScopeChainResolver, ScopeDescendantsResolver, ScopeRef } from '../types.js'
import { APP_SCOPE, APP_SCOPE_TYPE } from '../types.js'

/**
 * El árbol de scopes visto por el JUEZ.
 *
 * El contrato no sabe (ni debe saber) quién materializa la jerarquía: en un
 * driver con `resolveChain` es un mapa del consumidor; en un driver que
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
  /**
   * Cadena CANÓNICA `[scope tal como está en el árbol, ...ancestros]`, del
   * más cercano a la raíz, `app` incluida (2.5-B · K1). `null` = scope
   * desconocido. Un árbol que canoniza ids (el tipo `uuid` de PG funde
   * mayúsculas y guiones) devuelve la fila real como elemento 0.
   */
  chainOf(scope: ScopeRef): Promise<ScopeRef[] | null>
  edges(): AsyncIterable<{ child: ScopeRef; parent: ScopeRef }>
  /**
   * Descendientes del árbol, si el árbol sabe enumerarlos mejor que paseando
   * `edges()` (un árbol SQL: `sqlDescendantsOf`). Opcional: `descendantsFrom`
   * lo usa si está y, si no, camina las aristas.
   */
  descendantsOf?: ScopeDescendantsResolver
}

/** Separador no imprimible: un `type` con ':' no puede colisionar con otro. */
function key(scope: ScopeRef): string {
  return `${scope.type}\u001f${scope.uuid ?? ''}`
}

/**
 * El resolutor que un harness inyecta al driver para que vea el árbol del
 * juez: la cadena canónica del árbol (`chainOf`). Un scope que el árbol NO
 * conoce resuelve a `null` tal cual: el driver deniega y rechaza escribir
 * (L0.3). Es lo que hace que los casos de herencia dependan de verdad de
 * `tree.attach` — con un fallback a `[APP_SCOPE]` un driver que ignorase el
 * árbol seguiría pasando.
 */
export function resolveChainFrom(tree: ContractScopeTree): ScopeChainResolver {
  return (scope) => tree.chainOf(scope)
}

/**
 * El `descendantsOf` que un harness inyecta al MANAGER para que las
 * primitivas de enumeración (2.1: `authorizedScopes`) vean el árbol del
 * juez. Se calcula desde `edges()` —lo único que el contrato exige a un
 * árbol— así que vale para cualquier `ContractScopeTree`. Un scope que el
 * árbol no conoce resuelve a `null`; más de `maxNodes` descendientes ⇒ lanza
 * (el contrato del puerto: nunca una lista truncada en silencio).
 */
export function descendantsFrom(tree: ContractScopeTree): ScopeDescendantsResolver {
  if (tree.descendantsOf) return (scope, options) => tree.descendantsOf!(scope, options)
  return async (scope, { maxNodes }) => {
    if (scope.type !== APP_SCOPE_TYPE && (await tree.chainOf(scope)) === null) return null
    const children = new Map<string, ScopeRef[]>()
    for await (const { child, parent } of tree.edges()) {
      const k = key(parent)
      if (!children.has(k)) children.set(k, [])
      children.get(k)!.push(child)
    }
    const result: ScopeRef[] = []
    const seen = new Set<string>([key(scope)])
    const frontier: ScopeRef[] = [scope]
    while (frontier.length) {
      const current = frontier.shift()!
      for (const child of children.get(key(current)) ?? []) {
        if (seen.has(key(child))) continue
        seen.add(key(child))
        result.push(child)
        if (result.length > maxNodes) {
          throw new Error(`descendantsFrom: ${key(scope)} tiene más de ${maxNodes} descendientes`)
        }
        frontier.push(child)
      }
    }
    return result
  }
}

/**
 * Árbol en memoria para harness de test: un `Map` hijo→padre.
 *
 * El árbol de TEST también garantiza ser árbol (anti-ciclo, raíz única,
 * padre existente), igual que hace el manager en `scopes.attached/moved`:
 * el juez habla con el driver directamente, sin manager, y un test que
 * construyera un ciclo por error pasaría en falso o se colgaría subiendo
 * ancestros. Por eso aquí se lanza.
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
    async chainOf(scope) {
      if (scope.type === APP_SCOPE_TYPE) return [APP_SCOPE]
      const own = parents.get(key(scope))
      if (!own) return null
      // El elemento 0 es el nodo tal como se colgó (canónico para este
      // árbol); un `Map` compara por bytes, así que aquí un alias nunca casa.
      const chain: ScopeRef[] = [own.child]
      // `link` ya impide ciclos; el conjunto de visitados es el cinturón por
      // si alguien manipula el mapa por otra vía.
      const visited = new Set<string>([key(scope)])
      let current: { child: ScopeRef; parent: ScopeRef } | undefined = own
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
