/**
 * Árbol de scopes del JUEZ materializado en SQL (2.5-B · K1): la tabla
 * `demo_scopes` del harness —`uuid` nativo en PostgreSQL, `char(36)` con la
 * collation por defecto en MySQL— leída con los helpers que el paquete
 * publica para un árbol del consumidor (`hierarchicalScopeResolver` hacia
 * arriba, `sqlDescendantsOf` hacia abajo).
 *
 * Existe porque el árbol en memoria (`memoryScopeTree`, un `Map` de JS)
 * compara byte a byte y NO puede mostrar lo que un motor real hace con un
 * alias del uuid (mayúsculas, guiones quitados): el auditor de 2.5 encontró
 * que el tipo `uuid` de PG y la collation `*_ci` de MySQL funden el alias con
 * la fila real, la cadena resolvía y el deny —guardado con la forma canónica
 * en `authz_*` (`utf8mb4_bin`)— no casaba. Con este árbol el juez lo observa.
 */

import type { Database } from '@adonisjs/lucid/database'
import { hierarchicalScopeResolver } from '../../src/hierarchical_resolver.js'
import { sqlDescendantsOf } from '../../src/sql_descendants.js'
import type { ScopeNode } from '../../src/hierarchical_resolver.js'
import type { ContractScopeTree } from '../../src/testing/scope_tree.js'
import { APP_SCOPE, APP_SCOPE_TYPE } from '../../src/types.js'
import type { ScopeRef } from '../../src/types.js'

const TABLE = 'demo_scopes'

/**
 * El `nodeOf` de un consumidor: lee la fila y devuelve el nodo CANÓNICO (la
 * fila, no lo que llegó: con `uuid` de PG un alias encuentra la fila real) y
 * su padre (también la fila del padre).
 */
async function nodeOfRow(db: Database, scope: ScopeRef): Promise<ScopeNode | undefined> {
  const row: any = await db.from(TABLE).where('uuid', scope.uuid!).where('type', scope.type).first()
  if (!row) return undefined
  const self: ScopeRef = { type: row.type, uuid: String(row.uuid) }
  if (row.parent_uuid === null) return { self, parent: null }
  const parent: any = await db.from(TABLE).where('uuid', row.parent_uuid).first()
  return parent ? { self, parent: { type: parent.type, uuid: String(parent.uuid) } } : undefined
}

export function sqlScopeTree(db: Database): ContractScopeTree {
  const nodeOf = (scope: ScopeRef) => nodeOfRow(db, scope)
  const chain = hierarchicalScopeResolver({ nodeOf })
  const descendants = sqlDescendantsOf(
    { table: TABLE, uuidColumn: 'uuid', parentColumn: 'parent_uuid', typeColumn: 'type' },
    db
  )

  async function exists(scope: ScopeRef): Promise<boolean> {
    if (scope.type === APP_SCOPE_TYPE) return true
    return (await chain(scope)) !== null
  }

  async function link(child: ScopeRef, parent: ScopeRef): Promise<void> {
    if (child.type === APP_SCOPE_TYPE) throw new Error('sqlScopeTree: la raíz `app` no puede colgar de nada')
    if (!(await exists(parent))) throw new Error(`sqlScopeTree: el padre ${parent.type}:${parent.uuid} no existe en el árbol`)
    if (parent.type !== APP_SCOPE_TYPE) {
      const above = (await chain(parent)) ?? []
      if (above.some((s) => s.type === child.type && s.uuid === child.uuid)) {
        throw new Error(`sqlScopeTree: ciclo — ${parent.type}:${parent.uuid} desciende de ${child.type}:${child.uuid}`)
      }
    }
    const parentUuid = parent.type === APP_SCOPE_TYPE ? null : parent.uuid
    const updated: unknown = await db.from(TABLE).where('uuid', child.uuid!).where('type', child.type).update({ parent_uuid: parentUuid })
    if (Number(updated) === 0) await db.table(TABLE).insert({ uuid: child.uuid, type: child.type, parent_uuid: parentUuid })
  }

  return {
    attach: link,
    async move(child, newParent) {
      if (!(await exists(child))) throw new Error(`sqlScopeTree: no se puede mover ${child.type}:${child.uuid}, no existe`)
      await link(child, newParent)
    },
    async detach(child) {
      const below = (await descendants(child, { maxNodes: 100_000 })) ?? []
      for (const s of [...below, child]) await db.from(TABLE).where('uuid', s.uuid!).where('type', s.type).delete()
    },
    chainOf: (scope) => chain(scope),
    descendantsOf: (scope, options) => descendants(scope, options),
    async *edges() {
      const rows: any[] = await db.from(TABLE).select('uuid', 'type', 'parent_uuid')
      const byUuid = new Map(rows.map((r) => [r.uuid, r]))
      for (const row of rows) {
        const parentRow = row.parent_uuid === null ? null : byUuid.get(row.parent_uuid)
        const parent: ScopeRef = parentRow ? { type: parentRow.type, uuid: parentRow.uuid } : APP_SCOPE
        yield { child: { type: row.type, uuid: row.uuid }, parent }
      }
    },
  }
}

/** Vacía el árbol SQL entre tests. */
export async function cleanSqlScopeTree(db: Database): Promise<void> {
  await db.from(TABLE).delete()
}
