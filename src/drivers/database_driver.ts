import db from '@adonisjs/lucid/services/db'
import { Exception } from '@adonisjs/core/exceptions'
import { v7 as uuidv7 } from 'uuid'
import type {
  AuthorizationDriver,
  GrantOptions,
  ScopeRef,
  ScopeType,
  SubjectRef,
} from '../types.js'
import { APP_SCOPE } from '../types.js'
import type { ScopeAncestorsResolver } from '../types.js'
import { assertIdentity, assertScope } from '../identity.js'
import { AuthorizationInternalError } from '../errors.js'
import { guardSql, resolveChain } from './backend_guard.js'

export type QueryBuilder = ReturnType<typeof db.from>

/**
 * UUID centinela para el scope 'app' en las columnas scope_uuid (NOT NULL):
 * permite que el unique de assignments/denies cubra también el nivel app
 * (los NULL serían "distintos" para el motor SQL). Detalle de almacenamiento
 * de ESTE driver — la API pública sigue usando uuid null para app.
 */
export const APP_SCOPE_DB_UUID = '00000000-0000-0000-0000-000000000000'

function toDbScopeUuid(scope: ScopeRef): string {
  // Defensa en profundidad (L0.10/L0.15): es el único punto donde el scope
  // se serializa a columnas, así que aquí se garantiza que `app` no lleve
  // uuid y que ningún otro tipo use el centinela de la raíz.
  assertScope(scope)
  return scope.uuid ?? APP_SCOPE_DB_UUID
}

function fromDbScopeUuid(uuid: string): string | null {
  return uuid === APP_SCOPE_DB_UUID ? null : uuid
}

/**
 * Filtro (scope_type, scope_uuid) ∈ scopes (centinela para el nivel app).
 *
 * Con `scopes` VACÍO no hay filtro que construir, y "sin filtro" en SQL es
 * "todas las filas": la consulta de denies sobre-bloquearía (cerrado) pero la
 * de asignaciones concedería en CUALQUIER scope (abierto) — L0.1. Hoy ningún
 * call-site pasa un conjunto vacío (la cadena siempre contiene el scope), pero
 * `descendantsOf`/`authorizedScopes` (Fase 2) lo harán alcanzable:
 *  - lectura ⇒ `null`: nada puede coincidir, el llamante responde vacío/false
 *    SIN ejecutar la consulta;
 *  - escritura ⇒ 500: escribir "en ningún scope" es un bug de programación.
 * Exportada (no método privado) para poder fijarlo con un test.
 */
export function whereScopeIn(
  query: QueryBuilder,
  column: string,
  scopes: ScopeRef[],
  intent: 'write'
): QueryBuilder
export function whereScopeIn(
  query: QueryBuilder,
  column: string,
  scopes: ScopeRef[],
  intent: 'read'
): QueryBuilder | null
export function whereScopeIn(
  query: QueryBuilder,
  column: string,
  scopes: ScopeRef[],
  intent: 'read' | 'write'
): QueryBuilder | null {
  if (scopes.length === 0) {
    if (intent === 'write') {
      throw new AuthorizationInternalError(
        `whereScopeIn: una escritura sin scopes no tiene destino (columna '${column}')`
      )
    }
    return null
  }
  return query.where((outer) => {
    for (const s of scopes) {
      outer.orWhere((inner) => {
        inner.where(`${column}_type`, s.type).where(`${column}_uuid`, toDbScopeUuid(s))
      })
    }
  })
}

export interface DatabaseDriverOptions {
  /** Jerarquía del consumidor (ver ScopeAncestorsResolver). */
  resolveAncestors?: ScopeAncestorsResolver
  /**
   * Deadline de cada consulta SQL en ms (default 5000). Vencido ⇒ 503
   * `E_AUTHZ_BACKEND_TIMEOUT`. Sin deadline, una base saturada convertía cada
   * request autorizada en un socket retenido para siempre (L0.13).
   */
  timeoutMs?: number
}

export const DEFAULT_TIMEOUT_MS = 5_000

/**
 * Driver `database`: motor de autorización propio sobre las tablas `authz_*`.
 * Default autosuficiente del chasis (cero piezas extra en el appliance).
 *
 * Resolución de `authorize`: NO hay deny en la cadena de scopes Y alguna
 * asignación vigente (expires_at null o futuro) en la cadena concede el
 * permiso vía su rol. La cadena es `[scope, ...ancestros]` — herencia solo
 * hacia abajo. Solo SQL estándar vía query builder (regla M6: nada
 * específico de un motor).
 *
 * Toda consulta pasa por `sql()`: un fallo del cliente SQL (conexión, tabla,
 * deadline) sale como `AuthorizationBackendError` 503, nunca como el error
 * crudo de knex (L0.11).
 */
export class DatabaseAuthorizationDriver implements AuthorizationDriver {
  /**
   * Resolutor de jerarquía inyectado por el consumidor (el chasis pasa el
   * suyo, que conoce organizations/units, en `config/authorization.ts`).
   * Default puro sin dominio: todo cuelga directamente de `app`.
   */
  private resolveAncestors: ScopeAncestorsResolver
  private timeoutMs: number

  constructor(options: DatabaseDriverOptions = {}) {
    this.resolveAncestors =
      options.resolveAncestors ?? (async (scope) => (scope.type === 'app' ? [] : [APP_SCOPE]))
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  }

  private chain(scope: ScopeRef, operation: string): Promise<ScopeRef[]> {
    return resolveChain(this.resolveAncestors, scope, operation)
  }

  /**
   * Ejecuta una consulta clasificando su fallo (503 con código propio). `fn`
   * devuelve el BUILDER sin ejecutar: el guard le fija el deadline y luego lo
   * ejecuta. Por eso no se usa `.first()` de Lucid (ejecuta al instante, sin
   * dejar poner el timeout): `first()` de abajo hace `limit(1)` y toma la fila.
   */
  private sql<T>(operation: string, fn: () => Promise<T>): Promise<T> {
    return guardSql('database', operation, this.timeoutMs, fn)
  }

  private async first(operation: string, fn: () => QueryBuilder): Promise<any | null> {
    const rows = await this.sql(operation, () => fn().limit(1))
    return rows[0] ?? null
  }

  /** Asignación vigente: sin expiración o con expiración futura. */
  private whereActive(query: QueryBuilder, column: string = 'expires_at'): QueryBuilder {
    return query.where((builder) => {
      builder.whereNull(column).orWhere(column, '>', new Date())
    })
  }

  private findPermission(slug: string): Promise<{ uuid: string } | null> {
    return this.first('findPermission', () =>
      db.from('authz_permissions').where('slug', slug).select('uuid')
    )
  }

  private findRole(slug: string, scopeType: string): Promise<{ uuid: string } | null> {
    return this.first('findRole', () =>
      db.from('authz_roles').where('slug', slug).where('scope_type', scopeType).select('uuid')
    )
  }

  private async findRoleOrFail(slug: string, scopeType: string): Promise<{ uuid: string }> {
    const role = await this.findRole(slug, scopeType)
    if (!role) {
      throw new Exception(`Rol '${slug}' no existe en el catálogo para el nivel '${scopeType}'`, {
        status: 422,
      })
    }
    return role
  }

  async authorize(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<boolean> {
    assertIdentity({ subject, permission, scope })
    const perm = await this.findPermission(permission)
    if (!perm) return false

    const chain = await this.chain(scope, 'authorize')

    const deniedQuery = whereScopeIn(
      db
        .from('authz_denies')
        .where('holder_type', subject.type)
        .where('holder_uuid', subject.uuid)
        .where('permission_uuid', perm.uuid),
      'scope',
      chain,
      'read'
    )
    if (!deniedQuery) return false
    if (await this.first('authorize.denies', () => deniedQuery)) return false

    const grantedQuery = whereScopeIn(
      db
        .from('authz_assignments as a')
        .join('authz_role_permissions as rp', 'rp.role_uuid', 'a.role_uuid')
        .where('rp.permission_uuid', perm.uuid)
        .where('a.holder_type', subject.type)
        .where('a.holder_uuid', subject.uuid),
      'a.scope',
      chain,
      'read'
    )
    if (!grantedQuery) return false
    const granted = await this.first('authorize.assignments', () =>
      this.whereActive(grantedQuery, 'a.expires_at')
    )

    return Boolean(granted)
  }

  async grant(
    subject: SubjectRef,
    role: string,
    scope: ScopeRef,
    options: GrantOptions = {}
  ): Promise<void> {
    assertIdentity({ subject, role, scope })
    const { uuid: roleUuid } = await this.findRoleOrFail(role, scope.type)
    const expiresAt = options.expiresAt ?? null

    const findExisting = () =>
      whereScopeIn(
        db
          .from('authz_assignments')
          .where('holder_type', subject.type)
          .where('holder_uuid', subject.uuid)
          .where('role_uuid', roleUuid),
        'scope',
        [scope],
        'write'
      )

    const existing = await this.first('grant.find', findExisting)

    if (existing) {
      // Idempotente: re-grant refresca la expiración (revivir una asignación
      // expirada es un grant nuevo a todos los efectos).
      await this.sql('grant.update', () =>
        db.from('authz_assignments').where('uuid', existing.uuid).update({ expires_at: expiresAt })
      )
      return
    }

    try {
      await this.sql('grant.insert', () =>
        db.table('authz_assignments').insert({
          uuid: uuidv7(),
          holder_type: subject.type,
          holder_uuid: subject.uuid,
          role_uuid: roleUuid,
          scope_type: scope.type,
          scope_uuid: toDbScopeUuid(scope),
          expires_at: expiresAt,
          created_at: new Date(),
        })
      )
    } catch (error) {
      // Carrera check-then-insert: el unique (que cubre también el nivel app
      // vía centinela) la detecta — el perdedor degrada a update (idempotente).
      // Si no era una carrera, el fallo del insert (ya clasificado) se propaga.
      const raced = await this.first('grant.race', findExisting)
      if (!raced) throw error
      await this.sql('grant.update', () =>
        db.from('authz_assignments').where('uuid', raced.uuid).update({ expires_at: expiresAt })
      )
    }
  }

  async revoke(subject: SubjectRef, role: string, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, role, scope })
    const roleRow = await this.findRole(role, scope.type)
    if (!roleRow) return

    await this.sql('revoke', () =>
      whereScopeIn(
        db
          .from('authz_assignments')
          .where('holder_type', subject.type)
          .where('holder_uuid', subject.uuid)
          .where('role_uuid', roleRow.uuid),
        'scope',
        [scope],
        'write'
      ).delete()
    )
  }

  async hasRole(subject: SubjectRef, role: string, scope: ScopeRef): Promise<boolean> {
    assertIdentity({ subject, role, scope })
    const chain = await this.chain(scope, 'hasRole')
    const query = whereScopeIn(
      db
        .from('authz_assignments as a')
        .join('authz_roles as r', 'r.uuid', 'a.role_uuid')
        .where('r.slug', role)
        .where('a.holder_type', subject.type)
        .where('a.holder_uuid', subject.uuid),
      'a.scope',
      chain,
      'read'
    )
    if (!query) return false
    const found = await this.first('hasRole', () => this.whereActive(query, 'a.expires_at'))
    return Boolean(found)
  }

  async deny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, permission, scope })
    const perm = await this.findPermission(permission)
    if (!perm) {
      throw new Exception(`Permiso '${permission}' no existe en el catálogo`, { status: 422 })
    }

    const findExisting = () =>
      whereScopeIn(
        db
          .from('authz_denies')
          .where('holder_type', subject.type)
          .where('holder_uuid', subject.uuid)
          .where('permission_uuid', perm.uuid),
        'scope',
        [scope],
        'write'
      )

    const existing = await this.first('deny.find', findExisting)
    if (existing) return

    try {
      await this.sql('deny.insert', () =>
        db.table('authz_denies').insert({
          uuid: uuidv7(),
          holder_type: subject.type,
          holder_uuid: subject.uuid,
          permission_uuid: perm.uuid,
          scope_type: scope.type,
          scope_uuid: toDbScopeUuid(scope),
          created_at: new Date(),
        })
      )
    } catch (error) {
      // Carrera: si otro proceso insertó el mismo deny, el unique lo detecta
      // y el resultado deseado ya existe.
      const raced = await this.first('deny.race', findExisting)
      if (!raced) throw error
    }
  }

  async removeDeny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void> {
    assertIdentity({ subject, permission, scope })
    const perm = await this.findPermission(permission)
    if (!perm) return

    await this.sql('removeDeny', () =>
      whereScopeIn(
        db
          .from('authz_denies')
          .where('holder_type', subject.type)
          .where('holder_uuid', subject.uuid)
          .where('permission_uuid', perm.uuid),
        'scope',
        [scope],
        'write'
      ).delete()
    )
  }

  async listSubjects(role: string, scope: ScopeRef): Promise<SubjectRef[]> {
    assertIdentity({ role, scope })
    const query = whereScopeIn(
      db
        .from('authz_assignments as a')
        .join('authz_roles as r', 'r.uuid', 'a.role_uuid')
        .where('r.slug', role)
        .where('r.scope_type', scope.type),
      'a.scope',
      [scope],
      'read'
    )
    if (!query) return []
    const rows = await this.sql('listSubjects', () =>
      this.whereActive(query, 'a.expires_at').distinct('a.holder_type', 'a.holder_uuid')
    )

    return rows.map((row: any) => ({ type: row.holder_type, uuid: row.holder_uuid }))
  }

  async listRoles(subject: SubjectRef, scope: ScopeRef): Promise<string[]> {
    assertIdentity({ subject, scope })
    const query = whereScopeIn(
      db
        .from('authz_assignments as a')
        .join('authz_roles as r', 'r.uuid', 'a.role_uuid')
        .where('a.holder_type', subject.type)
        .where('a.holder_uuid', subject.uuid),
      'a.scope',
      [scope],
      'read'
    )
    if (!query) return []
    const rows = await this.sql('listRoles', () =>
      this.whereActive(query, 'a.expires_at').distinct('r.slug')
    )
    return rows.map((row: any) => row.slug)
  }

  async listRoleScopes(subject: SubjectRef, scopeType: ScopeType): Promise<ScopeRef[]> {
    assertIdentity({ subject, scopeType })
    const rows = await this.sql('listRoleScopes', () =>
      this.whereActive(
        db
          .from('authz_assignments as a')
          .where('a.holder_type', subject.type)
          .where('a.holder_uuid', subject.uuid)
          .where('a.scope_type', scopeType),
        'a.expires_at'
      ).distinct('a.scope_type', 'a.scope_uuid')
    )
    return rows.map((row: any) => ({ type: row.scope_type, uuid: fromDbScopeUuid(row.scope_uuid) }))
  }

  async listScopes(subject: SubjectRef, permission: string): Promise<ScopeRef[]> {
    assertIdentity({ subject, permission })
    const perm = await this.findPermission(permission)
    if (!perm) return []

    const rows = await this.sql('listScopes.assignments', () =>
      this.whereActive(
        db
          .from('authz_assignments as a')
          .join('authz_role_permissions as rp', 'rp.role_uuid', 'a.role_uuid')
          .where('rp.permission_uuid', perm.uuid)
          .where('a.holder_type', subject.type)
          .where('a.holder_uuid', subject.uuid),
        'a.expires_at'
      ).distinct('a.scope_type', 'a.scope_uuid')
    )

    const denies = await this.sql('listScopes.denies', () =>
      db
        .from('authz_denies')
        .where('holder_type', subject.type)
        .where('holder_uuid', subject.uuid)
        .where('permission_uuid', perm.uuid)
        .select('scope_type', 'scope_uuid')
    )

    const deniedKeys = new Set(
      denies.map((d: any) => `${d.scope_type}:${fromDbScopeUuid(d.scope_uuid) ?? ''}`)
    )

    const result: ScopeRef[] = []
    for (const row of rows) {
      const candidate: ScopeRef = { type: row.scope_type, uuid: fromDbScopeUuid(row.scope_uuid) }
      const chain = await this.chain(candidate, 'listScopes')
      const blocked = chain.some((s) => deniedKeys.has(`${s.type}:${s.uuid ?? ''}`))
      if (!blocked) result.push(candidate)
    }
    return result
  }
}
