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

type QueryBuilder = ReturnType<typeof db.from>

/**
 * UUID centinela para el scope 'app' en las columnas scope_uuid (NOT NULL):
 * permite que el unique de assignments/denies cubra también el nivel app
 * (los NULL serían "distintos" para el motor SQL). Detalle de almacenamiento
 * de ESTE driver — la API pública sigue usando uuid null para app.
 */
export const APP_SCOPE_DB_UUID = '00000000-0000-0000-0000-000000000000'

function toDbScopeUuid(scope: ScopeRef): string {
  return scope.uuid ?? APP_SCOPE_DB_UUID
}

function fromDbScopeUuid(uuid: string): string | null {
  return uuid === APP_SCOPE_DB_UUID ? null : uuid
}

/**
 * Driver `database`: motor de autorización propio sobre las tablas `authz_*`.
 * Default autosuficiente del chasis (cero piezas extra en el appliance).
 *
 * Resolución de `authorize`: NO hay deny en la cadena de scopes Y alguna
 * asignación vigente (expires_at null o futuro) en la cadena concede el
 * permiso vía su rol. La cadena es `[scope, ...ancestros]` — herencia solo
 * hacia abajo. Solo SQL estándar vía query builder (regla M6: nada
 * específico de un motor).
 */
export class DatabaseAuthorizationDriver implements AuthorizationDriver {
  /**
   * Resolutor de jerarquía inyectado por el consumidor (el chasis pasa el
   * suyo, que conoce organizations/units, en `config/authorization.ts`).
   * Default puro sin dominio: todo cuelga directamente de `app`.
   */
  private resolveAncestors: ScopeAncestorsResolver

  constructor(options: { resolveAncestors?: ScopeAncestorsResolver } = {}) {
    this.resolveAncestors =
      options.resolveAncestors ?? (async (scope) => (scope.type === 'app' ? [] : [APP_SCOPE]))
  }

  private async chain(scope: ScopeRef): Promise<ScopeRef[]> {
    return [scope, ...(await this.resolveAncestors(scope))]
  }

  /** Filtro (scope_type, scope_uuid) ∈ scopes (centinela para el nivel app). */
  private whereScopeIn(query: QueryBuilder, column: string, scopes: ScopeRef[]): QueryBuilder {
    return query.where((outer) => {
      for (const s of scopes) {
        outer.orWhere((inner) => {
          inner.where(`${column}_type`, s.type).where(`${column}_uuid`, toDbScopeUuid(s))
        })
      }
    })
  }

  /** Asignación vigente: sin expiración o con expiración futura. */
  private whereActive(query: QueryBuilder, column: string = 'expires_at'): QueryBuilder {
    return query.where((builder) => {
      builder.whereNull(column).orWhere(column, '>', new Date())
    })
  }

  private async findPermission(slug: string): Promise<{ uuid: string } | null> {
    return db.from('authz_permissions').where('slug', slug).select('uuid').first()
  }

  private async findRoleOrFail(slug: string, scopeType: string): Promise<{ uuid: string }> {
    const role = await db
      .from('authz_roles')
      .where('slug', slug)
      .where('scope_type', scopeType)
      .select('uuid')
      .first()
    if (!role) {
      throw new Exception(`Rol '${slug}' no existe en el catálogo para el nivel '${scopeType}'`, {
        status: 422,
      })
    }
    return role
  }

  async authorize(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<boolean> {
    const perm = await this.findPermission(permission)
    if (!perm) return false

    const chain = await this.chain(scope)

    const denied = await this.whereScopeIn(
      db
        .from('authz_denies')
        .where('holder_type', subject.type)
        .where('holder_uuid', subject.uuid)
        .where('permission_uuid', perm.uuid),
      'scope',
      chain
    ).first()
    if (denied) return false

    const granted = await this.whereActive(
      this.whereScopeIn(
        db
          .from('authz_assignments as a')
          .join('authz_role_permissions as rp', 'rp.role_uuid', 'a.role_uuid')
          .where('rp.permission_uuid', perm.uuid)
          .where('a.holder_type', subject.type)
          .where('a.holder_uuid', subject.uuid),
        'a.scope',
        chain
      ),
      'a.expires_at'
    ).first()

    return Boolean(granted)
  }

  async grant(
    subject: SubjectRef,
    role: string,
    scope: ScopeRef,
    options: GrantOptions = {}
  ): Promise<void> {
    const { uuid: roleUuid } = await this.findRoleOrFail(role, scope.type)
    const expiresAt = options.expiresAt ?? null

    const existing = await this.whereScopeIn(
      db
        .from('authz_assignments')
        .where('holder_type', subject.type)
        .where('holder_uuid', subject.uuid)
        .where('role_uuid', roleUuid),
      'scope',
      [scope]
    ).first()

    if (existing) {
      // Idempotente: re-grant refresca la expiración (revivir una asignación
      // expirada es un grant nuevo a todos los efectos).
      await db.from('authz_assignments').where('uuid', existing.uuid).update({
        expires_at: expiresAt,
      })
      return
    }

    try {
      await db.table('authz_assignments').insert({
        uuid: uuidv7(),
        holder_type: subject.type,
        holder_uuid: subject.uuid,
        role_uuid: roleUuid,
        scope_type: scope.type,
        scope_uuid: toDbScopeUuid(scope),
        expires_at: expiresAt,
        created_at: new Date(),
      })
    } catch (error) {
      // Carrera check-then-insert: el unique (que cubre también el nivel app
      // vía centinela) la detecta — el perdedor degrada a update (idempotente).
      const raced = await this.whereScopeIn(
        db
          .from('authz_assignments')
          .where('holder_type', subject.type)
          .where('holder_uuid', subject.uuid)
          .where('role_uuid', roleUuid),
        'scope',
        [scope]
      ).first()
      if (!raced) throw error
      await db.from('authz_assignments').where('uuid', raced.uuid).update({
        expires_at: expiresAt,
      })
    }
  }

  async revoke(subject: SubjectRef, role: string, scope: ScopeRef): Promise<void> {
    const roleRow = await db
      .from('authz_roles')
      .where('slug', role)
      .where('scope_type', scope.type)
      .select('uuid')
      .first()
    if (!roleRow) return

    await this.whereScopeIn(
      db
        .from('authz_assignments')
        .where('holder_type', subject.type)
        .where('holder_uuid', subject.uuid)
        .where('role_uuid', roleRow.uuid),
      'scope',
      [scope]
    ).delete()
  }

  async hasRole(subject: SubjectRef, role: string, scope: ScopeRef): Promise<boolean> {
    const chain = await this.chain(scope)
    const found = await this.whereActive(
      this.whereScopeIn(
        db
          .from('authz_assignments as a')
          .join('authz_roles as r', 'r.uuid', 'a.role_uuid')
          .where('r.slug', role)
          .where('a.holder_type', subject.type)
          .where('a.holder_uuid', subject.uuid),
        'a.scope',
        chain
      ),
      'a.expires_at'
    ).first()
    return Boolean(found)
  }

  async deny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void> {
    const perm = await this.findPermission(permission)
    if (!perm) {
      throw new Exception(`Permiso '${permission}' no existe en el catálogo`, { status: 422 })
    }

    const existing = await this.whereScopeIn(
      db
        .from('authz_denies')
        .where('holder_type', subject.type)
        .where('holder_uuid', subject.uuid)
        .where('permission_uuid', perm.uuid),
      'scope',
      [scope]
    ).first()
    if (existing) return

    try {
      await db.table('authz_denies').insert({
        uuid: uuidv7(),
        holder_type: subject.type,
        holder_uuid: subject.uuid,
        permission_uuid: perm.uuid,
        scope_type: scope.type,
        scope_uuid: toDbScopeUuid(scope),
        created_at: new Date(),
      })
    } catch (error) {
      // Carrera: si otro proceso insertó el mismo deny, el unique lo detecta
      // y el resultado deseado ya existe.
      const raced = await this.whereScopeIn(
        db
          .from('authz_denies')
          .where('holder_type', subject.type)
          .where('holder_uuid', subject.uuid)
          .where('permission_uuid', perm.uuid),
        'scope',
        [scope]
      ).first()
      if (!raced) throw error
    }
  }

  async removeDeny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void> {
    const perm = await this.findPermission(permission)
    if (!perm) return

    await this.whereScopeIn(
      db
        .from('authz_denies')
        .where('holder_type', subject.type)
        .where('holder_uuid', subject.uuid)
        .where('permission_uuid', perm.uuid),
      'scope',
      [scope]
    ).delete()
  }

  async listSubjects(role: string, scope: ScopeRef): Promise<SubjectRef[]> {
    const rows = await this.whereActive(
      this.whereScopeIn(
        db
          .from('authz_assignments as a')
          .join('authz_roles as r', 'r.uuid', 'a.role_uuid')
          .where('r.slug', role)
          .where('r.scope_type', scope.type),
        'a.scope',
        [scope]
      ),
      'a.expires_at'
    ).distinct('a.holder_type', 'a.holder_uuid')

    return rows.map((row: any) => ({ type: row.holder_type, uuid: row.holder_uuid }))
  }

  async listRoles(subject: SubjectRef, scope: ScopeRef): Promise<string[]> {
    const rows = await this.whereActive(
      this.whereScopeIn(
        db
          .from('authz_assignments as a')
          .join('authz_roles as r', 'r.uuid', 'a.role_uuid')
          .where('a.holder_type', subject.type)
          .where('a.holder_uuid', subject.uuid),
        'a.scope',
        [scope]
      ),
      'a.expires_at'
    ).distinct('r.slug')
    return rows.map((row: any) => row.slug)
  }

  async listRoleScopes(subject: SubjectRef, scopeType: ScopeType): Promise<ScopeRef[]> {
    const rows = await this.whereActive(
      db
        .from('authz_assignments as a')
        .where('a.holder_type', subject.type)
        .where('a.holder_uuid', subject.uuid)
        .where('a.scope_type', scopeType),
      'a.expires_at'
    ).distinct('a.scope_type', 'a.scope_uuid')
    return rows.map((row: any) => ({ type: row.scope_type, uuid: fromDbScopeUuid(row.scope_uuid) }))
  }

  async listScopes(subject: SubjectRef, permission: string): Promise<ScopeRef[]> {
    const perm = await this.findPermission(permission)
    if (!perm) return []

    const rows = await this.whereActive(
      db
        .from('authz_assignments as a')
        .join('authz_role_permissions as rp', 'rp.role_uuid', 'a.role_uuid')
        .where('rp.permission_uuid', perm.uuid)
        .where('a.holder_type', subject.type)
        .where('a.holder_uuid', subject.uuid),
      'a.expires_at'
    ).distinct('a.scope_type', 'a.scope_uuid')

    const denies = await db
      .from('authz_denies')
      .where('holder_type', subject.type)
      .where('holder_uuid', subject.uuid)
      .where('permission_uuid', perm.uuid)
      .select('scope_type', 'scope_uuid')

    const deniedKeys = new Set(
      denies.map((d: any) => `${d.scope_type}:${fromDbScopeUuid(d.scope_uuid) ?? ''}`)
    )

    const result: ScopeRef[] = []
    for (const row of rows) {
      const candidate: ScopeRef = { type: row.scope_type, uuid: fromDbScopeUuid(row.scope_uuid) }
      const chain = await this.chain(candidate)
      const blocked = chain.some((s) => deniedKeys.has(`${s.type}:${s.uuid ?? ''}`))
      if (!blocked) result.push(candidate)
    }
    return result
  }
}
