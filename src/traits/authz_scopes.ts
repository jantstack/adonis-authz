import { scope } from '@adonisjs/lucid/orm'
import db from '@adonisjs/lucid/services/db'
import { systemClock } from '../clock.js'

/**
 * Scopes de query sobre el motor de autorización propio — paridad con los
 * whereRoles/wherePermissions del paquete extirpado, ahora sobre `authz_*`.
 *
 * Filtra holders del modelo con asignación VIGENTE (sin expirar) del rol o
 * permiso, en cualquier scope. Es un listado grueso (¿quién tiene X?): el
 * enforcement fino por scope+denies lo hace `authorization.authorize()`.
 *
 * El morph name del holder sale del decorador @MorphMap del modelo.
 *
 *   Admin.query().withScopes((s) => s.whereRoles('superadmin'))
 *   User.query().withScopes((s) => s.wherePermissions('audit:read'))
 */
export function withAuthzScopes<T extends { new (...args: any[]): {} }>(Base: T) {
  return class extends Base {
    static whereRoles = scope((query: any, ...roles: string[]) => {
      const model = query.model
      const morph = model.prototype.__morphMapName
      const sub = db
        .from('authz_assignments as a')
        .join('authz_roles as r', 'r.uuid', 'a.role_uuid')
        .where('a.holder_type', morph)
        .whereIn('r.slug', roles)
        .where((b) => b.whereNull('a.expires_at').orWhere('a.expires_at', '>', systemClock()))
        .select('a.holder_uuid')
      query.whereIn(model.primaryKey, sub)
    })

    static wherePermissions = scope((query: any, ...permissions: string[]) => {
      const model = query.model
      const morph = model.prototype.__morphMapName
      const sub = db
        .from('authz_assignments as a')
        .join('authz_role_permissions as rp', 'rp.role_uuid', 'a.role_uuid')
        .join('authz_permissions as p', 'p.uuid', 'rp.permission_uuid')
        .where('a.holder_type', morph)
        .whereIn('p.slug', permissions)
        .where((b) => b.whereNull('a.expires_at').orWhere('a.expires_at', '>', systemClock()))
        .select('a.holder_uuid')
      query.whereIn(model.primaryKey, sub)
    })
  }
}
