import { scope } from '@adonisjs/lucid/orm'
import db from '@adonisjs/lucid/services/db'
import { isClock, systemClock } from '../clock.js'
import type { Clock } from '../clock.js'
import { AuthorizationConfigError } from '../errors.js'
import { dialectOf, sqlExpiryCodec } from '../drivers/sql_expiry.js'

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
 *
 * El reloj (2.5-B · K6, CR#5): la vigencia se decide con el reloj del
 * sistema, salvo que se pase uno al componer — `compose(BaseModel,
 * withAuthzScopes({ clock }))`. El trait no ve el manager ni su
 * `config.clock`: si tu app fija el reloj, pásale el MISMO aquí; si no,
 * este listado y `authorize` pueden discrepar sobre lo que ya venció.
 */
export interface AuthzScopesOptions {
  /** Reloj con el que se decide «vigente» (default: `systemClock`). */
  clock?: Clock
}

type Constructor = { new (...args: any[]): {} }

/** Lo que el trait añade al modelo: dos scopes de query. */
export interface AuthzScopesStatics {
  whereRoles: ReturnType<typeof scope<any, (query: any, ...roles: string[]) => void>>
  wherePermissions: ReturnType<typeof scope<any, (query: any, ...permissions: string[]) => void>>
}
export type WithAuthzScopes<T extends Constructor> = T & AuthzScopesStatics

/** La clave primaria del modelo comparable con `holder_uuid` en cualquier motor (K3). */
function comparablePrimaryKey(query: any): unknown {
  // En PostgreSQL una PK `uuid` nativa contra un subquery `varchar(64)` es
  // el error 42883 («operator does not exist: uuid = character varying»):
  // se compara como texto. MySQL y SQLite coaccionan y la columna vale tal
  // cual. Se castea la PK y no el subquery: castear `holder_uuid` a `uuid`
  // reventaría con un holder de OTRO morph cuyo id no sea un UUID.
  const column = `${query.model.table}.${query.model.primaryKey}`
  return dialectOf(db.connection()) === 'postgres' ? db.raw('CAST(?? AS text)', [column]) : column
}

function mixin<T extends Constructor>(Base: T, clock: Clock): WithAuthzScopes<T> {
  /** `expires_at` vigente con el reloj del trait y el codec del motor (K2: en MySQL, cadena UTC). */
  const active = (b: any) =>
    b.whereNull('a.expires_at').orWhere('a.expires_at', '>', sqlExpiryCodec(db.connection()).bind(clock()) as any)

  return class extends Base {
    static whereRoles = scope((query: any, ...roles: string[]) => {
      const model = query.model
      const morph = model.prototype.__morphMapName
      const sub = db
        .from('authz_assignments as a')
        .join('authz_roles as r', 'r.uuid', 'a.role_uuid')
        .where('a.holder_type', morph)
        .whereIn('r.slug', roles)
        .where(active)
        .select('a.holder_uuid')
      query.whereIn(comparablePrimaryKey(query), sub)
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
        .where(active)
        .select('a.holder_uuid')
      query.whereIn(comparablePrimaryKey(query), sub)
    })
  }
}

/**
 * Como mixin directo (`compose(BaseModel, withAuthzScopes)`: reloj del
 * sistema) o con opciones (`compose(BaseModel, withAuthzScopes({ clock }))`).
 * Una sola firma genérica y no dos overloads: TypeScript solo propaga la
 * inferencia de orden superior de `compose` (`A` = la clase mezclada) cuando
 * el argumento tiene UNA firma; con overloads `compose(BaseModel,
 * withAuthzScopes)` perdía los estáticos del modelo.
 */
export function withAuthzScopes<T extends Constructor | AuthzScopesOptions>(
  arg: T
): T extends Constructor ? WithAuthzScopes<T> : <U extends Constructor>(Base: U) => WithAuthzScopes<U>
export function withAuthzScopes(arg?: Constructor | AuthzScopesOptions): unknown {
  if (typeof arg === 'function') return mixin(arg, systemClock)
  const options = arg ?? {}
  if (options.clock !== undefined && !isClock(options.clock)) {
    throw new AuthorizationConfigError(
      `withAuthzScopes: 'clock' debe ser una función () => Date (llegó ${typeof options.clock})`
    )
  }
  const clock = options.clock ?? systemClock
  return <U extends Constructor>(Base: U) => mixin(Base, clock)
}
