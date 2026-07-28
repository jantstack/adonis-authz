import { DateTime } from 'luxon'
import { BaseModel, column, manyToMany } from '@adonisjs/lucid/orm'
import type { ManyToMany } from '@adonisjs/lucid/types/relations'
import { compose } from '@adonisjs/core/helpers'
import AuthzPermission from './authz_permission.js'
import { hasUuid } from '../traits/has_uuid.js'

/**
 * Rol del motor de autorización propio. `scopeType` indica a qué nivel es
 * asignable ('app' | 'organization' | 'unit'); el slug es único por nivel.
 */
export default class AuthzRole extends compose(BaseModel, hasUuid) {
  public static table = 'authz_roles'
  public static primaryKey = 'uuid'

  @column({ isPrimary: true })
  declare uuid: string

  @column()
  declare slug: string

  @column()
  declare name: string

  @column()
  declare description: string | null

  @column({ columnName: 'scope_type' })
  declare scopeType: string

  /** Rango de privilegio (mayor = más poder) — lo consume la policy de asignación. */
  @column()
  declare rank: number

  @manyToMany(() => AuthzPermission, {
    pivotTable: 'authz_role_permissions',
    localKey: 'uuid',
    pivotForeignKey: 'role_uuid',
    relatedKey: 'uuid',
    pivotRelatedForeignKey: 'permission_uuid',
    pivotTimestamps: { createdAt: 'created_at', updatedAt: false },
  })
  declare permissions: ManyToMany<typeof AuthzPermission>

  @column.dateTime({ autoCreate: true, columnName: 'created_at' })
  declare createdAt: DateTime

  @column.dateTime({ autoCreate: true, autoUpdate: true, columnName: 'updated_at' })
  declare updatedAt: DateTime
}
