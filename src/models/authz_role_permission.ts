import { DateTime } from 'luxon'
import { BaseModel, column } from '@adonisjs/lucid/orm'
import { compose } from '@adonisjs/core/helpers'
import { hasUuid } from '../traits/has_uuid.js'

/** Pivot rol ↔ permiso del motor de autorización propio. */
export default class AuthzRolePermission extends compose(BaseModel, hasUuid) {
  public static table = 'authz_role_permissions'
  public static primaryKey = 'uuid'

  @column({ isPrimary: true })
  declare uuid: string

  @column({ columnName: 'role_uuid' })
  declare roleUuid: string

  @column({ columnName: 'permission_uuid' })
  declare permissionUuid: string

  @column.dateTime({ autoCreate: true, columnName: 'created_at' })
  declare createdAt: DateTime
}
