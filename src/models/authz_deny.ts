import { DateTime } from 'luxon'
import { BaseModel, column } from '@adonisjs/lucid/orm'
import { compose } from '@adonisjs/core/helpers'
import { hasUuid } from '../traits/has_uuid.js'

/**
 * Deny explícito: bloquea UN permiso a un holder en un scope y sus
 * descendientes, aunque un rol se lo conceda. Gana siempre sobre los grants.
 */
export default class AuthzDeny extends compose(BaseModel, hasUuid) {
  public static table = 'authz_denies'
  public static primaryKey = 'uuid'

  @column({ isPrimary: true })
  declare uuid: string

  @column({ columnName: 'holder_type' })
  declare holderType: string

  @column({ columnName: 'holder_uuid' })
  declare holderUuid: string

  @column({ columnName: 'permission_uuid' })
  declare permissionUuid: string

  @column({ columnName: 'scope_type' })
  declare scopeType: string

  @column({ columnName: 'scope_uuid' })
  declare scopeUuid: string | null

  @column.dateTime({ autoCreate: true, columnName: 'created_at' })
  declare createdAt: DateTime
}
