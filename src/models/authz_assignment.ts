import { DateTime } from 'luxon'
import { BaseModel, column, belongsTo } from '@adonisjs/lucid/orm'
import type { BelongsTo } from '@adonisjs/lucid/types/relations'
import { compose } from '@adonisjs/core/helpers'
import AuthzRole from './authz_role.js'
import { hasUuid } from '../traits/has_uuid.js'

/**
 * Asignación de rol a un holder polimórfico (users/admins/integrations) en un
 * scope ('app' con scopeUuid null | 'organization' | 'unit'). `expiresAt`
 * pasado = asignación no vigente (el driver la ignora, no la borra).
 */
export default class AuthzAssignment extends compose(BaseModel, hasUuid) {
  public static table = 'authz_assignments'
  public static primaryKey = 'uuid'

  @column({ isPrimary: true })
  declare uuid: string

  @column({ columnName: 'holder_type' })
  declare holderType: string

  @column({ columnName: 'holder_uuid' })
  declare holderUuid: string

  @column({ columnName: 'role_uuid' })
  declare roleUuid: string

  @column({ columnName: 'scope_type' })
  declare scopeType: string

  @column({ columnName: 'scope_uuid' })
  declare scopeUuid: string | null

  @column.dateTime({ columnName: 'expires_at' })
  declare expiresAt: DateTime | null

  @belongsTo(() => AuthzRole, { foreignKey: 'roleUuid' })
  declare role: BelongsTo<typeof AuthzRole>

  @column.dateTime({ autoCreate: true, columnName: 'created_at' })
  declare createdAt: DateTime
}
