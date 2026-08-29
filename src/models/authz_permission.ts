import { DateTime } from 'luxon'
import { BaseModel, column } from '@adonisjs/lucid/orm'
import { compose } from '@adonisjs/core/helpers'
import { hasUuid } from '../traits/has_uuid.js'

/**
 * Permiso del motor de autorización propio. Slug con la misma gramática que
 * las abilities de tokens (M3): `recurso:accion` en minúsculas.
 */
export default class AuthzPermission extends compose(BaseModel, hasUuid) {
  public static table = 'authz_permissions'
  public static primaryKey = 'uuid'

  @column({ isPrimary: true })
  declare uuid: string

  @column()
  declare slug: string

  @column()
  declare description: string | null

  /**
   * Niveles (scope types) cuyos roles pueden llevar este permiso (3B · B5),
   * como JSON (`["app","organization"]`), o `null` = cualquiera. Control de
   * composición, nunca de evaluación.
   */
  @column({ columnName: 'assignable_at' })
  declare assignableAt: string | null

  @column.dateTime({ autoCreate: true, columnName: 'created_at' })
  declare createdAt: DateTime

  @column.dateTime({ autoCreate: true, autoUpdate: true, columnName: 'updated_at' })
  declare updatedAt: DateTime
}
