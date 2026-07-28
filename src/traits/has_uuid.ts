import { beforeCreate } from '@adonisjs/lucid/orm'
import type { BaseModel } from '@adonisjs/lucid/orm'
import type { NormalizeConstructor } from '@adonisjs/core/types/helpers'
import { v7 as uuidv7 } from 'uuid'

/**
 * Trait para asignar automáticamente UUIDv7 en la PK del modelo.
 * Autodetecta correctamente la primaryKey desde la instancia real.
 */
export const hasUuid = <Model extends NormalizeConstructor<typeof BaseModel>>(
  superclass: Model
) => {
  class WithPrimaryUuidClass extends superclass {
    static selfAssignPrimaryKey = true

    @beforeCreate()
    static generateUuid(model: any) {
      const pk = model.constructor.primaryKey ?? 'id'
      if (!model[pk]) {
        model[pk] = uuidv7()
      }
    }

    /** Devuelve un nuevo UUID v7 (para uso en pivots u otros datos que no son instancias del modelo). */
    static nextUuid(): string {
      return uuidv7()
    }
  }
  return WithPrimaryUuidClass
}
