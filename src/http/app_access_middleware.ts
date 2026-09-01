import type { HttpContext } from '@adonisjs/core/http'
import type { NextFn } from '@adonisjs/core/types/http'
import { Exception } from '@adonisjs/core/exceptions'
import authorization from '../../services/main.js'
import { APP_SCOPE } from '../types.js'
import { AuthorizationConfigError, RoleIsNotAccessError } from '../errors.js'

/**
 * Enforcement del ACL de NIVEL APP (gemelo de orgAccess para el scope
 * global). Debe ir DESPUÉS de `middleware.auth(...)` — típicamente con el
 * guard `admins`, aunque funciona con cualquier holder con morph name.
 *
 * Reglas:
 *  - No autenticado → 401.
 *  - Holder sin el permiso requerido a nivel app → 403.
 *  - El ACL decide por IDENTIDAD; el scope del token lo acota
 *    middleware.ability() aparte (el token nunca amplía, solo restringe).
 *  - Solo `permission`. `{ role }` se retiró (L0.6): `hasRole` es membresía
 *    y el deny no la gobierna, así que un PEP sobre un rol era indenegable.
 *    Toda decisión de acceso pasa por `authorize`.
 *
 * Uso: middleware.appAccess({ permission: 'audit:read' })
 */
export interface AppAccessOptions {
  permission: string
}

export default class AppAccessMiddleware {
  async handle(ctx: HttpContext, next: NextFn, options: AppAccessOptions) {
    // Antes de mirar si hay usuario: una ruta mal declarada tiene que saltar
    // en el primer request de desarrollo, autenticado o no.
    if (options && 'role' in (options as object)) {
      throw new RoleIsNotAccessError((options as any).role)
    }
    if (!options?.permission) {
      throw new AuthorizationConfigError(
        "middleware.appAccess requiere `{ permission }` (p. ej. appAccess({ permission: 'audit:read' }))"
      )
    }

    const holder = (ctx as any).auth?.user as { uuid: string; __morphMapName?: string } | undefined
    if (!holder) {
      return ctx.response.unauthorized({ message: 'No autenticado', statusCode: 401, errors: [] })
    }

    // El morph name lo estampa el decorador @MorphMap en el prototype.
    const morph = holder.__morphMapName
    if (!morph) {
      throw new Exception('El modelo autenticado no tiene @MorphMap — no es un holder válido', {
        status: 500,
      })
    }

    // El motor identifica a los holders por uuid. Un modelo con clave
    // primaria numérica llega aquí con `uuid: undefined` y, sin este guard,
    // el fallo aparece varias capas más abajo como un error de SQL ilegible.
    if (!holder.uuid) {
      throw new Exception(
        `El holder '${morph}' no expone 'uuid' — el motor identifica a los holders por uuid, ` +
          `no por la clave primaria del modelo.`,
        { status: 500 }
      )
    }

    const subject = { type: morph, uuid: holder.uuid }

    if (!(await authorization.authorize(subject, options.permission, APP_SCOPE))) {
      return ctx.response.forbidden({
        message: 'Permiso insuficiente',
        statusCode: 403,
        errors: [],
      })
    }

    return next()
  }
}
