import type { HttpContext } from '@adonisjs/core/http'
import type { NextFn } from '@adonisjs/core/types/http'
import { Exception } from '@adonisjs/core/exceptions'
import authorization from '../../services/main.js'
import type { ScopeRef } from '../types.js'
import { AuthorizationConfigError, RoleIsNotAccessError } from '../errors.js'

/**
 * Enforcement de acceso A UN RECURSO concreto. COMPONE el `authorize` que ya
 * existe: el consumidor dice CÓMO cargar el recurso (`load(ctx, id)`) y en qué
 * `{ scope }` vive, y el middleware pregunta al motor sobre ese scope. No es un
 * modelo ni un driver nuevo: es el borde HTTP del scope de un recurso.
 *
 * El ORDEN de las respuestas ES la propiedad de seguridad — un 403 donde
 * debería ir un 404 filtra qué recursos existen (enumeración):
 *
 *   1. 401  si no hay usuario autenticado (antes de nada).
 *   2. 403  si el `gate(ctx)` del consumidor (una ability previa, p. ej.
 *           «es admin del tenant») lo niega.
 *   3. 404  si el CONTENEDOR no existe (`containerParam`, cuando se declara).
 *   4. 404  si el RECURSO no existe (`load` ⇒ null) — MISMO cuerpo que el 404
 *           del contenedor, para no distinguir «no existe» de «no es tuyo».
 *   5. authorize sobre el `{ scope }` que devolvió `load`, con `permission`
 *           (o `readPermission` en métodos seguros): un `false` aquí también
 *           es 404 con el MISMO cuerpo, NO un 403 — que no puedas verlo no
 *           revela que existe.
 *
 * Invariantes que NO se negocian:
 *  - `AuthorizationBackendError` (503) NUNCA se disfraza de 404/403: si el
 *    backend cae (`gate`/`load`/`authorize` lanzan), el error sube tal cual.
 *    Es lo que distingue «denegado» de «no pude comprobar». El middleware NO
 *    envuelve estas llamadas en try/catch a propósito.
 *  - Prohibido `role`: como `appAccess`, solo acepta `permission`/
 *    `readPermission`. `{ role }` es 500 con receta (membresía no es acceso, y
 *    el deny no la gobierna: toda decisión pasa por `authorize`).
 *  - Sin segundo `authorize`: se llama UNA sola vez. No re-autoriza.
 *
 * Limitación conocida — canal de TEMPORIZACIÓN (auditor Fase 5, ⚪): el status
 * y el cuerpo de «no existe» y «existe pero no es tuyo» son idénticos, pero el
 * TIEMPO no: un id inexistente responde 404 sin round-trip a `authorize`; uno
 * ajeno responde el mismo 404 tras esa llamada. Es inherente a load→authorize
 * (no se puede autorizar el scope de algo que no se ha cargado), no un defecto;
 * quien necesite cerrar el canal iguala el tiempo en su capa (delay constante),
 * no en el middleware.
 *
 * Pureza: el middleware NO importa aliases del consumidor; `load`/`gate` llegan
 * INYECTADOS en las opciones de la ruta.
 *
 * Uso:
 *   router
 *     .get('/orgs/:orgId/documents/:id', [DocumentsController, 'show'])
 *     .use(middleware.resourceAccess({
 *       resource: 'document',
 *       param: 'id',
 *       containerParam: 'orgId',
 *       permission: 'documents:write',
 *       readPermission: 'documents:read',
 *       load: (ctx, id) => Document.query().where('id', id).first(),
 *       gate: (ctx) => ctx.auth.user!.isMemberOf(ctx.params.orgId),
 *     }))
 */
export interface ResourceAccessOptions {
  /**
   * Nombre del recurso. Es la clave bajo la que el recurso cargado (con su
   * scope) se PROPAGA al `ctx` para el controlador (`ctx[resource]`), así que
   * dos `resourceAccess` anidados no se pisan.
   */
  resource: string
  /** Nombre del param de ruta que trae el id del recurso (`ctx.params[param]`). */
  param: string
  /**
   * Nombre del param de ruta del contenedor (p. ej. el tenant de una ruta
   * anidada). Cuando se declara, un contenedor ausente en la ruta es 404 —el
   * MISMO cuerpo que un recurso ausente— y se comprueba ANTES de cargar el
   * recurso. La pertenencia real del recurso al contenedor la comprueba
   * `load` (que ve `ctx.params`): devolver `null` allí es el mismo 404, así que
   * «no existe» y «no está en este contenedor» son indistinguibles.
   */
  containerParam?: string
  /** Permiso requerido (métodos que mutan, y lectura si no hay `readPermission`). */
  permission: string
  /**
   * Permiso requerido en métodos SEGUROS (GET/HEAD). Si se omite, una lectura
   * exige `permission` — nunca es gratis. Suele ser el permiso MENOS
   * privilegiado (ver vs escribir).
   */
  readPermission?: string
  /**
   * Carga el recurso por su id y devuelve dónde vive (`{ scope }`) o `null` si
   * no existe / no es visible. Del consumidor: ve el `ctx` entero (params,
   * usuario). Un throw es «no pude comprobar» (sube como 503), NO un 404.
   */
  load: (
    ctx: HttpContext,
    id: string
  ) => Promise<{ scope: ScopeRef } | null> | { scope: ScopeRef } | null
  /**
   * Ability previa del consumidor (p. ej. «es admin del tenant»). Opcional; si
   * se declara y devuelve `false`, es 403 —una restricción ADICIONAL, evaluada
   * antes de tocar el recurso—. Si se omite, no hay pre-check: la seguridad la
   * da igualmente `authorize`.
   */
  gate?: (ctx: HttpContext) => Promise<boolean> | boolean
}

/** Métodos HTTP seguros: usan `readPermission` si se declara. */
const SAFE_METHODS = new Set(['GET', 'HEAD'])

export default class ResourceAccessMiddleware {
  async handle(ctx: HttpContext, next: NextFn, options: ResourceAccessOptions) {
    // Config PRIMERO, antes de mirar si hay usuario: una ruta mal declarada
    // tiene que saltar en el primer request de desarrollo, autenticado o no.
    if (options && 'role' in (options as object)) {
      throw new RoleIsNotAccessError((options as any).role)
    }
    if (!options?.permission) {
      throw new AuthorizationConfigError(
        "middleware.resourceAccess requiere `{ permission }` (p. ej. resourceAccess({ permission: 'documents:write', ... }))"
      )
    }
    if (!options.param) {
      throw new AuthorizationConfigError(
        'middleware.resourceAccess requiere `{ param }` — el nombre del param de ruta con el id del recurso'
      )
    }
    if (typeof options.load !== 'function') {
      throw new AuthorizationConfigError(
        'middleware.resourceAccess requiere `load(ctx, id)` — cómo cargar el recurso y en qué `{ scope }` vive'
      )
    }
    if (!options.resource) {
      throw new AuthorizationConfigError(
        'middleware.resourceAccess requiere `{ resource }` — el nombre bajo el que se propaga el recurso al controlador'
      )
    }

    // ── 1. 401 ────────────────────────────────────────────────────────────
    const holder = (ctx as any).auth?.user as
      | { uuid: string; __morphMapName?: string }
      | undefined
    if (!holder) {
      return ctx.response.unauthorized({ message: 'No autenticado', statusCode: 401, errors: [] })
    }

    // El holder tiene que ser un subject válido (mismos guards que appAccess).
    // Son errores de programación (500), no de acceso: nunca degradan a 404.
    const morph = holder.__morphMapName
    if (!morph) {
      throw new Exception('El modelo autenticado no tiene @MorphMap — no es un holder válido', {
        status: 500,
      })
    }
    if (!holder.uuid) {
      throw new Exception(
        `El holder '${morph}' no expone 'uuid' — el motor identifica a los holders por uuid, ` +
          `no por la clave primaria del modelo.`,
        { status: 500 }
      )
    }
    const subject = { type: morph, uuid: holder.uuid }

    // ── 2. 403 gate del consumidor ────────────────────────────────────────
    // Sin try/catch: si el gate lanza (backend caído), el 503 sube tal cual.
    if (options.gate && !(await options.gate(ctx))) {
      return ctx.response.forbidden({ message: 'Permiso insuficiente', statusCode: 403, errors: [] })
    }

    // El 404 del contenedor, del recurso ausente y del authorize negativo
    // comparten EXACTAMENTE el mismo cuerpo: nada distingue los tres.
    const notFound = () =>
      ctx.response.notFound({ message: 'Recurso no encontrado', statusCode: 404, errors: [] })

    // ── 3. 404 contenedor (ANTES que el recurso) ──────────────────────────
    if (options.containerParam) {
      const containerId = (ctx as any).params?.[options.containerParam]
      if (!containerId) return notFound()
    }

    // ── 4. 404 recurso ────────────────────────────────────────────────────
    const id = (ctx as any).params?.[options.param]
    if (!id) return notFound()
    // Un throw de `load` NO se atrapa: «no pude comprobar» (503) ≠ «no existe».
    const loaded = await options.load(ctx, String(id))
    if (!loaded) return notFound()

    // ── 5. authorize (UNA vez) sobre el scope del recurso ─────────────────
    const method = String((ctx as any).request?.method?.() ?? 'GET').toUpperCase()
    const permission =
      SAFE_METHODS.has(method) && options.readPermission
        ? options.readPermission
        : options.permission

    if (!(await authorization.authorize(subject, permission, loaded.scope))) {
      // Negado ⇒ 404 con el MISMO cuerpo, NO 403: que no puedas verlo no
      // revela que existe.
      return notFound()
    }

    // El recurso cargado (con su scope) llega al controlador sin recargarlo.
    ;(ctx as any)[options.resource] = loaded
    return next()
  }
}
