import { Exception } from '@adonisjs/core/exceptions'

/**
 * El backend de autorización no respondió.
 *
 * Es el tercer estado de una pregunta de permisos, y merece un tipo propio:
 *
 *   no tienes permiso        → `false`
 *   la pregunta no es válida → Exception 422 (permiso/rol inexistente)
 *   no se pudo preguntar     → esto, 503
 *
 * Dos razones para envolver el error del driver en vez de dejarlo pasar:
 *
 * 1. **La abstracción no debe tener fugas.** Sin esto escapaba un `FgaError`
 *    del SDK de OpenFGA, así que distinguir "backend caído" obligaba a
 *    importar el SDK — acoplando el call-site al backend que este paquete
 *    existe para abstraer. Cambiar de driver habría obligado a cambiar los
 *    `catch`.
 * 2. **Nadie debería escribir `try/catch` para estar a salvo.** Con `status`
 *    503, el manejador de excepciones responde solo, y con el código correcto:
 *    no es que la aplicación esté rota (500), es que una dependencia no está
 *    disponible.
 *
 * Lo que NO se hace es capturar y devolver `false`. Denegar en silencio
 * durante una caída deja a todos sin permisos sin decir por qué, y manda a
 * buscar un rol mal configurado que no existe. Se deniega igual; lo que
 * cambia es el diagnóstico.
 */
export class AuthorizationBackendError extends Exception {
  static status = 503
  static code = 'E_AUTHZ_BACKEND_UNAVAILABLE'

  constructor(driver: string, operation: string, cause: unknown) {
    super(`El backend de autorización '${driver}' no respondió (${operation})`, { cause })
  }
}

/**
 * El backend respondió tarde: venció `timeoutMs`. Es un `AuthorizationBackendError`
 * (503, se maneja igual) con código propio, porque para operaciones "no responde"
 * y "responde lento" son incidentes distintos: el segundo suele ser saturación, no
 * caída, y el remedio (subir el deadline, escalar el backend) es otro.
 */
export class AuthorizationBackendTimeoutError extends AuthorizationBackendError {
  static code = 'E_AUTHZ_BACKEND_TIMEOUT'

  constructor(driver: string, operation: string, timeoutMs: number, cause?: unknown) {
    super(driver, operation, cause)
    this.message = `El backend de autorización '${driver}' no respondió en ${timeoutMs} ms (${operation})`
  }
}

/**
 * El resolutor de ancestros del consumidor lanzó. Es una dependencia más de
 * cada pregunta (el árbol de scopes), así que su caída se clasifica como la
 * del backend: 503, nunca `false`, nunca el error crudo del consumidor.
 */
export class ScopeResolverError extends Exception {
  static status = 503
  static code = 'E_AUTHZ_RESOLVER_FAILED'

  constructor(operation: string, cause: unknown) {
    super(`El resolutor de ancestros de scopes falló (${operation})`, { cause })
  }
}

/**
 * Un componente de identidad (holder, scope, rol, permiso) no cumple el formato
 * del motor. Es una pregunta inválida (422), no un "sin permiso": aceptarla
 * fundiría identidades distintas en una (`user:undefined`, `{app, uuid}` que
 * colapsa a la raíz) o produciría ids que otro backend no puede representar.
 */
export class InvalidIdentityError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_INVALID_IDENTITY'
}

/**
 * Un slug de rol/permiso no cumple la gramática del catálogo: formato,
 * longitud, nombre reservado o familia de prefijos reservada. 422 porque es la
 * pregunta la que está mal formada; el catálogo no se consulta.
 */
export class InvalidSlugError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_INVALID_SLUG'
}

/**
 * La configuración del consumidor es contradictoria (p. ej. `holderTypes` no
 * inyectivo). 500: la aplicación está mal construida, no hay pregunta que
 * responder hasta que se arregle.
 */
export class AuthorizationConfigError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_CONFIG'
}

/**
 * Invariante interno del motor violado (una escritura sin scopes, un batchCheck
 * incompleto). 500: es un bug del paquete o de quien lo extiende, no del
 * llamante ni del backend.
 */
export class AuthorizationInternalError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_INTERNAL'
}

/**
 * El scope no existe para el consumidor (`resolveChain` devolvió `null`).
 * En lectura el motor responde `false` sin más; en escritura es 422: conceder
 * o denegar en un scope que nadie reconoce dejaría un hecho huérfano que
 * ningún árbol volverá a alcanzar — o, peor, que resucitaría si el uuid se
 * reutiliza (L0.3, N5).
 */
export class UnknownScopeError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_UNKNOWN_SCOPE'
}

/**
 * Se preguntó por un scope que no es la raíz y el driver no tiene resolutor
 * de ancestros. Antes el paquete suplía un default plano ("todo cuelga de
 * app") que convertía cualquier scope inventado en descendiente de la raíz.
 * 422 y no 500: la raíz sigue funcionando; lo que no existe en este
 * despliegue son los niveles intermedios.
 */
export class NoScopeResolverError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_NO_SCOPE_RESOLVER'
}

/**
 * Rol fuera del catálogo para ese nivel (pregunta inválida, 422). Con
 * `scopeType` se buscó por `(slug, scopeType)`; sin él, por uuid (3B ·
 * `purgeRole`, `updateScopedRole`, `deleteScopedRole`).
 */
export class UnknownRoleError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_UNKNOWN_ROLE'

  constructor(slugOrUuid: string, scopeType?: string) {
    super(
      scopeType === undefined
        ? `Rol con uuid '${slugOrUuid}' no existe en el catálogo`
        : `Rol '${slugOrUuid}' no existe en el catálogo para el nivel '${scopeType}'`
    )
  }
}

/**
 * El rol existe pero es LOCAL a un scope que no está en la cadena del scope
 * de la escritura (3B · B2): un rol de la organization A no existe en B ni
 * en la raíz. 422 y nada escrito — es la barrera que impide asignar el rol
 * de un tenant fuera de su contenedor. En lectura no hay error: el rol
 * simplemente no concede ni es membresía fuera de su owner.
 */
export class RoleNotVisibleError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_ROLE_NOT_VISIBLE'
}

/**
 * `updateScopedRole`/`deleteScopedRole` sobre un rol GLOBAL (3B · B3). Los
 * roles del catálogo del config se cambian en el config y se sincronizan
 * (`syncAuthzCatalog`); por la API de delegación son inmutables, o un
 * administrador de tenant podría editar el catálogo de la plataforma.
 */
export class RoleImmutableError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_ROLE_IMMUTABLE'
}

/**
 * Un rol de nivel L no puede llevar (o ser asignado llevando) un permiso
 * cuyo `assignableAt` no incluye L (3B · B5). Es un control de COMPOSICIÓN
 * —`syncAuthzCatalog`, `defineScopedRole`, `updateScopedRole` y, por defensa
 * en profundidad, `grant`—, nunca de evaluación: lo ya asignado sigue
 * concediendo (invariante 1).
 */
export class RoleNotAssignableAtError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_ROLE_NOT_ASSIGNABLE_AT'
}

/**
 * `defineScopedRole`/`updateScopedRole` con un permiso que el actor no puede
 * delegar (3B · B3): no está en `config.delegablePermissions` (lista blanca;
 * vacía por defecto: nadie delega nada hasta declararla), no existe en el
 * catálogo, o el actor no lo tiene EFECTIVO en el owner (no lo concede
 * ningún rol suyo en la cadena, o lo tiene denegado — auditor C2: un deny
 * no se lava componiendo un rol para un títere).
 */
export class PermissionNotDelegableError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_PERMISSION_NOT_DELEGABLE'
}

/**
 * El `rank` de un rol local no cumple `0 < rank < min(rank del actor, rank
 * máximo global)` (3B · B3), o el actor intenta tocar un rol de rango ≥ al
 * suyo. Es policy de ESCRITURA (composición y delegación); el motor sigue sin
 * evaluar `rank` en `authorize` (invariante 8).
 */
export class RankExceededError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_RANK_EXCEEDED'
}

/**
 * Dos catálogos de `config.catalogs` declaran el mismo rol `(slug, scopeType)`
 * o el mismo permiso. La identidad de un rol es ese par: compartirla es
 * compartir el rol, y el prune del segundo sync borraría los vínculos del
 * primero en silencio (D3). Un rol pertenece a exactamente un catálogo; se
 * rechaza antes de tocar la base, en el sync y en el diff.
 */
export class CatalogConflictError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_CATALOG_CONFLICT'
}

/** Permiso fuera del catálogo (pregunta inválida en `deny`/catálogo, 422). */
export class UnknownPermissionError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_UNKNOWN_PERMISSION'

  constructor(slug: string) {
    super(`Permiso '${slug}' no existe en el catálogo`)
  }
}

/**
 * `appAccess({ role })` se retiró (L0.6). `hasRole` es una consulta de
 * MEMBRESÍA y el deny no la gobierna: un middleware sobre ella era un punto de
 * decisión indenegable (un holder con todos sus permisos denegados seguía
 * pasando). 500: es la ruta la que está mal declarada, y debe saltar en el
 * primer request de desarrollo, no en producción.
 */
export class RoleIsNotAccessError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_ROLE_IS_NOT_ACCESS'

  constructor(role: unknown) {
    super(
      `appAccess({ role: ${JSON.stringify(role)} }) ya no existe: un rol es membresía, no acceso, ` +
        `y el deny no lo gobierna. Receta: crea un permiso que represente ese acceso ` +
        `(p. ej. 'admin:access'), vincúlalo al rol en el catálogo y protege la ruta con ` +
        `appAccess({ permission: 'admin:access' }).`
    )
  }
}

/**
 * Colgar `child` de `parent` cerraría un ciclo (el padre desciende del hijo,
 * o son el mismo). FGA no detecta ciclos de `parent`: los evalúa, y un grant
 * en cualquier nodo del ciclo concede en todos, raíz incluida (S2). La única
 * barrera es el paquete, antes de escribir nada.
 */
export class ScopeCycleError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_SCOPE_CYCLE'
}

/**
 * `purgeScope` terminó y el backend todavía muestra hechos del scope. Un
 * número parcial que no lanza deja grants huérfanos e indenegables (S6, B2);
 * se lanza para que el consumidor NO confirme el borrado de su entidad.
 */
export class PurgeIncompleteError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_PURGE_INCOMPLETE'
}

/**
 * `openfga:import` sobre un store con tuplas y sin `--reconcile`. En FGA la
 * condición no es parte de la clave: escribir "ignorando duplicados" sobre
 * una tupla existente dejaba la caducidad vieja (o ninguna) y reportaba
 * éxito (S7). 409: el estado del destino no es el que el comando espera.
 */
export class StoreNotEmptyError extends Exception {
  static status = 409
  static code = 'E_AUTHZ_STORE_NOT_EMPTY'
}

/**
 * `config.requireActor: true` y una escritura llegó sin `actor` (2.1, B7).
 * 422 antes de tocar el driver: una auditoría que exige saber quién ordenó
 * cada cambio no puede tener huecos, y el hueco no se descubre después.
 */
export class ActorRequiredError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_ACTOR_REQUIRED'
}

/**
 * `within` no está en la cadena del scope de la escritura (2.1, B1): el
 * call-site declaró "dentro de MI tenant" y el scope pertenece a otro. 422 y
 * nada escrito: es la barrera contra el administrador de A que concede en
 * una unit de B pasando un uuid ajeno. Vale para las SEIS escrituras del
 * manager (2D · F2): quitar un deny ajeno es conceder, revocar un rol ajeno
 * es sabotear, y purgar o recolgar un scope ajeno es lo mismo.
 */
export class NotWithinError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_NOT_WITHIN'
}

/**
 * `config.requireWithin` (`true` o `'non-root'`) y una escritura llegó sin
 * `within` (2.1, B1; las seis desde 2D · F2). 422 antes del driver: la
 * contención opt-in (auditor E2) deja de serlo cuando el consumidor lo declara.
 */
export class WithinRequiredError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_WITHIN_REQUIRED'
}

/**
 * `config.requireWithin: 'non-root'` y una escritura declaró `within: APP_SCOPE`
 * (2.1, 2D · F2). La raíz contiene todo, así que como `within` no acota nada:
 * era el comodín con el que un call-site de tenant satisfacía `requireWithin`
 * sin decir de qué tenant es (auditor 9). 422 y nada escrito; la plataforma,
 * que sí escribe en la raíz, usa `manager.driver()` o una config sin el flag.
 */
export class WithinRootForbiddenError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_WITHIN_ROOT_FORBIDDEN'
}

/**
 * Una enumeración de scopes superó su cota (2.1, B2/B3): `authorizedScopes`
 * por encima de `maxScopes`, o un `descendantsOf` que devolvió más de
 * `maxNodes`. 422 y NUNCA una lista parcial: un listado truncado en silencio
 * es la forma más discreta de fail-open/fail-closed. El llamante acota la
 * pregunta o sube la cota a sabiendas.
 */
export class TooManyScopesError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_TOO_MANY_SCOPES'
}

/**
 * `sqlDescendantsOf` sobre un dialecto sin observación (2.1, B2): hoy solo PG
 * y SQLite corren la CTE en la suite; MySQL entra en 2.5 con harness propio.
 * 500: config del consumidor, salta en la primera llamada.
 */
export class UnsupportedDialectError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_UNSUPPORTED_DIALECT'
}

/**
 * `hierarchicalScopeResolver` superó `maxDepth` (2.1, B4). Truncar la cadena
 * perdería la raíz —y con ella cualquier deny en `app`—: fail-open. 500 y no
 * 503: el árbol del consumidor es más profundo de lo declarado, no hay
 * reintento que lo arregle.
 */
export class ScopeTooDeepError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_SCOPE_TOO_DEEP'
}

/**
 * Una primitiva de 2.1 necesita un método OPCIONAL del puerto que el driver
 * activo no implementa (2.1, B5): se nombra el método y se lanza. 500 porque
 * es el despliegue el que está incompleto; nunca se simula la respuesta —un
 * `[]` en `listDenies` sería "sin denies", fail-open.
 */
export class UnsupportedOperationError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_UNSUPPORTED'

  constructor(method: string, primitive: string, driver: string) {
    super(
      `${primitive} necesita '${method}' y el driver '${driver}' no lo implementa: es un método opcional del ` +
        `puerto (2.1) que este driver tiene que añadir para usar esta primitiva.`
    )
  }
}

/**
 * Una vista de `forRequest()` se usó para LEER después de `maxAgeMs` (2D ·
 * F9, auditor 5). El memo de ancestros de la vista es correcto durante un
 * request y peligroso guardado en un módulo: tras un `scopes.moved` serviría
 * la cadena vieja para siempre (cruce de tenant). 500 y ruidoso: es un bug
 * del consumidor (la vista sobrevivió a su request), no un "sin permiso".
 */
export class ViewExpiredError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_VIEW_EXPIRED'
}

/**
 * `authorizedScopes` sin `scopes.descendantsOf` en el config (2.1, B3). 500
 * y nunca `none`: un "ningún scope" sin haber mirado el árbol sería un
 * fail-closed mentiroso que el consumidor tomaría por respuesta.
 */
export class NoDescendantsResolverError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_NO_DESCENDANTS_RESOLVER'
}
