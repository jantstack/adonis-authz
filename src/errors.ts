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
