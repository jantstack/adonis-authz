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
