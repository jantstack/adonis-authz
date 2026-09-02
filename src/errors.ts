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

  /**
   * **`assertWrite` devolvió una promesa** (2.4.0-alpha.3 · D3, hallazgo H2).
   * `assertWrite(ref): void` es SÍNCRONO y puro a propósito (R-13), pero
   * TypeScript no lo defiende: `assertWrite: async (ref) => { throw … }`
   * compila —una función que devuelve `Promise<void>` es asignable a `void`—,
   * y hasta alpha.3 la promesa se descartaba y la ESCRITURA ENTRABA (un gate
   * de policy que no rechaza nada, en silencio). Se cierra fail-closed: 500
   * ANTES de tocar el driver, nombrando la causa y la receta. La letra la
   * fija `tests/relations_events_docs.spec.ts` byte a byte.
   */
  static asyncAssertWrite(operation: string): AuthorizationConfigError {
    return new AuthorizationConfigError(
      `${operation}: assertWrite devolvió una promesa (thenable) y tiene que ser SÍNCRONO y puro (R-13): ` +
        `el manager no la espera, así que un rechazo asíncrono no habría rechazado nada y la escritura ` +
        `habría entrado (fail-open). No se ha tocado el driver. La policy que necesita actor, base de datos ` +
        `o await va en el servicio del consumidor, ANTES de llamar a relate/unrelate; assertWrite solo ` +
        `recibe la referencia de la tupla y lanza o vuelve.`
    )
  }

  /**
   * **`assertWrite` devolvió un VEREDICTO** (2.4.0-alpha.3, cierre del 🟠 3 /
   * 🟡 4 del auditor): `assertWrite: (ref) => allowed.has(ref.object.type)`
   * compila bajo `--strict` (cualquier retorno es asignable a `void`) y hasta
   * el cierre el `false` se IGNORABA y la escritura entraba — el mismo
   * fail-open que H2, y más frecuente que el `async`. `assertWrite` no
   * devuelve veredictos: LANZA o no lanza. Todo retorno distinto de
   * `undefined` es 500 ANTES del driver — también un `true` (un veredicto
   * positivo es el mismo error de modelo: quien lo escribió cree que el
   * `false` deniega) y también una FUNCIÓN con `.then` (el thenable que no
   * es `typeof 'object'` y esquivaba la guarda de H2).
   */
  static assertWriteReturned(operation: string, result: unknown): AuthorizationConfigError {
    if (isThenable(result)) return AuthorizationConfigError.asyncAssertWrite(operation)
    const shape = result === null ? 'null' : Array.isArray(result) ? 'array' : typeof result
    return new AuthorizationConfigError(
      `${operation}: assertWrite devolvió un valor (${shape}) y assertWrite no devuelve veredictos: LANZA ` +
        `para rechazar o vuelve sin valor para permitir (R-13). Un 'false' devuelto no denegaba nada y la ` +
        `escritura entraba (fail-open); un 'true' es el mismo error de modelo. No se ha tocado el driver. ` +
        `La policy que necesita actor, base de datos o await va en el servicio del consumidor, ANTES de ` +
        `llamar a relate/unrelate.`
    )
  }
}

/** Un thenable, sea objeto o FUNCIÓN con `.then` (la forma que esquivaba `typeof result === 'object'`). */
export function isThenable(value: unknown): boolean {
  return (
    value !== null &&
    (typeof value === 'object' || typeof value === 'function') &&
    typeof (value as { then?: unknown }).then === 'function'
  )
}

/**
 * **Marca de ESCRITURA PARCIAL** (invariante 13, `2.4.0-alpha.3`, cierre del
 * 🟡 6 del auditor). Una escritura del puerto que NO es una sola sentencia ni
 * un solo `Write` —la purga de `openfga`, que recorre ortografías × tipos con
 * varios `Read`+`deleteTuples`— puede fallar DESPUÉS de haber borrado parte:
 * ese fallo no es «esa escritura no ocurrió» (que es lo que un 503 no-timeout
 * significa para una escritura atómica) sino «puede haber ocurrido», lo mismo
 * que un deadline vencido. El driver marca el error con `markPartialWrite`
 * antes de propagarlo, y el manager (`#write`) notifica `onRelationWrite` con
 * `indeterminate: true` ANTES de propagar, exactamente como con
 * `AuthorizationBackendTimeoutError`. La marca es una propiedad
 * (`partialWrite: true`) y no una clase: el error que se propaga conserva su
 * clase y su `code` (503 `E_AUTHZ_BACKEND_UNAVAILABLE`, 500
 * `E_AUTHZ_PURGE_INCOMPLETE`…) — lo que cambia es solo la auditoría. Un driver
 * de terceros cuya purga sea multi-request tiene el mismo deber.
 */
export function markPartialWrite<E extends object>(error: E): E & { partialWrite: true } {
  try {
    Object.defineProperty(error, 'partialWrite', { value: true, enumerable: false, configurable: true })
  } catch {
    // Cierre-2 (⚪ 4 del re-ataque): un error CONGELADO (`Object.freeze`, un SDK
    // o una capa intermedia) no admite la propiedad. Lanzar aquí sustituiría el
    // 503/500 real por un `TypeError` sin `code` ni `status`, justo en el camino
    // de una purga que ya borró: se propaga el ORIGINAL sin marca (se pierde el
    // `indeterminate` de esa purga, no la clasificación del error).
  }
  return error as E & { partialWrite: true }
}

/** ¿El error viene marcado como escritura parcial (`markPartialWrite`)? */
export function isPartialWrite(error: unknown): boolean {
  return error !== null && typeof error === 'object' && (error as { partialWrite?: unknown }).partialWrite === true
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
 * En la cadena del scope de la pregunta hay MÁS DE UN rol visible con ese
 * `(slug, nivel)` (3D · M1): dos locales de owners distintos que un
 * `scopes.moved` juntó, o un local que tapa a un global. El slug ya no
 * identifica un rol y elegir uno («el owner más cercano gana») convertía un
 * homónimo en una escalada de privilegios (auditor V1/V2/V3): la ambigüedad
 * es un ERROR, no una regla de resolución. Toda ruta que direccione por slug
 * —`grant`, `revoke` por uuid, `hasRole`, `listSubjects`— falla CERRADA con
 * 422 nombrando los uuids y sus owners; la forma sin ambigüedad posible es
 * `{ uuid }` (`RoleQuery`). `authorize` no pasa por aquí: no direcciona por
 * slug (lo asignado concede lo que su rol vincula, invariante 1).
 */
export class AmbiguousRoleError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_AMBIGUOUS_ROLE'
}

/**
 * El `scopeType` de un rol local no es el nivel de su owner ni uno que
 * cuelgue de él (3E · P1, auditor A1). Un rol de nivel SUPERIOR al owner no
 * es visible en ninguna parte —no concede, no es membresía, nadie lo puede
 * asignar— pero OCUPA ese `(slug, nivel)`: bloqueaba el `defineScopedRole`
 * del dueño del árbol y, hasta 3E, el `syncAuthzCatalog` entero de la
 * plataforma. Es squatting con forma de spec, como `permissions: []` (3D ·
 * N3): 422. Los niveles que cuelgan del owner los declara el consumidor con
 * `scopes.descendantsOf`; sin él solo se admite el nivel del owner.
 */
export class RoleLevelAboveOwnerError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_ROLE_LEVEL_ABOVE_OWNER'
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
 * Una escritura del driver `openfga` chocó una y otra vez con otra
 * transacción sobre las MISMAS tuplas (3b-2f · R3). FGA responde
 * `Aborted` (HTTP 409) cuando dos `Write` transaccionales tocan una tupla a
 * la vez, y responde `write_failed_due_to_invalid_input` cuando la tupla ya
 * existía: las dos dicen "otro escritor llegó antes", y el driver las trata
 * releyendo y re-aplicando. Si tras varias vueltas el store sigue en
 * conflicto, el llamante se entera con un **409** —el estado del destino no
 * es el que esta escritura esperaba, y reintentar es lo correcto—, nunca con
 * un 503 "el backend no respondió": respondió, y dijo exactamente qué pasa.
 */
export class WriteConflictError extends Exception {
  static status = 409
  static code = 'E_AUTHZ_WRITE_CONFLICT'
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

  constructor(method: string, primitive: string, driver: string, hint?: string) {
    super(
      `${primitive} necesita '${method}' y el driver '${driver}' no lo implementa: es un método opcional del ` +
        `puerto (2.1) que este driver tiene que añadir para usar esta primitiva.` + (hint ? ` ${hint}` : '')
    )
  }

  /**
   * **Puerta 1 de `{ transaction }`** (L-2, panel `{trx}` (C)): la operación
   * pidió escribir en la transacción del consumidor y el driver activo no
   * declara `transactionalWrites: true`. 500 y no 422 por precedente
   * (`membersOf`, `purgeRole`): no es una pregunta mal formada, es un
   * despliegue que no casa con lo que se le pidió. La letra lleva la salida.
   */
  static transactional(operation: string, driver: string, port: 'roles' | 'relations'): UnsupportedOperationError {
    const error = new UnsupportedOperationError('transactionalWrites', operation, driver)
    error.message =
      `${operation}: se pidió escribir en la transacción del consumidor ({ transaction }) y el driver '${driver}' ` +
      `declara transactionalWrites: false (o no la declara): no puede inscribir la escritura en tu transacción ` +
      `(«los dos o ninguno» sería falso; en openfga una tupla no entra en una transacción SQL). No se ha tocado el ` +
      `driver. Salidas: usa el driver 'database' para ${port === 'roles' ? 'los hechos' : 'las relaciones'}, o ` +
      `declara requireTransactionalWrites: true en config/authorization.ts` +
      `${port === 'relations' ? ' (o en relations.requireTransactionalWrites)' : ''} para que esto falle al ARRANCAR ` +
      `en vez de en esta ruta. Sin { transaction } la misma llamada entra.`
    return error
  }

  /**
   * **El mismo rechazo, dicho por el DRIVER `openfga`** (L-5, defensa en
   * profundidad como F-05 en L-0): `manager.driver()` es la salida documentada
   * de las barreras y con `{ transaction }` entraría por aquí saltándose la
   * puerta 1; el driver no puede intentar un `Write` que finja ir en la
   * transacción del consumidor. Misma clase, mismo `code`, misma letra; la
   * frase final dice que no hay salida por el driver — la alternativa que SÍ
   * existe para el ÁRBOL es la outbox de scopes (encola en tu transacción);
   * para HECHOS y relaciones no hay outbox (descartada por el panel `{trx}`:
   * fail-open medido).
   */
  static transactionalDriver(operation: string, driver: string, port: 'roles' | 'relations'): UnsupportedOperationError {
    const error = UnsupportedOperationError.transactional(operation, driver, port)
    error.message +=
      ` Rechazado por el DRIVER '${driver}' (no por el manager): entrar por manager.driver() no es una salida — ` +
      `una tupla del store no puede inscribirse en tu transacción ni fingirlo. Para el ÁRBOL de scopes la salida ` +
      `que existe es scopes.outbox (encola en tu transacción y authz:scopes:relay aplica); para hechos y relaciones no hay outbox.`
    return error
  }

  /**
   * La API de delegación no admite `{ transaction }` (L-2, §1.4 del veredicto):
   * escribe el catálogo por `withAuthzCatalogWrite`, que ES el serializador
   * entre procesos (invariante 14); moverla al commit del consumidor lo anula.
   */
  static transactionalCatalog(operation: string): UnsupportedOperationError {
    const error = new UnsupportedOperationError('transactionalWrites', operation, 'catalog')
    error.message =
      `${operation}: { transaction } no se admite en la API de delegación: el catálogo se escribe por ` +
      `withAuthzCatalogWrite (cerrojo de la fila de versión + bump como última sentencia, invariante 14), que es el ` +
      `serializador del catálogo entre procesos; inscribirlo en tu transacción lo anularía. Solo grant/revoke/deny/` +
      `removeDeny (hechos) y relate/unrelate/purge* (relaciones) admiten { transaction }.`
    return error
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

/**
 * `pruneOrphanRoles({ force: true })` iba a purgar una fracción del catálogo
 * local que solo tiene sentido si el ÁRBOL se ha quedado ciego (3b-0b · AA2,
 * auditor 3b-0): TODOS los owners distintos huérfanos, o más del 50 % de los
 * roles locales. Esa es exactamente la firma de un `resolveChain` filtrado
 * por el tenant de la petición —patrón normal en multi-tenant— o corriendo
 * sin contexto (un comando, una réplica atrasada): devuelve `null` para
 * todo, así que TODO rol local parece huérfano y una pasada con `--force` se
 * lleva el catálogo local de todos los tenants. 500 y no 422 porque el
 * error está en el despliegue, no en la pregunta; el barrido legítimo de una
 * poda grande de verdad pasa con `allowMassPurge: true`
 * (`--allow-mass-purge`), que es una decisión humana, no un default.
 */
export class MassPurgeRefusedError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_MASS_PURGE_REFUSED'
}

/**
 * Un `purgeRole` falló a mitad del barrido de `prune-orphans`.
 *
 * La purga NO es transaccional entre roles: cada `purgeRole` es atómico, pero
 * si el tercero revienta, los dos primeros ya están borrados. El valor de
 * retorno —que es donde vivía la lista— nunca llega a producirse, así que
 * quien recoge el error necesita saber **qué se fue** y **qué queda**, o la
 * frase del CHANGELOG es papel mojado (tester 3b-1 §6.2).
 *
 * Por eso este error lleva `purged` y `skipped` con la misma forma que el
 * valor de retorno, y envuelve el error del driver como `cause` en vez de
 * dejarlo escapar crudo: la abstracción no filtra.
 *
 * Recuperación: los `role_purged` ya notificados nombran lo mismo que
 * `purged`, y la siguiente pasada recoge el resto (los huérfanos que quedan
 * lo siguen siendo).
 */
export class PruneInterruptedError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_PRUNE_INTERRUPTED'

  constructor(
    message: string,
    readonly purged: ReadonlyArray<{ uuid: string; slug: string; scopeType: string; owner: string }>,
    readonly skipped: ReadonlyArray<{ role: { uuid: string; slug: string; scopeType: string; owner: string }; reason: string }>,
    options?: ErrorOptions
  ) {
    super(message, options as any)
  }
}

/**
 * `readLocalRoles()` (el barrido de `prune-orphans`) encontró más roles
 * locales que su cota `maxLocalRoles` (3b-0b · AB2, auditor 3b-0 ⚪): la
 * lectura es UNA consulta sin `LIMIT`, así que un catálogo local enorme la
 * convierte en amplificación. 500 y nunca una lista parcial —truncar aquí
 * sería decidir a ciegas qué se purga—: se sube la cota a sabiendas.
 */
export class TooManyLocalRolesError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_TOO_MANY_LOCAL_ROLES'
}

/**
 * El catálogo no cabe en un authorization model de OpenFGA (3b-2a · A3): el
 * modo `facts` publica cada permiso como cuatro relaciones del modelo y el
 * servidor tiene un techo de 262.144 bytes. **Cuántos permisos son esos bytes
 * depende de tu catálogo** (3b-4 · C3): ~450 con slugs realistas
 * (`recurso:accion`) y tres holder types, 691 si los permisos se llaman
 * `p0`…`pN`, 272 con slugs de 40 caracteres. La tabla y de qué depende están
 * en `FACTS_MODEL_MAX_BYTES`; el mensaje del error dice los bytes REALES y
 * cuántos permisos tenía el catálogo que se intentó publicar.
 * Se comprueba en `syncAuthzCatalog` ANTES de escribir: si se escribiera
 * primero, el catálogo quedaría en la base sin poder proyectarse nunca y el
 * store sin poder regenerarse. 500 porque es config de despliegue —el techo
 * del servidor es del pliego de infraestructura—, no una pregunta inválida.
 */
export class ModelTooLargeError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_MODEL_TOO_LARGE'
}

/**
 * La config de relaciones ReBAC (Fase 4) no se puede FUSIONAR en el modelo
 * `facts`. Es 422 (pregunta inválida del que declara la config), no 500: un
 * tipo de objeto de relaciones que duplica un tipo o una familia de
 * relaciones reservados del modelo `facts` (`scope`/`role`/`role_binding`/
 * `deny_binding`/`group`, o `can_<P>`/`permits_<P>`/`denied_<P>`/`assignee`/
 * `parent`/`rooted`), o una relación cuyo nombre choca con un permiso del
 * catálogo (F-04), invalidaría el modelo compartido. Lo detecta el GENERADOR y
 * lanza el PAQUETE —nunca el 400 opaco del servidor—, porque en el store
 * compartido los ids de `facts` y los de relaciones viven en el mismo espacio
 * (⚪4 del auditor, cierre por construcción del 🔴).
 */
export class RelationConfigError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_RELATION_CONFIG'
}

/**
 * El árbol materializado del store no es un árbol (3b-2b, cruce 8). El
 * paquete escribe UNA arista `scope:<hijo>#parent@scope:<padre>` por nodo y
 * la sustituye entera en cada `moved`, así que encontrar dos padres para el
 * mismo scope significa que alguien MÁS está escribiendo ahí. No se
 * "arregla": con dos padres la herencia ya está trayendo hechos de otra rama
 * y elegir uno de los dos sería adivinar cuál de las dos concesiones vivas es
 * la buena. 500 y se denuncia; lo reconstruye `authz:reconcile`.
 */
export class ScopeTreeDriftError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_SCOPE_TREE_DRIFT'
}

/**
 * El motor está CONGELADO por una operación de plataforma (`authz:reconcile`
 * o la ventana de cutover de `authz:freeze`).
 *
 * Desde 3b-7 el freeze es DURABLE (la fila `id = 2` de
 * `authz_catalog_version`): mientras está vivo, las ESCRITURAS del manager
 * (`grant`/`revoke`/`deny`/`removeDeny`, las tres `scopes.*`, la API de
 * delegación, el barrido de huérfanos y el relay) responden con este 503 **en
 * todos los procesos que comparten esas tablas**, y las LECTURAS siguen
 * funcionando: una migración que copia hechos de un backend a otro no puede
 * competir con quien los está escribiendo —lo que entre entre la lectura del
 * origen y la escritura del destino se pierde sin que nadie lo cuente— y
 * dejar de leer sería tirar la aplicación entera por una operación de
 * plataforma.
 *
 * **503 y REINTENTABLE** (`retryable: true`): no es una pregunta inválida ni
 * un fallo del backend, es una ventana de mantenimiento acotada (por el
 * lease, o por el `authz:unfreeze` del operador). El llamante puede
 * reintentar tal cual; un 409 diría «tu estado no es el que esperaba» y un
 * 422 «no vuelvas a intentarlo», y ninguna de las dos es cierta aquí.
 */
export class AuthorizationFrozenError extends Exception {
  static status = 503
  static code = 'E_AUTHZ_FROZEN'

  /** Reintentar tal cual es lo correcto en cuanto termine la ventana. */
  readonly retryable = true
}

/**
 * Ya hay un freeze VIVO de otro dueño (3b-7, auditor A1.3).
 *
 * `freeze()` no puede ser idempotente entre procesos: dos `authz:reconcile`
 * simultáneos que compartieran la fila se levantarían la barrera el uno al
 * otro al terminar el primero — dos pasadas pisándose con el README diciendo
 * que no puede pasar. El segundo dueño recibe este 423 con el motivo y el
 * holder del freeze vivo; la excepción a propósito es el freeze de OPERADOR,
 * que `reconcile` reconoce como su propio contexto (el cutover, F6) en vez
 * de chocar con él.
 */
export class FreezeHeldError extends Exception {
  static status = 423
  static code = 'E_AUTHZ_FREEZE_HELD'
}

/**
 * `authz:reconcile --prune` iba a borrar hechos del destino con un ORIGEN
 * VACÍO (3b-3a; mismo patrón que `E_AUTHZ_MASS_PURGE_REFUSED`, 3b-0b · AA2).
 *
 * `--to=openfga` hace del store un espejo de `authz_assignments`/
 * `authz_denies`, así que un origen sin una sola fila de hechos y un destino
 * lleno significa casi siempre que **los hechos los está escribiendo el otro
 * driver** (el store ES la fuente cuando `openfga` está activo) o que la
 * conexión mira a la base equivocada. Con `--prune` eso se lleva por delante
 * todo lo concedido, y sin manera de reconstruirlo. 500 antes de escribir
 * nada, `allowMassDelete: true` (`--allow-mass-delete`) es la decisión
 * humana, y `--dry-run` no lanza: lo marca en el reporte.
 */
export class MassReconcileRefusedError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_MASS_RECONCILE_REFUSED'
}

/**
 * **El volcado del destino no cabe en la cota declarada** (3b-3b · B5).
 *
 * Reconciliar exige comparar contra el estado ENTERO del destino: sin esa
 * foto no se puede saber qué sobra, y «lo que sobra» es la mitad del trabajo
 * (las aristas que el consumidor ya no respalda, el nodo con dos padres, la
 * basura de una versión anterior). El ORIGEN sí se lee por lotes con cursor;
 * el destino no, y por eso hay una cota.
 *
 * Se declara en vez de esconderse: por encima de `maxTuples` la pasada se
 * niega **antes de escribir nada**, con la cifra y la salida (subir la cota,
 * o migrar por particiones, que hoy el paquete NO trae). Un OOM a mitad de
 * migración deja el destino con las escrituras de MENOS que ya se aplicaron
 * y sin reporte; esto no deja nada.
 */
export class ReconcileTooLargeError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_RECONCILE_TOO_LARGE'
}

/**
 * El driver se ha pedido en `hierarchy: 'facts'` —el árbol vive en el store
 * de FGA— sin `scopes.outbox` y sin aceptar el riesgo por escrito (3b-2d,
 * cruce 4 · S5). En ese montaje el paquete escribe la arista en FGA dentro
 * de la transacción del consumidor y un `rollback` posterior NO la deshace:
 * SQL dice un padre y FGA otro, FGA es quien decide, y la aplicación —que
 * lista y audita contra SQL— no puede ver la escalada. No es un mal uso: el
 * uso correcto fuga, sin crash, con un simple rollback.
 *
 * 500 y al construir, no al escribir: un puerto opcional que nadie declara
 * no mitiga nada, y descubrirlo en la primera escritura de un tenant es
 * tarde. `acceptScopeDriftRisk: true` es la salida explícita para quien
 * mueve el árbol solo desde la plataforma y lo asume por escrito.
 */
export class ScopeDriftUnguardedError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_SCOPE_DRIFT_UNGUARDED'
}

/**
 * **F-05, la frontera de ESCRITURA de relaciones (Fase 4, cierre del 🔴 del
 * auditor).** `relate`/`unrelate` recibieron un `object.type` que NO está
 * declarado en `defineRelationsConfig`. Es 422 ANTES de tocar el driver: en el
 * store COMPARTIDO los tipos de `facts` (`role_binding`, `scope`, `role`)
 * viven en el MISMO espacio de ids, y la composición
 * `<type>:<scopeKey(partition)>|<id>` reproduce byte a byte el id de un
 * `role_binding` real. Sin este corte, `relate(evil, assignee,
 * {type:'role_binding', id:<roleUuid>}, S)` escribía la tupla del binding y
 * `check(evil, can_<P>, S)` devolvía `true` (escalada a `roles.authorize`,
 * medida por el auditor). Junto con ⚪4 (un tipo reservado no se puede
 * declarar) la colisión deja de existir en vez de vigilarse. **Desde L-0 el
 * mismo 422 lo lanzan también los dos drivers** en `relate`/`unrelate`, antes
 * de tocar el backend (`assertRelationDeclared`, una sola función): el
 * manager cortaba, pero `manager.driver()` y `reconcileRelations` entran por
 * el driver y la escalada seguía abierta por ahí (panel `{trx}`, 🔴 2).
 */
export class RelationTypeUnknownError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_RELATION_TYPE_UNKNOWN'
}

/**
 * **F-05, cara de la RELACIÓN.** El `object.type` está declarado, pero la
 * `relation` no es una de las suyas en `defineRelationsConfig`. Mismo 422
 * antes de tocar el driver —y, desde L-0, también en el driver antes de tocar
 * el backend—: una relación no declarada podría, en un futuro modelo, mapear a
 * una relación propia de `facts` (hoy `document#assignee` en `openfga` salía
 * como un 503 mal clasificado del servidor).
 */
export class RelationUnknownError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_RELATION_UNKNOWN'
}
