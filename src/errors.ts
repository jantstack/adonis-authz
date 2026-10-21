import { Exception } from '@adonisjs/core/exceptions'
import type { ScopeRequeueConflict } from './types.js'

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
 * **El grafo excede lo que el motor resuelve** (lote «antes de RC» · R3, decisión del dueño 2026-10-17 (4)): OpenFGA
 * respondió `authorization_model_resolution_too_complex` —una cadena de scopes o una anidación de grupos más profunda que
 * su `--resolve-node-limit`—. Es un `AuthorizationBackendError` (503, se maneja igual y el relay lo trata como
 * transitorio) con código propio, porque NO es una caída: en el BORDE es probabilístico (a 23 saltos falla entre un 4 % y
 * un 26 % según la carga, medido en 3b-2e) y un reintento puede acertar, pero por ENCIMA de la cota falla siempre. Las
 * cotas están en la tabla «Limits» del README (`FACTS_MAX_RESOLVE_DEPTH`). Nunca un `false`: deniega, pero ruidoso.
 */
export class ResolutionLimitError extends AuthorizationBackendError {
  static code = 'E_AUTHZ_RESOLUTION_LIMIT'

  constructor(driver: string, operation: string, cause?: unknown) {
    super(driver, operation, cause)
    this.message =
      `El backend de autorización '${driver}' no pudo resolver ${operation}: el grafo (la cadena de scopes o la ` +
      'anidación de grupos) excede lo que OpenFGA resuelve (resolution_too_complex). En el borde es probabilístico y un ' +
      'reintento puede acertar; por encima de la cota falla siempre: ver «Limits» en el README (FACTS_MAX_RESOLVE_DEPTH ' +
      'para la cadena de scopes; maxGroupDepth (defineRelationsConfig) para la anidación de grupos —el driver ' +
      'openfga lo calibra contra el servidor, 22 en v1.19 por defecto—; el mando del servidor es OPENFGA_RESOLVE_NODE_LIMIT / --resolve-node-limit). ' +
      'Nunca es un «sin permiso».'
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
   * **Un deny CONDICIONAL ya en el store que `openfga` no puede reemplazar** (plan 2.5 · lote D · cierre 1 de D2, 🟡 4).
   * El deny del paquete no caduca (D3): una tupla `denied_<rel>` CON condición solo puede venir de fuera (escrita a
   * mano). Re-escribirla sin condición es 409 «already exists with a different condition» (medido en v1.19.0; M5: FGA
   * no reemplaza la misma clave en un `Write`), que hasta el cierre salía como 503 «transitorio» y se repetía para
   * siempre — y el deny CADUCABA. Ahora es 500 con la receta; `denyConditional: true` deja que el reconcile lo
   * clasifique como residuo `deny-conditional` del destino (nunca 503 repetido).
   */
  static conditionalDeny(operation: string, tuple: string): AuthorizationConfigError & { denyConditional: true } {
    const error = new AuthorizationConfigError(
      `${operation}: en el store ya hay un deny CONDICIONAL (con caducidad) sobre ${tuple}. El deny del paquete no caduca ` +
        '(D3), así que esa tupla se escribió desde fuera del paquete; OpenFGA no puede REEMPLAZAR la misma clave en un ' +
        'Write (409 «already exists with a different condition», M5), así que este driver no puede rehacerlo permanente ' +
        'y repetir no sirve: no es una caída. Mientras viva niega; cuando caduque concederá lo que cortaba. Receta: ' +
        'removeDeny + deny (entre los dos hay una VENTANA en la que el deny no está y lo que cortaba se concede: hazlo ' +
        'con la flota sin tráfico sobre ese objeto o asúmela). No se ha escrito nada.'
    ) as AuthorizationConfigError & { denyConditional: true }
    error.denyConditional = true
    return error
  }

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

/**
 * **Marca de fallo de DESPLIEGUE** (lote «antes de RC» · cierre de L11, 🟠 A1 del auditor = H1; adelanta SOLO esta pieza
 * de la decisión del dueño 2026-10-17 (3), que R3 generaliza con `classifyFgaFailure`): el error dice algo del
 * DESPLIEGUE —el modelo fijado no es el que genera la config (la puerta L11), o el generador no puede generar con él—,
 * no de la entrada que se estaba aplicando. Para el relay es TRANSITORIO (`markFailed(…, { transient: true })`: no
 * consume intento ni aparca): aparcar un `moved`/`detached` por un despliegue a medias era fail-open PERSISTENTE (los
 * admins de la org vieja conservaban el acceso hasta un `requeue` manual). Para el llamante sigue siendo lo que es
 * (500 `E_AUTHZ_CONFIG`, «no es transitorio»): la marca es una propiedad, no una clase, y no cambia ni `status` ni
 * `code`. Interna: no se exporta por `index.ts` (R3 decide la forma pública).
 */
export function markDeploymentFailure<E extends object>(error: E): E & { deploymentFailure: true } {
  try {
    Object.defineProperty(error, 'deploymentFailure', { value: true, enumerable: false, configurable: true })
  } catch {
    // Un error congelado no admite la marca: se propaga sin ella (cuenta intento, como antes de la marca).
  }
  return error as E & { deploymentFailure: true }
}

/** ¿El error viene marcado como fallo de despliegue (`markDeploymentFailure`)? */
export function isDeploymentFailure(error: unknown): boolean {
  return error !== null && typeof error === 'object' && (error as { deploymentFailure?: unknown }).deploymentFailure === true
}

/**
 * **¿Es un fallo TRANSITORIO para el relay?** (no consume intento ni aparca; `markFailed(…, { transient: true })`).
 * PUNTO DE PASO ÚNICO de la regla (el manager la llama en cada fallo de la pasada; la guardia `fga.errors.classify` la
 * juzga sobre las formas medidas). Transitorio: un 503 del backend (`AuthorizationBackendError` y subclases —timeout,
 * `E_AUTHZ_RESOLUTION_LIMIT`—, o cualquier `status` 503), un fallo marcado de DESPLIEGUE (`markDeploymentFailure`) y
 * **una CARRERA que escapa** (409 `E_AUTHZ_WRITE_CONFLICT`: otro escritor —un `grant` concurrente sobre la misma
 * arista `scope#binding` del barrido, o la contención del árbol de `reparent`— llegó antes). Cierre de R3 (🟠 R3-A1 del
 * auditor, decisión (3) firmada «carrera ⇒ como hoy»: antes de R3 la carrera que escapaba del guard era un 503
 * transitorio): para el LLAMANTE sigue siendo 409; para el relay, aparcar por contención era H1 (un `moved` aparcado
 * deja el padre viejo concediendo y tapona su clave). Lo demás —422, 500 sin marca, error sin `status`— cuenta intento.
 */
export function isTransientRelayFailure(error: unknown): boolean {
  if (error instanceof AuthorizationBackendError) return true
  if (isDeploymentFailure(error)) return true
  if (typeof error !== 'object' || error === null) return false
  const { status, code } = error as { status?: unknown; code?: unknown }
  if (code === WriteConflictError.code) return true
  return status === 503
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
 * `requeueScopeChanges` se NIEGA (2.4.0-alpha.5 · R2b): devolver la entrada
 * aparcada a la cola reaplicaría un cambio ANTERIOR a otro ya APLICADO sobre
 * la misma clave de scope — el árbol del store quedaría en un orden que
 * nunca existió (auditor 🔴 2, medido: el `moved` viejo tras el nuevo deja
 * el padre VIEJO con un solo padre, y nada lo delata). 500 y no 422: la
 * pregunta está bien formada, es el estado de la cola el que la prohíbe; y
 * nunca se reencola «lo que se pueda»: es todo o nada. `conflicts` es el
 * diff —cada aparcada y las aplicadas posteriores que revertiría—; el
 * comando lo imprime y solo `--force` (en el comando ace) lo salta.
 */
export class ScopeRequeueRefusedError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_REQUEUE_REFUSED'
  readonly conflicts: ScopeRequeueConflict[]

  constructor(message: string, conflicts: ScopeRequeueConflict[]) {
    super(message)
    this.conflicts = conflicts
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
 * **Renovar esta membresía abriría un hueco en un deny** (plan 2.5 · lote D · cierre 2 de D2, 🟠 N1; decisión del dueño
 * 2026-10-15 (9)): `relate` sobre una membresía `group:*#member` EXISTENTE con otra caducidad, en un driver que renueva
 * con delete + write (`atomicRenewal: false`, `openfga`: FGA no reemplaza la misma clave en un `Write`, M5), cuando ese
 * grupo —o uno por encima de él— es sujeto de un deny vivo de la partición. Entre los dos `Write` el sujeto no tendría el
 * deny y CONCEDERÍA; si el 2.º fallara, para siempre. 409 y CERO escrituras: el estado del store no admite esta
 * escritura tal cual. **Siempre cero escrituras** (cierre 4 · ⚪ C3-3): la renovación que SÍ se aplicó y en cuya
 * ventana cayó un deny concurrente es `RenewalRacedError` (`E_AUTHZ_RENEWAL_RACED`), con otra receta.
 *
 * **La receta, honesta** (cierre 5 de D2, decisión del dueño §2026-10-16 (10), opción A): en `openfga` NO hay forma sin
 * ventana de cambiar esa caducidad —FGA no tiene upsert, openfga/openfga#2151—. (1) Patrón recomendado: membresías SIN
 * caducidad en los grupos con deny, que se terminan con `unrelate`. (2) Si hay que cambiarla: `unrelate` + `relate`
 * ACEPTANDO la ventana, dicho como tal. Hasta el cierre 5 el mensaje ofrecía además «retira antes el deny, renueva y
 * vuelve a escribirlo» como si fuera la salida segura: también abre la ventana (sin el deny, el sujeto concede). Cuando
 * OpenFGA ofrezca upsert, la renovación será UNA escritura y `atomicRenewal` pasará a `true`.
 */
export class RenewalUnsafeError extends Exception {
  static status = 409
  static code = 'E_AUTHZ_RENEWAL_UNSAFE'

  static carrier(membership: string, denied: string): RenewalUnsafeError {
    return new RenewalUnsafeError(
      `relate: no se renueva ${membership}: el grupo TRANSPORTA un deny vivo (${denied}) y este driver renueva con DOS ` +
        'Write —delete y write: OpenFGA no reemplaza la misma clave en un Write (M5; sin upsert, openfga/openfga#2151)—; ' +
        'entre los dos el deny no alcanzaría al sujeto y concedería (y si el segundo fallara, para siempre). No se ha escrito ' +
        'nada. En este driver NO hay forma sin ventana de cambiar esta caducidad. (1) Patrón recomendado: membresías SIN ' +
        'caducidad en los grupos con deny, que se terminan con unrelate. (2) Si hay que cambiarla: unrelate + relate de esa ' +
        'membresía ACEPTANDO la ventana — mientras dura, el sujeto no recibe el deny del grupo y concede lo que otro camino le ' +
        'dé y ese deny corte.'
    )
  }

  /**
   * **La clave YA existe con una condición que el paquete no escribe** (lote «antes de RC» · L11, injerto 3 del juez —H8
   * del auditor—): `relate` (relaciones) o `grant` (roles) de `openfga` sobre una tupla cuya condición es `foreign`
   * (otra condición, o `not_expired` con un contexto que no es exactamente `{ valid_until }`) o `unparseable`
   * (`fgaTupleExpiry`). Tratarla como «sin caducidad» era un no-op mudo sobre una tupla que el servidor ignora o evalúa
   * con otra semántica; como «vencida», una reescritura en dos `Write` sin mirar nada. 409 y CERO escrituras.
   */
  static foreignCondition(operation: string, tuple: string, detail: string): RenewalUnsafeError {
    return new RenewalUnsafeError(
      `${operation}: la tupla ${tuple} ya existe en el store con una condición que este paquete no escribe ni sabe leer ` +
        `(${detail}). No se reescribe a ciegas: el paquete no sabe qué concede (la puede haber escrito otra herramienta, o ` +
        'un modelo anterior). No se ha escrito nada. Receta: revísala y bórrala a mano (SDK/CLI de OpenFGA, o unrelate/' +
        'revoke por el paquete) y repite.'
    )
  }
}

/**
 * **La renovación SE APLICÓ y un deny concurrente cayó en su ventana** (cierre 3 de D2 · 🟡 C2-3; código PROPIO desde el
 * cierre 4 · ⚪ C3-3): la renovación (dos `Write`) de una membresía cuyo grupo NO transportaba ningún deny al
 * comprobarlo, y la RE-COMPROBACIÓN tras los dos `Write` encuentra uno —un `deny` concurrente entró entre la comprobación
 * y la renovación—. Estado final correcto (la membresía está y el deny vuelve a alcanzar al sujeto), pero durante la
 * ventana entre los dos `Write` el deny ya confirmado NO alcanzó al sujeto. Va marcado parcial (`markPartialWrite`: el
 * manager notifica `indeterminate: true`) y lleva `carriedDeny` y `renewalApplied: true`.
 *
 * Hasta el cierre 4 era el MISMO 409 `E_AUTHZ_RENEWAL_UNSAFE` («cero escrituras, aplica la receta»): un consumidor que
 * automatizara esa receta (`unrelate` + `relate`) ante este caso reabría la ventana con el deny YA dentro del grupo. Por
 * eso tiene su código y su receta, que NO es esa.
 */
export class RenewalRacedError extends Exception {
  static status = 409
  static code = 'E_AUTHZ_RENEWAL_RACED'
  declare carriedDeny: string
  declare renewalApplied: true

  static raced(membership: string, denied: string): RenewalRacedError {
    const error = new RenewalRacedError(
      `relate: la renovación de ${membership} SE APLICÓ, pero un deny concurrente (${denied}) entró entre la comprobación ` +
        'de portadora y los dos Write: durante la ventana entre el delete y el write ese deny, ya confirmado, NO alcanzó al ' +
        'sujeto. El estado final es correcto (la membresía está y el deny la alcanza): NO hay nada que reescribir, y la receta ' +
        'de E_AUTHZ_RENEWAL_UNSAFE (unrelate + relate) reabriría la ventana con el deny ya dentro. Receta: revisa las ' +
        'decisiones de acceso de ese sujeto en esa ventana; para no repetirla, serializa los deny y las renovaciones de ese ' +
        'grupo, o renueva con removeDeny antes y deny después.'
    )
    error.carriedDeny = denied
    error.renewalApplied = true
    return error
  }
}

/**
 * **El lote de `checkMany` no tiene la forma admitida** (plan 2.5 · lote A,
 * P4): vacío, o por encima de `RELATIONS_CHECK_MANY_MAX` (50). Es 422 con
 * CERO llamadas al backend: pregunta inválida (invariante 5), no una caída.
 */
export class CheckManyBatchError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_CHECK_MANY_BATCH'
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
 * `scopes.attached`/`scopes.moved` dejarían al hijo a más de `scopes.maxDepth`
 * saltos de `app` (2.4.0-alpha.5 · R0; opt-in por config). 422 y no 500: la
 * pregunta está bien formada, es el árbol el que no cabe en el techo que el
 * dueño declaró — y se dice ANTES de escribir o encolar. Distinto de
 * `E_AUTHZ_SCOPE_TOO_DEEP` (500): aquel es `hierarchicalScopeResolver` que no
 * puede TERMINAR una cadena ya existente; este es una escritura que se niega.
 */
export class ScopeDepthLimitError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_SCOPE_DEPTH_LIMIT'
  /**
   * Para el OPERADOR, no para el tenant (2.4.0-alpha.8; panel relay 2,
   * cuestión 7.2): el `message` de un 422 llega a quien hizo la petición, así
   * que dice solo lo accionable para él (profundidad, `scopes.maxDepth`, «no
   * se ha escrito ni encolado nada»). Por qué existe el techo —el modelo
   * `facts` del driver `openfga` no resuelve de forma fiable más allá de
   * `FACTS_MAX_RESOLVE_DEPTH`, y el mando del servidor es
   * `OPENFGA_RESOLVE_NODE_LIMIT`— nombra el backend y va aquí, para el log.
   */
  declare readonly details: { depth: number; maxDepth: number; why: string; server: string }

  constructor(message: string, details: { depth: number; maxDepth: number; why: string; server: string }) {
    super(message)
    // NO enumerable (cierre alpha.8, 🟡 3 del auditor): `JSON.stringify(error)` —lo
    // que un handler de errores genérico manda al tenant— no puede enseñar el
    // backend ni el mando del servidor. Legible por `error.details` para el log.
    Object.defineProperty(this, 'details', { value: details, enumerable: false, configurable: true, writable: false })
  }
}

/**
 * **La arista de anidación de grupos que el techo del driver no admite** (lote «antes de RC» · R1, decisiones del dueño
 * 2026-10-17 (5) y (5-bis)): `relate(group:Gc#member, 'member', group:Gp)` dejaría una cadena de grupos anidados MÁS
 * LARGA que el techo del driver —el camino más largo que atraviesa la arista nueva, hacia arriba y hacia abajo—, cerraría
 * un CICLO, o el grafo a recorrer pasa de `GROUP_DEPTH_MAX_NODES`. 422 y CERO escrituras: la pregunta está bien formada,
 * es el grafo el que no cabe. Gemelo de `E_AUTHZ_SCOPE_DEPTH_LIMIT` y con su misma regla de letra (alpha.8, 7.2): el
 * `message` es para el TENANT (la cadena, el techo, `maxGroupDepth`, «no se ha escrito nada») y no nombra el
 * backend; el porqué del techo —OpenFGA no resuelve más allá, el mando del servidor es `OPENFGA_RESOLVE_NODE_LIMIT`— va
 * en `details`, NO enumerable (un handler genérico que serializa el error no se lo enseña al tenant).
 */
export class GroupDepthLimitError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_GROUP_DEPTH_LIMIT'
  declare readonly details: {
    reason: 'too-deep' | 'cycle' | 'too-many-groups'
    edge: string
    depth: number | null
    maxGroupDepth: number
    /** Solo con `too-many-groups`: qué cota se pasó (grupos, requests, tuplas leídas o el deadline total). */
    budget?: 'nodes' | 'reads' | 'tuples' | 'deadline'
    why: string
    server: string
  }

  constructor(message: string, details: GroupDepthLimitError['details']) {
    super(message)
    Object.defineProperty(this, 'details', { value: details, enumerable: false, configurable: true, writable: false })
  }
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

  /**
   * **Los `list*` de relaciones no paginan en 2.5** (lote «antes de RC» · 7.4, opción 4 del juez, decisión del dueño
   * 2026-10-17 (7.4)): `listObjects`/`listSubjects`/`listDenies`/`membersOf` ya no tienen `page` en la firma (nunca
   * hizo nada: se diseñó en la Fase 4 y no llegó a programarse). Un valor DISTINTO de `undefined` —`null`, `{}`,
   * `{ limit: 0 }`…— que llegue por JS o `as any` es 500 con cero llamadas al backend, en el manager y en los drivers:
   * una lista entera que PARECE una página es la ruptura muda que el linaje L8 prohíbe. La paginación de verdad llegará
   * como métodos aparte (`*Page`, 2.6) con capacidad propia.
   */
  static listPage(operation: string, driver: string): UnsupportedOperationError {
    const error = new UnsupportedOperationError('page', operation, driver)
    error.message =
      `${operation}: se pasó una página (page) y ${operation} no pagina en 2.5 — devuelve el conjunto COMPLETO (o ` +
      `señala truncated), nunca un cursor. No se ha llamado al backend ('${driver}'). Quita el argumento page; la ` +
      `paginación de los listados llegará como métodos aparte (*Page) con capacidad propia.`
    return error
  }

  /**
   * **Un cursor que este driver nunca emitió** (7.4, injerto 4 del juez; `openfga` y el doble): sus `enumerate*`
   * devuelven todo en una página y JAMÁS un cursor, así que un `after` no puede haber salido de ellos. 500 con cero
   * llamadas: aceptarlo en silencio sería empezar «desde algún sitio» o ignorarlo, las dos cosas mudas.
   */
  static enumerateCursor(operation: string, driver: string): UnsupportedOperationError {
    const error = new UnsupportedOperationError('page.after', operation, driver)
    error.message =
      `${operation}: el driver '${driver}' no emite cursor (devuelve todas las tuplas en una página), así que un ` +
      `page.after no salió de él y no se acepta. No se ha llamado al backend. Llama sin after.`
    return error
  }
}

/**
 * **Una página de `enumerate*` mal formada** (lote «antes de RC» · 7.4, injerto 4 del juez; tester H2/H3, auditor T-1):
 * `limit` que no es un entero ≥ 1 (`NaN`, `0`, negativo, decimal, cadena) o `after` que no es una cadena no vacía (en
 * `database`, además, con forma de uuid canónico en minúsculas: el cursor que ESE driver emite). 422 porque es la
 * pregunta la que está mal formada (invariante 5); hasta 7.4 `limit: NaN` generaba una consulta sin `LIMIT` y un
 * `after` ajeno era un 503 en PostgreSQL (la columna es `uuid`) y un fin silencioso en MySQL/SQLite. Un `limit` por
 * encima de `RELATIONS_ENUMERATE_MAX_LIMIT` NO es este error: se recorta (con cursor, sin pérdida).
 */
export class InvalidRelationPageError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_INVALID_PAGE'
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
 * **Una clave que la spec de relaciones no conoce** (plan 2.5 · lote B · B2;
 * tester H3, linaje L5 — 5.ª iteración ⇒ propiedad universal: «ninguna clave
 * de una spec de config se descarta»). Hasta `2.5.0-alpha.1` `defineRelationsConfig`
 * copiaba solo `type`/`relations` y `name`/`includes` a la config congelada y
 * TIRABA el resto en silencio: un `denny: true` (typo) era una entrada inerte y
 * un `deny: true` leído por un proceso viejo republicaba el modelo sin
 * `denied_*` sin que nada protestara. Subclase de `RelationConfigError` (misma
 * familia, mismo `status`) con `code` propio para que el llamante distinga «la
 * forma es inválida» de «esta clave no existe en este nivel».
 */
export class RelationConfigUnknownKeyError extends RelationConfigError {
  static code = 'E_AUTHZ_RELATION_CONFIG_UNKNOWN_KEY'
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
 * Una operación iba a tomar el freeze y encontró la ventana del OPERADOR
 * CADUCADA (2.4.0-alpha.10, S2 de la auditoría de sistema): motivo puesto,
 * holder `operator:` y `untilMs` en el pasado. Hasta alpha.9 `acquireFreeze`
 * pisaba esa fila en silencio —un lease vencido no bloquea la toma—, la pasada
 * se certificaba con SU ventana de 15 s y al soltarla dejaba la fila a `NULL`:
 * el último rastro de que la flota volvió a escribir a mitad del cutover lo
 * borraba una pasada ajena, y `authz:unfreeze` decía «nada que levantar». 503
 * antes de tomar nada; la salida es reconocerla con `authz:unfreeze` (que dice
 * cuándo venció y limpia la fila) y reabrir la ventana con `authz:freeze`. La
 * exclusión va DENTRO del `UPDATE` de `acquireFreezeOutcome` (cierre del
 * auditor · R2): comprobar fuera y tomar después era un TOCTOU.
 */
export class OperatorWindowExpiredError extends Exception {
  static status = 503
  static code = 'E_AUTHZ_OPERATOR_WINDOW_EXPIRED'
}

/**
 * `authz:reconcile --to=<driver ACTIVO> --from=<otro>`: la DIRECCIÓN RANCIA
 * (2.4.0-alpha.10, 🔴 4 del sexto informe de COGNITIV; decisión del dueño del
 * 2026-09-13 (4)).
 *
 * La regla 3b-5 dice que con `--from` manda el operador — **salvo hacia el
 * driver activo**. Si el motor ya sirve desde `to`, sus hechos se escriben
 * ahí desde el cutover y el origen dejó de verlos: con `openfga` activo,
 * `--from=database` lee `authz_*` congeladas y re-escribe en el store vivo los
 * roles revocados después, con o sin `--prune` (y el seguro de borrado masivo
 * no salta: el origen no está vacío). 500 en el MANAGER —la API es la puerta,
 * no el comando— antes de construir el origen, leer nada o congelar;
 * `allowStaleSource: true` (`--allow-stale-source`) es la decisión humana y
 * `dryRun` no lanza: lo marca en `report.staleSource`. Simétrico al seguro de
 * `E_AUTHZ_MASS_PURGE_REFUSED`. El gemelo de relaciones lo lanza
 * `runRelationsReconcile` (la única vía pública desde el cierre del auditor),
 * juzgando el driver RESUELTO por su factory: un alias del activo también se
 * niega. Límite declarado: «activo» es el `config.default` del PROCESO que corre
 * la pasada (sello durable del driver activo: roadmap 2.5).
 */
export class StaleSourceRefusedError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_STALE_SOURCE_REFUSED'
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

/**
 * **Un userset que no es `group#member` como SUJETO** (plan 2.5 · lote B · B3;
 * auditor [N 9] de la ronda 1, analista B(2)). El modelo fusionado solo
 * admite UN userset en cada relación de dominio (`[<holders> with not_expired,
 * group#member]`): un `document#viewer` como sujeto no existe en el modelo.
 * Hasta `2.5.0-alpha.1` `database` guardaba la fila INERTE (ningún holder la
 * alcanzaba) y `openfga` respondía 400 del servidor ⇒ 503 mal clasificado
 * (invariante 5: una pregunta inválida es 422). Clase PROPIA (422), **no una
 * subclase de `RelationUnknownError`** (cierre 1 del lote B, decisión 4 del
 * implementador RECHAZADA, 🟠 2 del auditor): heredar de F-05 hacía que
 * `relateOrSkip` del reconcile la TRAGARA como `skipped.undeclared` —motivo
 * falso («decláralo en el destino»), `--dry-run` ≠ pasada real, sin `details`—,
 * ampliando el patrón «422 ⇒ skipped vía el driver» que R2-5 manda evitar. El
 * reconcile clasifica el residuo en el PLAN (`planPartition`, contador
 * `skipped.usersetUnsupported`, entrada en `details`) y el driver no absorbe
 * nada. Misma función, clase, `code` y mensaje en el manager, los dos drivers y
 * el doble publicado (`assertUsersetSubject`).
 */
export class RelationUsersetUnsupportedError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_RELATION_USERSET_UNSUPPORTED'
}

/**
 * **Deny sobre algo que no se puede denegar** (plan 2.5 · lote D · D1; panel
 * tenencia ronda 2, D10/D-17). `deny(…)` sobre un tipo cuya spec no declara
 * `deny: 'write'` (fase 2 del opt-in: sin opt-in, o en `deny: 'read'`, la fase
 * en la que el modelo y las lecturas ya honran el deny pero aún no se aceptan
 * escrituras), sobre el tipo built-in `group`, o con el comodín `*` como
 * sujeto. 422 ANTES de tocar el driver (cero llamadas, cero eventos): una
 * pregunta inválida, no una caída.
 */
export class RelationNotDenyableError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_RELATION_NOT_DENYABLE'
}

/**
 * **`expiresAt` en un deny** (plan 2.5 · lote D · D3, decisión del dueño
 * 2026-10-14): el deny de relaciones NO caduca en v1. Medido (M5, OpenFGA
 * v1.19.0): FGA rechaza delete+write de la misma clave en un `Write` (400
 * `cannot_allow_duplicate_tuples_in_one_request`) y `on_duplicate: ignore` con
 * otra condición es 409, así que cambiar la caducidad de un deny VIVO exige dos
 * `Write` con una ventana en la que deja de bloquear — y si el segundo cae, el
 * deny DESAPARECE. 422 ANTES de tocar el driver, con la razón medida.
 */
export class RelationDenyExpiryError extends Exception {
  static status = 422
  static code = 'E_AUTHZ_DENY_EXPIRY_UNSUPPORTED'
}

/**
 * **`membersOf` de `database` sobre un objeto con deny y más candidatos que la cota** (lote D · cierre 1 de D1, 🟡 4 del
 * auditor). Con una fila `denied_*` vigente en el objeto, cada candidato se juzga con un `check` (el corte de camino);
 * sin cota eran N consultas en serie —una amplificación barata para quien puede escribir un deny—. Pasada
 * `RELATIONS_MEMBERS_DENY_CHECK_MAX` (1 000) ⇒ 500, NUNCA una lista parcial; el deadline TOTAL del bucle es 503
 * `E_AUTHZ_BACKEND_TIMEOUT`. **500 y no 422** (decisión 1 del cierre 1, ratificada en el cierre 2): no es una pregunta
 * inválida del llamante —la misma pregunta es válida con menos candidatos— sino una cota del DESPLIEGUE (precedente
 * `E_AUTHZ_TOO_MANY_LOCAL_ROLES`); y no 503 porque no es reintentable. `authorizedScopes` (`E_AUTHZ_TOO_MANY_SCOPES`,
 * 422) acota una enumeración que el llamante pide con su `maxScopes`; aquí no hay cota del llamante.
 */
export class MembersOfDenyLimitError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_MEMBERS_DENY_LIMIT'
}

/**
 * **`authz:relations:reconcile` se NIEGA a migrar denies** (plan 2.5 · lote D · D2; auditor R2-5, tester S6, juez ronda 2
 * fila D). El origen trae al menos un deny vivo y el destino no puede escribirlo: no declara `relationDenies` (o no trae
 * `deny`/`removeDeny`/`denyPhase`), el tipo no está en la fase `'write'` del opt-in EN EL DESTINO (su config, no la spec
 * persistida), el par tipo/relación no está declarado allí, su modelo fijado no declara `denied_<rel>` (D-31), o el
 * origen enumera un deny SIN marcar `kind` (`unmarked`). Se decide en la FASE DE PLAN, antes de la primera escritura en
 * cualquier partición: **CERO escrituras**, y **jamás `skipped`** — perder un deny no es una pérdida que se pueda declarar
 * (escribir los allows sin él concede lo que el origen niega). `--dry-run` no lanza: lo marca en `report.denyRefused` y es
 * deriva. Lleva `refusals` (una entrada por tipo/relación y motivo). 500 y no 422: no es una pregunta del llamante sino
 * el estado del despliegue (precedente `E_AUTHZ_MASS_RECONCILE_REFUSED`).
 */
export class DenyMigrationRefusedError extends Exception {
  static status = 500
  static code = 'E_AUTHZ_DENY_MIGRATION_REFUSED'
  refusals: ReadonlyArray<{ objectType: string; relation: string; reason: string; message: string }> = []
}
