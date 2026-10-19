import {
  AuthorizationBackendError,
  AuthorizationBackendTimeoutError,
  AuthorizationConfigError,
  markDeploymentFailure,
  NoScopeResolverError,
  ResolutionLimitError,
  ScopeResolverError,
  UnknownScopeError,
  WriteConflictError,
} from '../errors.js'
import type { ScopeChainResolver, ScopeRef } from '../types.js'
import { APP_SCOPE, APP_SCOPE_TYPE } from '../types.js'
import { assertScope, scopeSpellings } from '../identity.js'

/**
 * Clasificación de fallos de dependencias, compartida por ambos drivers.
 *
 * Tres dependencias participan en una pregunta: el catálogo (SQL, en ambos
 * drivers), el árbol del consumidor (`resolveChain`) y el backend de
 * hechos (SQL o FGA). Las tres se clasifican igual: 503 con código propio,
 * la causa original conservada, y NUNCA un `false` ni un error crudo — el
 * invariante 5 tal como está publicado (L0.11, N3).
 *
 * Lo que ya es un error del paquete (422 de catálogo, 500 de programación)
 * pasa intacto: un rol inexistente no es una caída.
 */

/** ¿Es un error que este paquete ya clasificó (tiene `code` E_AUTHZ_*)? */
export function isAuthzError(error: unknown): boolean {
  return typeof (error as any)?.code === 'string' && (error as any).code.startsWith('E_AUTHZ_')
}

/**
 * ¿Es un error del CLIENTE SQL (pg, mysql2, better-sqlite3, knex) y no del
 * código del consumidor? Por la forma que cada cliente da a sus errores:
 * `pg` un `DatabaseError` con SQLSTATE de 5 caracteres (`25P02`…) y
 * `severity`; `mysql2` un `errno` numérico con `sqlState`; SQLite un `code`
 * `SQLITE_*`; knex un `KnexTimeoutError`. Sirve para clasificar (503) lo que
 * un `fn` del consumidor deja escapar desde dentro de una transacción
 * (2.5-B · K12): un error crudo del cliente nunca cruza la frontera.
 */
export function isSqlDriverError(error: unknown): boolean {
  const e: any = error
  if (!e || typeof e !== 'object') return false
  if (e.name === 'KnexTimeoutError') return true
  if (typeof e.code === 'string' && /^SQLITE_/.test(e.code)) return true
  if (typeof e.errno === 'number' && typeof e.sqlState === 'string') return true
  if (typeof e.code === 'string' && /^[0-9A-Z]{5}$/.test(e.code) && ('severity' in e || 'routine' in e)) return true
  return false
}

/**
 * ¿El error (o alguna de sus causas) es un choque del UNIQUE? Por la forma de
 * cada cliente: PostgreSQL SQLSTATE `23505`, MySQL `errno` 1062
 * (`ER_DUP_ENTRY`), SQLite `SQLITE_CONSTRAINT_UNIQUE` (o el `SQLITE_CONSTRAINT`
 * genérico con «UNIQUE» en el mensaje). Se mira la cadena entera de causas:
 * `guardSql` ya lo habrá envuelto en un `AuthorizationBackendError`.
 *
 * Lo usa el driver `database` DENTRO de una transacción del llamante (L-3):
 * fuera de ella un choque se absorbe releyendo (K4), dentro no se puede —en
 * PostgreSQL la transacción ya está abortada y en REPEATABLE READ la relectura
 * no vería al ganador— y sale como 409 `E_AUTHZ_WRITE_CONFLICT`.
 */
export function isUniqueViolation(error: unknown): boolean {
  let current: any = error
  for (let depth = 0; current && depth < 6; depth++) {
    if (current.code === '23505') return true
    if (current.errno === 1062) return true
    if (typeof current.code === 'string' && /^SQLITE_CONSTRAINT/.test(current.code)) {
      if (current.code === 'SQLITE_CONSTRAINT_UNIQUE' || /UNIQUE/i.test(String(current.message ?? ''))) return true
    }
    current = current.cause
  }
  return false
}

/**
 * ¿El error (o alguna de sus causas) es un DEADLOCK que el motor resolvió
 * eligiendo esta transacción como víctima? PostgreSQL SQLSTATE `40P01`
 * (`deadlock_detected`; y `40001`, `serialization_failure`, la misma familia
 * de «reintenta»), MySQL `errno` 1213 (`ER_LOCK_DEADLOCK`: InnoDB deshace la
 * transacción ENTERA de la víctima). SQLite no tiene deadlocks entre
 * escritores: el segundo recibe `SQLITE_BUSY` (503), no un deadlock.
 *
 * Lo usa el driver `database` de relaciones DENTRO de una transacción del
 * llamante (L-4, 🟡 12 del auditor): dos transacciones que escriben dos
 * relaciones en orden cruzado ⇒ el perdedor sale con **409
 * `E_AUTHZ_WRITE_CONFLICT`** («haz rollback y reintenta»), jamás un error
 * crudo del motor ni un 503 disfrazado de indeterminado.
 */
export function isDeadlock(error: unknown): boolean {
  let current: any = error
  for (let depth = 0; current && depth < 6; depth++) {
    if (current.code === '40P01' || current.code === '40001') return true
    if (current.errno === 1213) return true
    current = current.cause
  }
  return false
}

/**
 * **¿Es el 400 del tope de operaciones por `Write` del servidor OpenFGA?** MEDIDO en v1.19.0 (cierre 2 de D1 · ⚪ N3):
 * el SDK lanza `FgaApiValidationError` con `statusCode` 400 y `apiErrorCode` `exceeded_entity_limit` («The number of
 * write operations exceeds the allowed limit of N»). Se mira el error y su `cause` directa (los dos drivers lo envuelven
 * en un `AuthorizationBackendError`). PUNTO DE PASO ÚNICO de los dos puertos (lote D · D2, el gemelo de roles de N3):
 * un despliegue con `--max-tuples-per-write` < 100 no es transitorio y no puede salir como 503.
 */
export function isServerWriteLimit(error: unknown): boolean {
  for (const candidate of [error, (error as { cause?: unknown } | null)?.cause]) {
    const e = candidate as { statusCode?: unknown; apiErrorCode?: unknown } | null | undefined
    if (e && typeof e === 'object' && e.statusCode === 400 && e.apiErrorCode === 'exceeded_entity_limit') return true
  }
  return false
}

/**
 * ¿El error viene de un deadline vencido? knex lanza `KnexTimeoutError` (o, si
 * además falló la cancelación, el error de cancelación con `timeout` puesto);
 * axios usa `ECONNABORTED`/`ETIMEDOUT`, a veces envuelto por el SDK como
 * `cause`. Se mira la cadena entera de causas.
 */
export function isTimeoutLike(error: unknown): boolean {
  let current: any = error
  for (let depth = 0; current && depth < 6; depth++) {
    if (current.name === 'KnexTimeoutError' || typeof current.timeout === 'number') return true
    if (current.code === 'ECONNABORTED' || current.code === 'ETIMEDOUT') return true
    if (isBareFgaError(current)) return true
    current = current.cause
  }
  return false
}

/**
 * **El `FgaError` SIN respuesta** (lote «antes de RC» · R3; F0 · M-d, nota 1 al auditor): el SDK 0.9.6 envuelve el
 * timeout de axios —y también la conexión rechazada— en un `FgaError` genérico que NO conserva `code`, `cause` ni
 * `statusCode` (fixtures `real-client-timeout`, `fake-client-timeout-slow-server`, `net-connection-refused`): solo
 * `name` y `message`. Sin leer el mensaje (prohibido, decisión 2026-10-17 (3)) los dos NO se separan, así que se toma la
 * clase CONSERVADORA: timeout —indeterminado—. Para el relay los dos son transitorios; para la auditoría
 * (invariante 13) decir «quizá se escribió» de una conexión rechazada sobra, y callarlo de un timeout faltaría. Hasta R3
 * solo lo salvaba que `withDeadline` arranca antes que el reloj del SDK. El nombre EXACTO `FgaError` (las subclases del
 * SDK tienen el suyo) y SIN `statusCode`: con respuesta, lo decide `classifyFgaFailure`.
 */
function isBareFgaError(candidate: any): boolean {
  return candidate?.name === 'FgaError' && (candidate.statusCode === undefined || candidate.statusCode === null)
}

/* ── R3: el clasificador ÚNICO de los fallos de OpenFGA ─────────────────────────────────────────────────────────────── */

/**
 * Las clases de la decisión del dueño 2026-10-17 (3) y (4) (lote «antes de RC» · R3), separadas SIN leer el mensaje
 * (F0 · M-d: 41 formas literales del SDK 0.9.6 contra OpenFGA v1.19, en `tests/fixtures/fga_errors/`):
 *
 * | clase | al llamante | en el relay |
 * |---|---|---|
 * | `timeout` (deadline propio, `ECONNABORTED`/`ETIMEDOUT`, el `FgaError` sin respuesta) | 503 `E_AUTHZ_BACKEND_TIMEOUT` | transitorio |
 * | `transient` (5xx —501 incluido—, 408, 429, `deadline_exceeded`, sin respuesta, ítem `internal_error`; en una ESCRITURA el 504 y `deadline_exceeded` son `timeout`) | 503 `E_AUTHZ_BACKEND_UNAVAILABLE` | transitorio |
 * | `resolution-limit` (`authorization_model_resolution_too_complex`, excepción o ítem) | 503 `E_AUTHZ_RESOLUTION_LIMIT` | transitorio |
 * | `deployment` (401/403/404, 400 con código de la LISTA BLANCA, validación del cliente) | 500 `E_AUTHZ_CONFIG` «no es transitorio» | transitorio (marca) |
 * | `race` (409, 400 `write_failed_due_to_invalid_input`) | 409 `E_AUTHZ_WRITE_CONFLICT` si escapa | transitorio (`isTransientRelayFailure`, cierre de R3) |
 * | `unknown-4xx` (cualquier otro 4xx) | 500 `E_AUTHZ_CONFIG` con `cause` | transitorio (marca) |
 */
export type FgaFailureKind = 'timeout' | 'transient' | 'resolution-limit' | 'deployment' | 'race' | 'unknown-4xx'

export interface FgaFailure {
  kind: FgaFailureKind
  /** El `statusCode` HTTP de la respuesta (ausente sin respuesta y en el error por ítem de `batchCheck`). */
  status?: number
  /** `apiErrorCode` del SDK, o el valor de la clave del error por ítem (`input_error`/`internal_error`). */
  apiErrorCode?: string
}

/** El código de OpenFGA que dice «el grafo excede lo que resuelvo» (decisión 4: 503 con código propio). */
export const FGA_RESOLUTION_TOO_COMPLEX = 'authorization_model_resolution_too_complex'

/**
 * **La LISTA BLANCA de códigos de despliegue** (F0 · M-d): solo códigos MEDIDOS. Un 400 con un código fuera de ella (y todo 422)
 * es `unknown-4xx` (la clase `FgaApiValidationError` no basta: el 400 de código desconocido es la misma clase). Dentro de
 * la clase no se separan sin el mensaje —y no hace falta, la decisión 3 los junta—: relación/tipo ausente del modelo
 * fijado ↔ contexto ausente en la tupla ↔ `current_time` ausente (los tres `validation_error`), y store ↔ modelo ausente
 * con pin (los dos `authorization_model_not_found`).
 */
export const FGA_DEPLOYMENT_CODES: ReadonlySet<string> = new Set([
  'validation_error',
  'authorization_model_not_found',
  'latest_authorization_model_not_found',
  'exceeded_entity_limit',
  // `store_id_not_found` NO está (cierre de R3, ⚪-6 del tester): se midió solo como 404, que ya decide el status.
])

/** El código con el que OpenFGA dice que venció SU deadline (504 por el grpc-gateway; F0 · M-d `fake-504-deadline-exceeded`). */
const FGA_DEADLINE_EXCEEDED = 'deadline_exceeded'

/** El 400 de la carrera (`isDuplicateWrite`/`isTreeWriteRace` leen su sub-tipo; aquí basta el código). */
const FGA_RACE_CODE = 'write_failed_due_to_invalid_input'

/**
 * Los errores del SDK que se lanzan SIN red (el cliente valida antes de llamar: un `authorizationModelId` que no es un
 * ULID, un parámetro obligatorio ausente). Deterministas: despliegue. Es lo ÚNICO que se decide por `name`, porque sin
 * respuesta no hay `statusCode` que mirar (la regla general es «por `statusCode` + `apiErrorCode`, nunca por la clase JS»:
 * 408/409/418/501 son los cuatro `FgaApiError`).
 */
const FGA_CLIENT_VALIDATION_NAMES: ReadonlySet<string> = new Set(['FgaValidationError', 'FgaRequiredParamError'])

/**
 * **`classifyFgaFailure(error)`**: la clase de un fallo de OpenFGA, por `statusCode` + `apiErrorCode` (lista blanca) o,
 * en el error POR ÍTEM de un `batchCheck` 200, por la CLAVE del objeto `error` (`input_error`/`internal_error`). **Jamás
 * lee `message` ni `apiErrorMessage`** (lo vigila la propiedad `fga.errors.classify` de la guardia; las ÚNICAS exenciones,
 * por nombre y firmadas —decisión del dueño 2026-10-18 (5-bis)—, son `isDuplicateWrite`/`isTreeWriteRace`, que leen el
 * SUB-tipo de la carrera «already exists» / «does not exist» y viven ENCIMA de esta clase). PUNTO DE PASO ÚNICO de los
 * TRES sitios: `#guard` del driver de relaciones, `guardBackendErrors` y `alignBatchResults` (los dos drivers).
 */
export function classifyFgaFailure(error: unknown, context: { write?: boolean } = {}): FgaFailure {
  const item = error as { input_error?: unknown; internal_error?: unknown; statusCode?: unknown } | null
  if (item && typeof item === 'object' && item.statusCode === undefined && ('input_error' in item || 'internal_error' in item)) {
    // El error POR ÍTEM de `batchCheck` (respuesta 200): no es una excepción del SDK, es un objeto de la respuesta.
    if (typeof item.internal_error === 'string') return { kind: 'transient', apiErrorCode: item.internal_error }
    if (typeof item.input_error === 'string') {
      const code = item.input_error
      if (code === FGA_RESOLUTION_TOO_COMPLEX) return { kind: 'resolution-limit', apiErrorCode: code }
      if (FGA_DEPLOYMENT_CODES.has(code)) return { kind: 'deployment', apiErrorCode: code }
      return { kind: 'unknown-4xx', apiErrorCode: code }
    }
    return { kind: 'transient' }
  }
  if (isTimeoutLike(error)) return { kind: 'timeout' }
  const responded = respondedFgaError(error)
  if (responded === null) {
    let current: any = error
    for (let depth = 0; current && depth < 6; depth++) {
      if (typeof current.name === 'string' && FGA_CLIENT_VALIDATION_NAMES.has(current.name)) return { kind: 'deployment' }
      current = current.cause
    }
    return { kind: 'transient' }
  }
  const { status, apiErrorCode } = responded
  const failure = (kind: FgaFailureKind): FgaFailure => ({ kind, status, ...(apiErrorCode !== undefined ? { apiErrorCode } : {}) })
  // Cierre de R3 (🟡 R3-A2 del auditor; invariante 13: «una escritura que vence el deadline es indeterminada»): en una
  // ESCRITURA, el deadline del SERVIDOR (`deadline_exceeded`) y el 504 de un proxy/gateway son de la familia TIMEOUT —el
  // `Write` puede haberse confirmado aguas arriba después de que se cortara la respuesta—, así que salen 503
  // `E_AUTHZ_BACKEND_TIMEOUT` y el manager notifica `indeterminate: true`. El resto de 5xx en una escritura conserva
  // «no ocurrió» (el servidor contestó que falló); en una LECTURA el 504 sigue siendo transitorio (no hay nada que auditar).
  if (context.write === true && (status === 504 || apiErrorCode === FGA_DEADLINE_EXCEEDED)) return failure('timeout')
  if (status >= 500 || status === 408 || status === 429) return failure('transient')
  if (status === 409) return failure('race')
  if (status === 401 || status === 403 || status === 404) return failure('deployment')
  // Solo el 400 lleva códigos medidos (cierre de R3, ⚪-6 del tester: un 422 se midió solo con código desconocido, así
  // que cualquier 422 es `unknown-4xx` —mismo error público que el despliegue: 500 marcado—).
  if (status === 400) {
    if (apiErrorCode === FGA_RACE_CODE) return failure('race')
    if (apiErrorCode === FGA_RESOLUTION_TOO_COMPLEX) return failure('resolution-limit')
    if (apiErrorCode !== undefined && FGA_DEPLOYMENT_CODES.has(apiErrorCode)) return failure('deployment')
    return failure('unknown-4xx')
  }
  if (status >= 400) return failure('unknown-4xx')
  return failure('transient')
}

/** El primer error de la cadena de `cause` que trae una respuesta HTTP (`statusCode` numérico). */
function respondedFgaError(error: unknown): { status: number; apiErrorCode?: string } | null {
  let current: any = error
  for (let depth = 0; current && depth < 6; depth++) {
    if (typeof current.statusCode === 'number') {
      return {
        status: current.statusCode,
        ...(typeof current.apiErrorCode === 'string' ? { apiErrorCode: current.apiErrorCode } : {}),
      }
    }
    current = current.cause
  }
  return null
}

/**
 * **El error PÚBLICO de un fallo de OpenFGA** (R3): `classifyFgaFailure` ⇒ la clase de la tabla de arriba. La causa
 * original viaja SIEMPRE en `cause` (la carrera la leen `isDuplicateWrite`/`isTreeWriteRace` por la cadena). `timeoutMs`
 * solo da la letra del timeout. `failure` deja pasar una clasificación ya hecha (el llamante que necesita mirarla antes).
 */
export function fgaFailureError(
  driver: string,
  operation: string,
  error: unknown,
  options: { timeoutMs?: number; failure?: FgaFailure; write?: boolean } = {}
): Error {
  const failure = options.failure ?? classifyFgaFailure(error, { write: options.write })
  const what = [failure.status !== undefined ? `HTTP ${failure.status}` : null, failure.apiErrorCode ?? null]
    .filter((x) => x !== null)
    .join(' ')
  switch (failure.kind) {
    case 'timeout': {
      const timeout = new AuthorizationBackendTimeoutError(driver, operation, options.timeoutMs ?? 0, error)
      if (failure.status !== undefined) {
        // Con respuesta (504 / `deadline_exceeded` en una escritura): no es NUESTRO deadline, es el del servidor o el
        // de un proxy intermedio. La escritura es INDETERMINADA (invariante 13), no «no ocurrió».
        timeout.message =
          `El backend de autorización '${driver}' venció un deadline aguas arriba en ${operation} (${what}): la ` +
          'escritura es INDETERMINADA —el servidor puede haberla confirmado después de cortarse la respuesta—.'
      }
      return timeout
    }
    case 'transient':
      return new AuthorizationBackendError(driver, operation, error)
    case 'resolution-limit':
      return new ResolutionLimitError(driver, operation, error)
    case 'race':
      return new WriteConflictError(
        `El backend de autorización '${driver}' rechazó ${operation} por una CARRERA con otro escritor (${what}): el ` +
          'estado del store no es el que esta escritura esperaba. Relee y reintenta la escritura.',
        { cause: error }
      )
    case 'deployment':
      return markDeploymentFailure(
        new AuthorizationConfigError(
          `El backend de autorización '${driver}' rechazó ${operation} (${what || 'validación del cliente, sin red'}): el ` +
            'DESPLIEGUE no es el que espera la config —store o modelo inexistente (OPENFGA_STORE_ID/OPENFGA_MODEL_ID), ' +
            'credenciales, o un tipo, relación o contexto que el modelo fijado no admite—. No es transitorio: repetida, la ' +
            'operación vuelve a fallar igual hasta que se corrija el despliegue (openfga:provision publica el modelo de la ' +
            'config). Para el relay no consume intento.',
          { cause: error }
        )
      )
    case 'unknown-4xx':
      return markDeploymentFailure(
        new AuthorizationConfigError(
          `El backend de autorización '${driver}' rechazó ${operation} con un 4xx que este paquete no conoce (${what}). ` +
            'No es transitorio (un 4xx dice «no reintentes»): mira la causa (cause) y la versión del servidor OpenFGA. ' +
            'Para el relay no consume intento.',
          { cause: error }
        )
      )
  }
}

/**
 * Ejecuta una consulta SQL con deadline y traduce su fallo. El builder de
 * Lucid es perezoso (se ejecuta al hacer `await`), así que el `timeout` se
 * fija aquí, en el ÚNICO punto por el que pasan todas las consultas: un
 * call-site nuevo lo hereda sin saberlo. `cancel: true` pide a knex que
 * cancele la consulta en el servidor cuando el dialecto lo permite.
 */
export async function guardSql<T>(
  driver: string,
  operation: string,
  timeoutMs: number,
  fn: () => Promise<T>
): Promise<T> {
  try {
    const query: any = fn()
    if (typeof query?.timeout === 'function') {
      try {
        query.timeout(timeoutMs, { cancel: true })
      } catch {
        // knex rechaza `cancel` al CONSTRUIR la consulta en los dialectos que
        // no saben cancelar (SQLite). El deadline sigue valiendo: vencido, la
        // promesa rechaza y la conexión se descarta; solo no se manda un
        // "cancela" al servidor.
        query.timeout(timeoutMs)
      }
    }
    return await query
  } catch (error: any) {
    if (isAuthzError(error)) throw error
    if (isTimeoutLike(error)) {
      throw new AuthorizationBackendTimeoutError(driver, operation, timeoutMs, error)
    }
    throw new AuthorizationBackendError(driver, operation, error)
  }
}

/**
 * Deadline TOTAL de una llamada al backend: vencido ⇒ rechaza con el error
 * que fabrique `onTimeout`. El timer no retiene el event loop y se limpia al
 * resolver. La promesa original sigue su curso —la petición en vuelo puede
 * aterrizar después— pero el llamante ya fue liberado: por eso el manager
 * notifica `indeterminate: true` en las escrituras que vencen (D2) y el
 * driver openfga no deja al SDK reintentar por su cuenta (`maxRetry: 0`).
 */
export function withDeadline<T>(promise: Promise<T>, ms: number, onTimeout: () => Error): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(onTimeout()), ms)
    timer.unref?.()
  })
  return Promise.race([promise, deadline]).finally(() => clearTimeout(timer))
}

/**
 * El resolutor que usa un driver construido SIN `resolveChain`: solo
 * conoce la raíz. Sustituye al default plano de 1.x (`resto → [APP_SCOPE]`),
 * que hacía descender de `app` cualquier scope inventado o borrado (L0.3).
 * No se lanza al construir el driver, sino en la primera pregunta por un
 * scope intermedio: un despliegue que solo usa `app` es legítimo sin árbol.
 */
export const rootOnlyResolver: ScopeChainResolver = async (scope) => {
  if (scope.type === APP_SCOPE_TYPE) return [APP_SCOPE]
  throw new NoScopeResolverError(
    `El driver no tiene 'resolveChain' y se preguntó por un scope de tipo '${scope.type}'. ` +
      `Sin resolutor solo existe la raíz 'app': pasa 'scopes.resolveChain' en el config ` +
      `(y 'resolveChain' al driver) para declarar tu jerarquía.`
  )
}

/**
 * ¿Dos uuids nombran, con formas distintas, el mismo id? Un motor que
 * canoniza (el tipo `uuid` de PostgreSQL acepta mayúsculas y guiones
 * quitados; una collation `*_ci` funde mayúsculas) puede devolver la fila real
 * para un alias: aquí se acepta ESA relación y nada más. Cualquier otra
 * diferencia es otro scope, y un resolutor que lo devuelva miente.
 */
function sameUuidLoosely(canonical: string | null, asked: string | null): boolean {
  if (canonical === null || asked === null) return canonical === asked
  const fold = (value: string) => value.toLowerCase().replaceAll('-', '')
  return fold(canonical) === fold(asked)
}

/**
 * Cadena CANÓNICA `[scope canónico, ...ancestros]` con el resolutor del
 * consumidor envuelto (2.5-B · K1): el elemento 0 es el scope tal como está
 * en la tabla del consumidor —no tal como lo escribió el llamante—, y es la
 * identidad con la que el paquete lee y escribe TODOS los hechos. Antes se
 * devolvía `[scope del llamante, ...ancestros]`: un alias del uuid (que el
 * árbol fundía con la fila real) resolvía la cadena entera y el grant del
 * ancestro aplicaba, pero el deny —escrito con la forma canónica— no casaba.
 *
 * Si el resolutor lanza, sale como `ScopeResolverError` (503): el árbol es
 * una dependencia más y su caída no es un bug del paquete ni un "sin
 * permiso". `null` = el scope no existe para el consumidor; el llamante decide
 * qué significa (denegar en lectura, 422 en escritura). La raíz no se
 * pregunta: el motor la conoce y su cadena es `[APP_SCOPE]` por definición.
 *
 * La RESPUESTA se valida (D13 + K1): no-array, elemento mal formado
 * (`{app, 'X'}`, `{organization, 'a|b'}`), cadena vacía, o un elemento 0 que
 * no es el scope pedido (otro tipo; un uuid que no es el mismo id salvo
 * mayúsculas/guiones) ⇒ 503 con el motivo como causa. Nunca se acepta en
 * silencio una identidad que el llamante no pidió.
 */
export async function resolveChain(
  resolver: ScopeChainResolver,
  scope: ScopeRef,
  operation: string
): Promise<ScopeRef[] | null> {
  if (scope.type === APP_SCOPE_TYPE) return [APP_SCOPE]
  let chain: ScopeRef[] | null
  try {
    chain = await resolver(scope)
  } catch (error) {
    if (isAuthzError(error)) throw error
    throw new ScopeResolverError(operation, error)
  }
  if (chain === null || chain === undefined) return null
  if (!Array.isArray(chain)) {
    throw new ScopeResolverError(
      operation,
      new TypeError(`resolveChain devolvió ${typeof chain} en vez de ScopeRef[] | null`)
    )
  }
  if (chain.length === 0) {
    throw new ScopeResolverError(
      operation,
      new TypeError(
        `resolveChain devolvió una cadena vacía para ${scope.type}:${scope.uuid ?? ''}: la cadena empieza por el propio scope canónico`
      )
    )
  }
  for (const element of chain) {
    try {
      assertScope(element)
    } catch (error) {
      throw new ScopeResolverError(operation, error)
    }
  }
  const self = chain[0]
  if (self.type !== scope.type || !sameUuidLoosely(self.uuid, scope.uuid)) {
    throw new ScopeResolverError(
      operation,
      new TypeError(
        `resolveChain devolvió ${self.type}:${self.uuid ?? ''} como elemento 0 de la cadena de ` +
          `${scope.type}:${scope.uuid ?? ''}: el primer elemento tiene que ser el propio scope (canónico), no otro`
      )
    )
  }
  return chain
}

/**
 * El scope CANÓNICO para una escritura que no exige que exista (`revoke`,
 * `removeDeny`, `purgeScope`): la fila del árbol si lo conoce (un alias se
 * canoniza y el hecho canónico se encuentra, K1); el scope tal cual si ya no
 * lo conoce (un hecho de un scope borrado sin avisar, D8, sigue siendo
 * alcanzable con su identidad exacta) o si el driver no tiene resolutor (solo
 * existe la raíz: no hay nada con lo que canonizar). Un resolutor que LANZA
 * sigue siendo 503: no se limpia a ciegas cuando el árbol está caído.
 */
export async function canonicalScope(resolver: ScopeChainResolver, scope: ScopeRef, operation: string): Promise<ScopeRef> {
  try {
    const chain = await resolveChain(resolver, scope, operation)
    return chain ? chain[0] : scope
  } catch (error) {
    if (error instanceof NoScopeResolverError) return scope
    throw error
  }
}

/**
 * **Los scopes destino de una purga o un DELETE que no exigen que el scope
 * exista** (`scopes.detached` en el manager; `revoke`/`removeDeny` en los dos
 * drivers; 3b-8 · A4, mismo cierre que 3b-2h · 🟠 3). Es el ÚNICO punto de
 * paso del fan-out sin cadena (cierre-3 del lote A). Con la fila viva es
 * exactamente UNO, el canónico (`chain[0]`). Sin cadena con la que canonizar
 * —la fila ya borrada, o sin resolutor— la ortografía del llamante a secas
 * hacía del delete un no-op SILENCIOSO cuando llegaba un alias del uuid (el
 * mismo uuid sin guiones, que el tipo `uuid` de PG o una collation `*_ci`
 * funden con la fila real): el hecho canónico seguía escrito y volvía a
 * conceder si el scope se restauraba. Se reusa el fan-out de
 * `scopeSpellings` (la regla `pgFusedSpellings`: solo lo que PG funde): la
 * ortografía del llamante Y la canónica de la que puede ser alias.
 *
 * **Y se DESCARTA toda ortografía que el resolutor reconozca como scope VIVO
 * distinto del pedido** (cierre-3 · 🟡 C2-2/C2-3, decisión del dueño
 * 2026-10-15 (3)). «Quitar nunca concede» era FALSO en dos sitios: quitar un
 * DENY concede (`removeDeny`), y `purgeScope` en `database` borra también
 * `authz_denies` del scope purgado mientras la herencia viene del resolutor.
 * En un consumidor con ids de scope de TEXTO elegibles por el usuario, un
 * tenant crea y borra `<32 hex de la víctima>` (o cualquier otra forma que PG
 * funda) y llama `detached`/`removeDeny` sin cadena: la canónica añadida ES
 * la víctima, viva, de otro tenant — fail-open cross-tenant en `database`
 * (el deny desaparece), DoS en `facts` (se va la arista `parent`). Por eso
 * cada ortografía EXTRA se contrasta con el resolutor: si existe, no es «la
 * canónica de la que el alias puede ser alias», es otro scope, y no se toca.
 * La del llamante no se contrasta (ya se sabe que no resuelve: por eso
 * estamos aquí). Un resolutor que LANZA al contrastar sigue siendo 503:
 * nunca se purga «por si acaso» con el árbol caído. Sin resolutor
 * (`NoScopeResolverError`) solo existe la raíz, nada puede estar vivo y el
 * fan-out va entero.
 */
export async function canonicalScopeTargets(
  resolver: ScopeChainResolver,
  scope: ScopeRef,
  operation: string
): Promise<ScopeRef[]> {
  let chain: ScopeRef[] | null
  try {
    chain = await resolveChain(resolver, scope, operation)
  } catch (error) {
    if (!(error instanceof NoScopeResolverError)) throw error
    return scopeSpellings(scope)
  }
  if (chain) return [chain[0]]
  const [asked, ...aliases] = scopeSpellings(scope)
  const targets = [asked]
  for (const alias of aliases) {
    // Vivo para el resolutor ⇒ es OTRO scope (nunca se purga un scope vivo
    // que no es el pedido). Un throw sale como 503, jamás como «purgar igual».
    const live = await resolveChain(resolver, alias, operation)
    if (live === null) targets.push(alias)
  }
  return targets
}

/** La cadena canónica, o 422 `E_AUTHZ_UNKNOWN_SCOPE` si el scope no existe (para escrituras). */
export async function assertKnownScope(
  resolver: ScopeChainResolver,
  scope: ScopeRef,
  operation: string
): Promise<ScopeRef[]> {
  const chain = await resolveChain(resolver, scope, operation)
  if (!chain) {
    throw new UnknownScopeError(
      `El scope ${scope.type}:${scope.uuid} no existe para el resolutor de la cadena (${operation}). ` +
        `No se escribe sobre un scope que el árbol no reconoce.`
    )
  }
  return chain
}
