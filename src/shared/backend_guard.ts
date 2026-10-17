import {
  AuthorizationBackendError,
  AuthorizationBackendTimeoutError,
  NoScopeResolverError,
  ScopeResolverError,
  UnknownScopeError,
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
    current = current.cause
  }
  return false
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
