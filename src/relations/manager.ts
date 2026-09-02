/**
 * `RelationsManager` — la fachada de ReBAC (Fase 4, lote 4-2).
 *
 * Es el análogo de `AuthorizationManager` para el puerto `RelationsDriver`:
 * aplica la POLICY antes de tocar el driver y despacha la auditoría después.
 * Lo que fija este lote:
 *
 *  - **F-05 (cierre del 🔴 del auditor)**: `relate`/`unrelate` con un
 *    `object.type` o una `relation` que NO estén declarados en
 *    `defineRelationsConfig` ⇒ 422 ANTES de llamar al driver. Junto con ⚪4
 *    (un tipo reservado no se puede declarar) hace IMPOSIBLE que un `relate`
 *    componga el id de un `role_binding` real y escale a `roles.authorize`.
 *  - **R-13**: `assertWrite` PURO (obligatorio aquí, a diferencia de
 *    `roles/`): si rechaza, nada toca el driver.
 *  - `actor` en `onRelationWrite` (auditoría del consumidor sin
 *    `AsyncLocalStorage`).
 *  - `membersOf` como método OPCIONAL DISTINTO de `listSubjects`: si el driver
 *    no lo trae (`membersOfNative: false`) ⇒ 500 `E_AUTHZ_UNSUPPORTED`
 *    nombrándolo, jamás un `skip`.
 *
 * Pureza (regla 2): solo depende del puerto, los errores, la gramática
 * compartida y `defineRelationsConfig`. Nada de `manager`/`drivers/*`.
 */
import {
  ActorRequiredError,
  AuthorizationBackendTimeoutError,
  AuthorizationConfigError,
  UnsupportedOperationError,
  isPartialWrite,
} from '../errors.js'
import { assertScope, assertSubject, assertRelationId, assertExpiresAt } from '../identity.js'
import { isClock, systemClock } from '../clock.js'
import { assertNotFrozenRow } from '../freeze.js'
import type {
  RelObject,
  RelSubject,
  RelationRef,
  RelationWriteEvent,
  RelationWriteOptions,
  RelationsDriver,
  RelationObjectsPage,
  RelationSubjectsPage,
  RelationPage,
  RelationTuplePage,
  RelationTransactionOptions,
  RelationPurgeOptions,
  ScopeRef,
  SubjectRef,
} from '../types.js'
import { isRelUserset } from '../types.js'
import { assertRelationDeclared, assertObjectTypeDeclared } from './define_relations_config.js'
import type { RelationsConfig } from './define_relations_config.js'

export interface RelationsManagerOptions {
  /**
   * Comprobación PURA de escritura (R-13): recibe la referencia completa de la
   * tupla (sujeto, relación, objeto, partición, operación) y LANZA para
   * rechazarla. Corre DESPUÉS de F-05 y ANTES de tocar el driver. **No
   * devuelve veredictos**: todo retorno distinto de `undefined` —una promesa,
   * un `false`, un `true`, una función con `.then`— es 500 `E_AUTHZ_CONFIG`
   * antes del driver (2.4.0-alpha.3 y su cierre: un `false` devuelto no
   * denegaba nada y la escritura entraba).
   */
  assertWrite?(ref: RelationRef): void
  /**
   * Auditoría: se notifica DESPUÉS de que el driver vuelva, con el `actor`
   * (validado), `transactional: true` con `{ transaction }` e
   * `indeterminate: true` al vencer el deadline (invariante 13). Puede ser
   * `async` (la promesa devuelta SE ESPERA); si lanza o rechaza, se registra y
   * NO tumba la escritura ya aplicada (2.4.0-alpha.3, paridad con
   * `hooks.onWrite`). Se tipa `void` (y no `void | Promise<void>`) para no
   * romper a quien ya lo construye a mano con `(e) => events.push(e)`: un
   * retorno cualquiera solo es asignable a `void` a secas.
   */
  onRelationWrite?(event: RelationWriteEvent): void
  /** `true` exige `actor` en toda escritura (paridad con `requireActor` de roles). */
  requireActor?: boolean
  /**
   * Reloj de pared (R-15, paridad con `config.clock` de roles, 2.5 · J1): se
   * aplica al driver con `withClock` al construir; un driver sin `withClock`
   * con `clock` declarado es 500 `E_AUTHZ_CONFIG` (el reloj mentiría).
   */
  clock?: () => Date
  /**
   * Deadline TOTAL (ms, default 5000) de la lectura de la barrera del freeze
   * (paridad con `freezeTimeoutMs` del config de roles; el provider pasa el
   * mismo valor).
   */
  freezeTimeoutMs?: number
  /**
   * **Puerta 2 de `{ transaction }`** (L-2, opt-in): con `true`, el driver
   * tiene que declarar `capabilities.transactionalWrites: true` o el manager
   * falla AL CONSTRUIRSE (500 `E_AUTHZ_CONFIG`) — que para este puerto es el
   * momento de resolver el driver (`buildRelationsManager`). El provider pasa
   * `relations.requireTransactionalWrites ?? config.requireTransactionalWrites`.
   */
  requireTransactionalWrites?: boolean
  /** Nombre del driver (la clave en `relations.drivers`) para los mensajes de las dos puertas. Default `'relations'`. */
  driverName?: string
}

export class RelationsManager {
  readonly #driver: RelationsDriver
  readonly #config: RelationsConfig
  readonly #options: RelationsManagerOptions

  constructor(driver: RelationsDriver, config: RelationsConfig, options: RelationsManagerOptions = {}) {
    if (options.clock !== undefined) {
      if (!isClock(options.clock)) {
        throw new AuthorizationConfigError(
          `RelationsManager: clock debe ser una función () => Date (llegó ${typeof options.clock})`
        )
      }
      if (typeof driver.withClock !== 'function') {
        throw new AuthorizationConfigError(
          `RelationsManager: el driver de relaciones no implementa withClock(now) y la config declara clock: ` +
            `sin él la caducidad de las relaciones se decidiría con otro reloj que el declarado.`
        )
      }
      driver = driver.withClock(options.clock)
    }
    if (options.requireTransactionalWrites === true && driver.capabilities?.transactionalWrites !== true) {
      throw new AuthorizationConfigError(
        `requireTransactionalWrites está en true y el driver de relaciones '${options.driverName ?? 'relations'}' ` +
          `declara transactionalWrites: ${driver.capabilities ? String(driver.capabilities.transactionalWrites) : 'nada (sin capabilities)'}: ` +
          `no puede inscribir relate/unrelate/purge* en la transacción del consumidor («los dos o ninguno»), así que ` +
          `el RelationsManager no se construye. Usa un driver que la declare (database) o quita el flag ` +
          `(relations.requireTransactionalWrites, o el del raíz).`
      )
    }
    this.#driver = driver
    this.#config = config
    this.#options = options
  }

  /**
   * **Puerta 1 de `{ transaction }`** (L-2, siempre activa): una escritura con
   * `{ transaction }` a un driver que no declara `transactionalWrites: true`
   * es 500 `E_AUTHZ_UNSUPPORTED` nombrando driver y operación, ANTES de la
   * barrera, de F-05 y del driver (cero llamadas). Encolar ≠ escribir: aquí
   * la transacción ESCRIBE la tupla dentro de ella, no hay outbox.
   */
  #assertTransactional(options: RelationTransactionOptions | undefined, operation: string): void {
    if (options?.transaction === undefined || options.transaction === null) return
    if (this.#driver.capabilities?.transactionalWrites === true) return
    throw UnsupportedOperationError.transactional(
      `relations.${operation}`,
      this.#options.driverName ?? 'relations',
      'relations'
    )
  }

  /**
   * La marca del evento de una escritura inscrita en la transacción del
   * llamante (2.4.0-alpha.3 · B, paridad literal con `#transactional` de
   * roles, L-3): `onRelationWrite` se dispara cuando el DRIVER vuelve, y en
   * ese momento la tupla existe solo dentro de esa transacción — es un hecho
   * si y solo si el llamante confirma, cosa que el paquete nunca ve. Quien
   * audita lo necesita para no registrar como firme lo que un rollback
   * deshace (`trx.after('commit')`). `undefined`/`null` cuentan como SIN
   * transacción (lo mismo que `#assertTransactional`); sin ella la marca está
   * AUSENTE, nunca `false`.
   */
  #transactional(options: RelationTransactionOptions | undefined): { transactional?: true } {
    return options?.transaction === undefined || options.transaction === null ? {} : { transactional: true }
  }

  /** `{ actor }` listo para fundir en el evento, o `{}`: el evento no inventa autores (como `#writeOptions` de roles). */
  #actorOf(options: { actor?: SubjectRef } | undefined): { actor?: SubjectRef } {
    return options?.actor ? { actor: options.actor } : {}
  }

  /**
   * **Invariante 13 en relaciones** (2.4.0-alpha.3 · C; el MISMO `#write` de
   * roles, `manager.ts:3257`): una escritura que vence el deadline (503
   * `E_AUTHZ_BACKEND_TIMEOUT`) es INDETERMINADA — la sentencia/el `Write`
   * puede aterrizar después de que el llamante reciba el error—. Antes de
   * propagar se notifica el mismo evento con `indeterminate: true`, para que
   * quien audita registre «puede haber ocurrido» en vez de nada. Cualquier
   * otro fallo (422, `assertWrite`, freeze, conexión rechazada) significa que
   * la escritura no ocurrió y se propaga SIN evento. Con `{ transaction }` el
   * evento lleva además `transactional: true` (el rollback del llamante
   * determina el resultado, pero es suyo y el paquete no lo ve). Envuelve las
   * CUATRO escrituras.
   *
   * **Y una escritura PARCIAL también es indeterminada** (cierre del 🟡 6 del
   * auditor de alpha.3): la purga de `openfga` es multi-request (ortografías
   * × tipos, cada una `Read`+`deleteTuples`+`Read`), así que un 503 que NO es
   * timeout —o el 500 `E_AUTHZ_PURGE_INCOMPLETE`— puede llegar DESPUÉS de haber
   * borrado parte. Ahí «esa escritura no ocurrió» sería falso; el driver marca
   * el error con `markPartialWrite` (`src/errors.ts`) y aquí se notifica
   * `indeterminate: true` igual que con el deadline. La frase «no ocurrió y no
   * hay evento» queda para los fallos ANTES de la primera sentencia/`Write`.
   */
  async #write<T>(event: RelationWriteEvent, fn: () => Promise<T>): Promise<T> {
    try {
      return await fn()
    } catch (error) {
      if (error instanceof AuthorizationBackendTimeoutError || isPartialWrite(error)) {
        await this.#notify({ ...event, indeterminate: true })
      }
      throw error
    }
  }

  /**
   * **El evento es una COPIA, no un alias** (⚪ 8 del auditor de alpha.3): el
   * sink lo guarda y el llamante (o el propio sink, ahora que se `await`ea)
   * puede mutar después `object.id`, `partition.uuid` o el `actor`. Copia por
   * nivel de identidad (spread: el `actor` conserva los campos de más que
   * traiga, como en roles — se documenta, no se poda); `expiresAt` es un
   * `Date` inmutable por convención y se copia como instante.
   */
  #copyEvent(event: RelationWriteEvent): RelationWriteEvent {
    const copy: RelationWriteEvent = { ...event, partition: { ...event.partition } }
    if (event.subject !== undefined) {
      copy.subject = isRelUserset(event.subject)
        ? { ...event.subject, object: { ...event.subject.object } }
        : { ...event.subject }
    }
    if (event.object !== undefined) copy.object = { ...event.object }
    if (event.actor !== undefined) copy.actor = { ...event.actor }
    if (event.expiresAt instanceof Date) copy.expiresAt = new Date(event.expiresAt.getTime())
    return copy
  }

  /**
   * Notifica al consumidor (2.4.0-alpha.3 · D1/D2, hallazgo H1; el MISMO
   * `#notify` de roles, `manager.ts:3276`). El hook es un side-effect
   * (auditar, emitir un evento): cuando falla, la escritura YA está aplicada,
   * así que propagar su error le daría al llamante un fallo por una operación
   * que sí ocurrió — y le invitaría a reintentar algo ya hecho. Se ESPERA (un
   * hook `async` que rechaza ya no es un unhandled rejection), se registra y
   * se sigue. Hasta alpha.3 se llamaba sin `await` ni `try/catch`.
   */
  async #notify(event: RelationWriteEvent): Promise<void> {
    try {
      await this.#options.onRelationWrite?.(event)
    } catch (error) {
      await this.#logHookFailure(event, error)
    }
  }

  async #logHookFailure(event: RelationWriteEvent, error: unknown): Promise<void> {
    const context = `authz: el hook onRelationWrite falló tras '${event.operation}' (la escritura sí se aplicó)`
    try {
      const { default: logger } = await import('@adonisjs/core/services/logger')
      logger.error({ err: error, event }, context)
    } catch {
      // Fuera de una app booteada (tests, scripts sueltos) no hay logger.
      console.error(context, error)
    }
  }

  /** El driver crudo — salida documentada de las barreras (plataforma y tests). */
  driver(): RelationsDriver {
    return this.#driver
  }

  /**
   * **F-05**: rechaza un tipo/relación no declarado ANTES de tocar el driver.
   * La gramática de identidad no basta: `role_binding`/`assignee` son
   * gramaticalmente válidos y en el store compartido componen el id de un
   * binding real. Es la MISMA función que aplican los dos drivers (L-0,
   * `assertRelationDeclared`): el manager corta primero; el driver es la red
   * para quien entra por `manager.driver()` o por `reconcileRelations`.
   *
   * **En las OCHO operaciones** (2.4.0-alpha.3, 🔴 1 / 🟠 2 del auditor;
   * cierre-2 · 🟡 3 `membersOf`): hasta alpha.3 solo `relate`/`unrelate`
   * pasaban por aquí, y `purgeObject({ type: 'role_binding', id: R }, S)`
   * componía en el driver `openfga` el id EXACTO del binding real y lo
   * borraba con demostración de cero (`authorize` de `true` a `false`), con
   * un evento de auditoría limpio; `listSubjects('assignee', role_binding)`
   * enumeraba sus asignados. **Dos funciones, no un opcional** (cierre-2,
   * 🟠 1: la `relation?` opcional apagó F-05 en `relate`/`unrelate` sin
   * relación): `#assertDeclared` es ESTRICTA —la relación es obligatoria— y
   * la usan `relate`/`unrelate`/`check`/`listObjects`/`listSubjects`/
   * `membersOf` y el userset del sujeto; `#assertTypeDeclared` (solo el tipo)
   * la usa `purgeObject`. `purgeSubject` no nombra objeto: su F-05 es la del
   * userset (`#assertSubject`).
   */
  #assertDeclared(object: RelObject | { type: string }, relation: string): void {
    assertRelationDeclared(this.#config, object, relation)
  }

  #assertTypeDeclared(object: RelObject | { type: string }): void {
    assertObjectTypeDeclared(this.#config, object)
  }

  /**
   * **R-16**: el `object.id` con la gramática estricta de relaciones ANTES del
   * driver ⇒ 422 `E_AUTHZ_INVALID_IDENTITY`. `#assertDeclared` solo valida el
   * TIPO (F-05): un `object.id` con un `|`/`#`/`:`/espacio se colaba y en
   * `openfga` se ESCRIBÍA (invisibilidad de enumeración y pérdida en
   * `reconcile`) o salía como 503 mal clasificado. Se valida aquí (una vez) y
   * en cada driver (defensa en profundidad).
   */
  #assertObjectId(object: RelObject): void {
    assertRelationId(`el id del objeto '${object?.type}'`, object?.id)
  }

  /**
   * El `actor` de una escritura (2.4.0-alpha.3 · D4, hallazgo H3; paridad con
   * `#writeOptions` de roles, `manager.ts:1512`): **validar-si-viene y después
   * exigir-si-falta**. Hasta alpha.3 solo se comprobaba la PRESENCIA: un
   * `actor: { uuid: 'A#B' }` viajaba al evento (envenena el rastro) y un
   * `actor: {}` truthy satisfacía `requireActor`. Ahora un actor mal formado
   * es 422 `E_AUTHZ_INVALID_IDENTITY` ANTES del driver, en las CUATRO
   * escrituras (purgas incluidas, D-3).
   */
  #assertActor(options: { actor?: SubjectRef } | undefined, operation: string): void {
    if (options?.actor !== undefined) assertSubject(options.actor)
    if (this.#options.requireActor && !options?.actor) {
      throw new ActorRequiredError(
        `relations.${operation}: escritura de relación sin 'actor' y la config exige uno (requireActor).`
      )
    }
  }

  /**
   * **R-13 con dientes** (2.4.0-alpha.3 · D3, hallazgo H2; cierre 🟠 3 / 🟡 4
   * del auditor): `assertWrite` es síncrono y puro, y **no devuelve
   * veredictos: lanza o no lanza**. TODO retorno distinto de `undefined` es
   * 500 `E_AUTHZ_CONFIG` antes de tocar el driver — una promesa (H2: la
   * promesa se descarta con el rechazo quitado para que no salga como
   * unhandled rejection), una FUNCIÓN con `.then` (esquivaba la guarda
   * `typeof 'object'`), un `false` (compila bajo `--strict` y hasta el cierre
   * la escritura ENTRABA: fail-open) y también un `true` (el mismo error de
   * modelo). Un `assertWrite` que LANZA propaga tal cual (es su forma de
   * rechazar). La policy con actor/BD/await va en el servicio del consumidor.
   */
  #assertWrite(ref: RelationRef, operation: string): void {
    const result: unknown = this.#options.assertWrite?.(ref)
    if (result === undefined) return
    if (result !== null && typeof (result as { then?: unknown }).then === 'function') {
      Promise.resolve(result).then(undefined, () => {})
    }
    throw AuthorizationConfigError.assertWriteReturned(`relations.${operation}`, result)
  }

  /**
   * **La barrera del freeze, la MISMA que la de roles** (L-1 · J1, juez del
   * panel `{trx}`): hasta L-1 no había una sola referencia al freeze en
   * `relations/`, así que durante un cutover las escrituras de roles recibían
   * 503 y las de relaciones ENTRABAN, y `authz:relations:reconcile`
   * certificaba un estado que podía cambiar debajo. Es la fila `id = 2` de
   * `authz_catalog_version` leída por la conexión del motor (`assertNotFrozenRow`,
   * `src/freeze.ts` — raíz de `src/`, así que la regla 2 de pureza se cumple),
   * delante de las CUATRO escrituras y antes de validar nada: 503
   * `E_AUTHZ_FROZEN` reintentable. Las lecturas no pasan por aquí.
   * `manager.driver()` sigue siendo la salida documentada.
   */
  #assertNotFrozen(operation: string): Promise<void> {
    return assertNotFrozenRow(`relations.${operation}`, {
      driver: 'relations',
      nowMs: (this.#options.clock ?? systemClock)().getTime(),
      timeoutMs: this.#options.freezeTimeoutMs,
    })
  }

  async relate(
    subject: RelSubject,
    relation: string,
    object: RelObject,
    partition: ScopeRef,
    options?: RelationWriteOptions
  ): Promise<void> {
    this.#assertTransactional(options, 'relate')
    await this.#assertNotFrozen('relate')
    this.#assertDeclared(object, relation)
    this.#assertObjectId(object)
    this.#assertActor(options, 'relate')
    assertScope(partition)
    this.#assertSubject(subject, partition)
    // R-15: `expiresAt` en sus tres estados legales (omitido / null / Date
    // válida); cualquier otra cosa es 422 ANTES del driver (invariante 5).
    assertExpiresAt(options?.expiresAt)
    const ref: RelationRef = { operation: 'relate', subject, relation, object, partition }
    if (options && 'expiresAt' in options) ref.expiresAt = options.expiresAt
    this.#assertWrite(ref, 'relate')
    const event = this.#copyEvent({ ...ref, ...this.#actorOf(options), ...this.#transactional(options) })
    await this.#write(event, () => this.#driver.relate(subject, relation, object, partition, options))
    await this.#notify(event)
  }

  async unrelate(
    subject: RelSubject,
    relation: string,
    object: RelObject,
    partition: ScopeRef,
    options?: RelationWriteOptions
  ): Promise<void> {
    this.#assertTransactional(options, 'unrelate')
    await this.#assertNotFrozen('unrelate')
    this.#assertDeclared(object, relation)
    this.#assertObjectId(object)
    this.#assertActor(options, 'unrelate')
    assertScope(partition)
    this.#assertSubject(subject, partition)
    const ref: RelationRef = { operation: 'unrelate', subject, relation, object, partition }
    this.#assertWrite(ref, 'unrelate')
    const event = this.#copyEvent({ ...ref, ...this.#actorOf(options), ...this.#transactional(options) })
    await this.#write(event, () => this.#driver.unrelate(subject, relation, object, partition, options))
    await this.#notify(event)
  }

  /**
   * **Las lecturas también pasan por F-05** (2.4.0-alpha.3, 🟠 2 del auditor):
   * el `objectId` lleva la partición, así que `listSubjects('assignee',
   * { type: 'role_binding', id: R }, S)` era la lista de asignados de un rol
   * en un scope, por el puerto de relaciones, sin catálogo, sin `within`, sin
   * `requireActor` (las lecturas no lo tienen) y sin visibilidad de rol
   * (invariante 18). `check`/`listSubjects` validan el par (tipo, relación);
   * `listObjects` el tipo; el userset del sujeto, su par. PRIMERA línea,
   * cero llamadas al driver; el driver re-valida (defensa en profundidad).
   */
  async check(subject: RelSubject, relation: string, object: RelObject, partition: ScopeRef): Promise<boolean> {
    this.#assertDeclared(object, relation)
    assertScope(partition)
    this.#assertObjectId(object)
    this.#assertSubject(subject, partition)
    return this.#driver.check(subject, relation, object, partition)
  }

  async listObjects(
    subject: RelSubject,
    relation: string,
    objectType: string,
    partition: ScopeRef,
    page?: RelationPage
  ): Promise<RelationObjectsPage> {
    this.#assertDeclared({ type: objectType }, relation)
    assertScope(partition)
    this.#assertSubject(subject, partition)
    return this.#driver.listObjects(subject, relation, objectType, partition, page)
  }

  async listSubjects(
    relation: string,
    object: RelObject,
    partition: ScopeRef,
    page?: RelationPage
  ): Promise<RelationSubjectsPage> {
    this.#assertDeclared(object, relation)
    assertScope(partition)
    this.#assertObjectId(object)
    return this.#driver.listSubjects(relation, object, partition, page)
  }

  /**
   * **Las purgas notifican** (2.4.0-alpha.3 · E, hallazgo #4; D-1/D-3): UN
   * evento por llamada —aunque el driver barra las dos ortografías del uuid
   * de partición por dentro: el manager no canoniza particiones, y diverge a
   * propósito de `scopes.detached`, que emite uno por ortografía porque ahí
   * canoniza el MANAGER—, con el objetivo y la partición TAL COMO la pasó el
   * llamante, sin `relation` y SIN conteo (el puerto devuelve `void`; un
   * conteo lo rompería para terceros y un rollback lo desmentiría). Se
   * notifica también cuando no borra nada: el hecho auditable es «alguien
   * pidió borrar las llaves de X». Sujeta a `requireActor` (D-3, breaking) y
   * al actor validado; NO pasa por `assertWrite` (su `RelationRef.operation`
   * es `'relate' | 'unrelate'`, tipo publicado de R-13). Mismo `#write`
   * (invariante 13) y mismo `#notify` que `relate`/`unrelate`.
   *
   * **Y pasan por F-05** (cierre del 🔴 1 del auditor de alpha.3): el mismo
   * orden que `relate` —puerta 1, freeze, F-05 (solo el TIPO: una purga no
   * nombra relación), id, actor, scope—. `purgeSubject` valida su sujeto como
   * `relate` (`#assertSubject`, ⚪ 7: un userset no declarado o un holder mal
   * formado es 422 ANTES del driver y no llega al evento).
   */
  async purgeObject(object: RelObject, partition: ScopeRef, options?: RelationPurgeOptions): Promise<void> {
    this.#assertTransactional(options, 'purgeObject')
    await this.#assertNotFrozen('purgeObject')
    this.#assertTypeDeclared(object)
    assertScope(partition)
    this.#assertObjectId(object)
    this.#assertActor(options, 'purgeObject')
    const event = this.#copyEvent({
      operation: 'purgeObject',
      object,
      partition,
      ...this.#actorOf(options),
      ...this.#transactional(options),
    })
    await this.#write(event, () => this.#driver.purgeObject(object, partition, options))
    await this.#notify(event)
  }

  async purgeSubject(subject: RelSubject, partition: ScopeRef, options?: RelationPurgeOptions): Promise<void> {
    this.#assertTransactional(options, 'purgeSubject')
    await this.#assertNotFrozen('purgeSubject')
    assertScope(partition)
    this.#assertSubject(subject, partition)
    this.#assertActor(options, 'purgeSubject')
    const event = this.#copyEvent({
      operation: 'purgeSubject',
      subject,
      partition,
      ...this.#actorOf(options),
      ...this.#transactional(options),
    })
    await this.#write(event, () => this.#driver.purgeSubject(subject, partition, options))
    await this.#notify(event)
  }

  /**
   * Membresía TRANSITIVA de un grupo (a través de usersets anidados) —
   * DISTINTA de `listSubjects`, que da los hechos DIRECTOS. Solo la trae el
   * driver `database` (`membersOfNative: true`); en `openfga` es 500
   * `E_AUTHZ_UNSUPPORTED` nombrándola (la transitiva sería `ListUsers`, que
   * trunca), jamás un `skip`.
   */
  async membersOf(
    object: RelObject,
    relation: string,
    partition: ScopeRef,
    page?: RelationPage
  ): Promise<RelationSubjectsPage> {
    // Cierre-2 · 🟡 3: `membersOf` toma `(object, relation)` —la forma exacta
    // que F-05 guarda— y era la octava operación fuera de «las siete»; un
    // driver de terceros con `membersOfNative: true` sobre un store compartido
    // reabría la fuga de `listSubjects`. F-05 (par, ESTRICTA) ANTES de la
    // capacidad: 422 con cero llamadas, también donde `membersOf` sería 500.
    this.#assertDeclared(object, relation)
    assertScope(partition)
    this.#assertObjectId(object)
    if (!this.#driver.membersOf || !this.#driver.capabilities?.membersOfNative) {
      throw new UnsupportedOperationError(
        'membersOf',
        'la membresía transitiva de un grupo',
        'relations',
        `Solo el driver 'database' la resuelve (CTE recursiva); en 'openfga' la transitiva sería ` +
          `'ListUsers', que trunca. Usa 'listSubjects' para los hechos directos.`
      )
    }
    return this.#driver.membersOf(object, relation, partition, page)
  }

  /** ORIGEN de `authz:reconcile` de relaciones. 500 `E_AUTHZ_UNSUPPORTED` si el driver no lo trae. */
  async enumerateRelations(partition: ScopeRef, page?: RelationPage): Promise<RelationTuplePage> {
    assertScope(partition)
    if (!this.#driver.enumerateRelations || !this.#driver.capabilities?.enumerateRelations) {
      throw new UnsupportedOperationError(
        'enumerateRelations',
        'ser origen de authz:reconcile de relaciones',
        'relations'
      )
    }
    return this.#driver.enumerateRelations(partition, page)
  }

  #assertSubject(subject: RelSubject, partition: ScopeRef): void {
    if (isRelUserset(subject)) {
      // El userset (`group:g#member`) también se ancla a la partición; su
      // objeto se valida como cualquier otro objeto declarado (tipo + id, R-16).
      this.#assertDeclared(subject.object, subject.relation)
      this.#assertObjectId(subject.object)
      assertScope(partition)
      return
    }
    assertSubject(subject)
  }
}
