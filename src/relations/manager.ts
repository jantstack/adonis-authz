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
import { ActorRequiredError, AuthorizationConfigError, UnsupportedOperationError } from '../errors.js'
import { assertScope, assertSubject, assertRelationId, assertExpiresAt } from '../identity.js'
import { isClock } from '../clock.js'
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
  ScopeRef,
} from '../types.js'
import { isRelUserset } from '../types.js'
import { assertRelationDeclared } from './define_relations_config.js'
import type { RelationsConfig } from './define_relations_config.js'

export interface RelationsManagerOptions {
  /**
   * Comprobación PURA de escritura (R-13): recibe la referencia completa de la
   * tupla (sujeto, relación, objeto, partición, operación) y lanza para
   * rechazarla. Corre DESPUÉS de F-05 y ANTES de tocar el driver.
   */
  assertWrite?(ref: RelationRef): void
  /** Auditoría: se notifica DESPUÉS de una escritura confirmada, con el `actor`. */
  onRelationWrite?(event: RelationWriteEvent): void
  /** `true` exige `actor` en toda escritura (paridad con `requireActor` de roles). */
  requireActor?: boolean
  /**
   * Reloj de pared (R-15, paridad con `config.clock` de roles, 2.5 · J1): se
   * aplica al driver con `withClock` al construir; un driver sin `withClock`
   * con `clock` declarado es 500 `E_AUTHZ_CONFIG` (el reloj mentiría).
   */
  clock?: () => Date
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
    this.#driver = driver
    this.#config = config
    this.#options = options
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
   */
  #assertDeclared(object: RelObject, relation: string): void {
    assertRelationDeclared(this.#config, object, relation)
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

  #assertActor(options?: RelationWriteOptions): void {
    if (this.#options.requireActor && !options?.actor) {
      throw new ActorRequiredError(
        `Escritura de relación sin 'actor' y la config exige uno (requireActor).`
      )
    }
  }

  async relate(
    subject: RelSubject,
    relation: string,
    object: RelObject,
    partition: ScopeRef,
    options?: RelationWriteOptions
  ): Promise<void> {
    this.#assertDeclared(object, relation)
    this.#assertObjectId(object)
    this.#assertActor(options)
    assertScope(partition)
    this.#assertSubject(subject, partition)
    // R-15: `expiresAt` en sus tres estados legales (omitido / null / Date
    // válida); cualquier otra cosa es 422 ANTES del driver (invariante 5).
    assertExpiresAt(options?.expiresAt)
    const ref: RelationRef = { operation: 'relate', subject, relation, object, partition }
    if (options && 'expiresAt' in options) ref.expiresAt = options.expiresAt
    this.#options.assertWrite?.(ref)
    await this.#driver.relate(subject, relation, object, partition, options)
    this.#options.onRelationWrite?.({ ...ref, actor: options?.actor })
  }

  async unrelate(
    subject: RelSubject,
    relation: string,
    object: RelObject,
    partition: ScopeRef,
    options?: RelationWriteOptions
  ): Promise<void> {
    this.#assertDeclared(object, relation)
    this.#assertObjectId(object)
    this.#assertActor(options)
    assertScope(partition)
    this.#assertSubject(subject, partition)
    const ref: RelationRef = { operation: 'unrelate', subject, relation, object, partition }
    this.#options.assertWrite?.(ref)
    await this.#driver.unrelate(subject, relation, object, partition, options)
    this.#options.onRelationWrite?.({ ...ref, actor: options?.actor })
  }

  async check(subject: RelSubject, relation: string, object: RelObject, partition: ScopeRef): Promise<boolean> {
    assertScope(partition)
    this.#assertObjectId(object)
    return this.#driver.check(subject, relation, object, partition)
  }

  async listObjects(
    subject: RelSubject,
    relation: string,
    objectType: string,
    partition: ScopeRef,
    page?: RelationPage
  ): Promise<RelationObjectsPage> {
    assertScope(partition)
    return this.#driver.listObjects(subject, relation, objectType, partition, page)
  }

  async listSubjects(
    relation: string,
    object: RelObject,
    partition: ScopeRef,
    page?: RelationPage
  ): Promise<RelationSubjectsPage> {
    assertScope(partition)
    this.#assertObjectId(object)
    return this.#driver.listSubjects(relation, object, partition, page)
  }

  async purgeObject(object: RelObject, partition: ScopeRef): Promise<void> {
    assertScope(partition)
    this.#assertObjectId(object)
    return this.#driver.purgeObject(object, partition)
  }

  async purgeSubject(subject: RelSubject, partition: ScopeRef): Promise<void> {
    assertScope(partition)
    return this.#driver.purgeSubject(subject, partition)
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
    assertScope(partition)
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
