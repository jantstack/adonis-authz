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
  RelationTypeUnknownError,
  RelationUnknownError,
  UnsupportedOperationError,
} from '../errors.js'
import { assertScope, assertSubject } from '../identity.js'
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
}

export class RelationsManager {
  readonly #driver: RelationsDriver
  readonly #config: RelationsConfig
  readonly #options: RelationsManagerOptions

  constructor(driver: RelationsDriver, config: RelationsConfig, options: RelationsManagerOptions = {}) {
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
   * binding real.
   */
  #assertDeclared(object: RelObject, relation: string): void {
    if (!object || typeof object !== 'object' || typeof object.type !== 'string') {
      throw new RelationTypeUnknownError(
        `Objeto de relación inválido: se esperaba { type, id } y llegó ${JSON.stringify(object)}.`
      )
    }
    if (!this.#config.hasType(object.type)) {
      throw new RelationTypeUnknownError(
        `El tipo de objeto '${object.type}' no está declarado en defineRelationsConfig (F-05): ` +
          `relate/unrelate solo aceptan tipos declarados. En el store compartido un tipo no declarado ` +
          `podría componer el id de un 'role_binding' real y escalar a roles.authorize.`
      )
    }
    if (!this.#config.isDeclared(object.type, relation)) {
      throw new RelationUnknownError(
        `La relación '${relation}' no está declarada para el tipo '${object.type}' en ` +
          `defineRelationsConfig (F-05).`
      )
    }
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
    this.#assertActor(options)
    assertScope(partition)
    this.#assertSubject(subject, partition)
    const ref: RelationRef = { operation: 'relate', subject, relation, object, partition }
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
    return this.#driver.listSubjects(relation, object, partition, page)
  }

  async purgeObject(object: RelObject, partition: ScopeRef): Promise<void> {
    assertScope(partition)
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
      // objeto se valida como cualquier otro objeto declarado.
      this.#assertDeclared(subject.object, subject.relation)
      assertScope(partition)
      return
    }
    assertSubject(subject)
  }
}
