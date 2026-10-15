/**
 * **El contrato del puerto `RelationsDriver`** (Fase 4, lote 4-2) — el juez de
 * ReBAC, SEPARADO de `runAuthorizationDriverContract`.
 *
 *   import { runRelationsDriverContract, makeRelationsDriver } from '@jantstack/adonis-authz/testing'
 *
 * Es un runner APARTE (precedente: `runMigrationContract`), no un nivel `'2.4'`
 * del runner de roles: así los conteos de `contract_harness.spec.ts` no
 * cambian y los dos puertos no se conflan. Corre contra un DOBLE en memoria
 * (`makeRelationsDriver`) —como los casos `'2.1'` de roles corren sobre
 * `managerOver`— para probar el CONTRATO sin servidor: F-05, la validación de
 * config y las capacidades. Lo que NO puede probar un doble (la profundidad
 * real, «un Check», el truncado real de `ListObjects`, la paridad de
 * respuestas con `database`) es del lote 4-4 contra el `:8101`.
 *
 * **Cada capacidad lleva SUS DOS CARAS** y el runner FALLA si una no está
 * poblada (más estricto que el guard de roles, que solo exige la cara `true`):
 * el tester lo pidió explícito —una cara ausente es un `skip` disfrazado—.
 */
import { v7 as uuidv7 } from 'uuid'
import { test as japaTest } from '@japa/runner'
import type { Assert } from '@japa/assert'
import db from '@adonisjs/lucid/services/db'
import { partitionKey, scopeKey } from '../identity.js'
import { RelationsManager } from '../relations/manager.js'
import {
  defineRelationsConfig,
  assertRelationDeclared,
  assertObjectTypeDeclared,
  assertUsersetSubject,
  assertRelationDenyable,
  assertDenySubject,
  assertDenyNoExpiry,
  cutPathAllows,
  decideFrom,
  deniedRelationOf,
  relationsDown,
  RELATION_DENY_PREFIX,
} from '../relations/define_relations_config.js'
import { assertCheckManyObjects, distinctObjects, expandByPosition, RELATIONS_CHECK_MANY_MAX } from '../relations/check_many.js'
import { systemClock } from '../clock.js'
import type { Clock } from '../clock.js'
import { resolveGrantExpiry } from '../expiry.js'
import type { RelationsConfig } from '../relations/define_relations_config.js'
import type {
  RelObject,
  RelSubject,
  RelationsDriver,
  RelationsDriverCapabilities,
  RelationObjectsPage,
  RelationSubjectsPage,
  RelationTuplePage,
  RelationPage,
  RelationWriteEvent,
  RelationDecision,
  ScopeRef,
  SubjectRef,
} from '../types.js'
import { APP_SCOPE, isRelUserset } from '../types.js'
import type { ContractTestApi } from './contract.js'

/* ── El vocabulario del contrato ─────────────────────────────────────────── */

/** Los holder types del contrato de relaciones. */
export const RELATIONS_HOLDER_TYPES = ['user', 'admin', 'integration'] as const

/**
 * La config FIJA del contrato: un tipo `document` con `owner ⊆ editor ⊆
 * viewer` (includes de un nivel) y `membersOf` habilitado en `database`.
 */
/**
 * **Los dos tipos del contrato** (plan 2.5 · lote A, H10): `document` y un
 * SEGUNDO tipo con las MISMAS relaciones, `workspace`, para que «tipos
 * mezclados con la misma relación responden por ítem» (`checkMany`, P4-7)
 * sea observable con la config fija —solo con `document` y el `group`
 * built-in no comparten nombre de relación—. Cambio anunciado del export
 * publicado: un harness de terceros que afirme sobre el modelo publicado de
 * esta config ve un tipo más.
 */
export const RELATIONS_CONTRACT_OBJECT_TYPES = ['document', 'workspace'] as const

/**
 * La config FIJA del contrato: `document` y `workspace`, cada uno con `owner ⊆
 * editor ⊆ viewer` (includes de un nivel) y `membersOf` habilitado en `database`.
 */
export function contractRelationsConfig(): RelationsConfig {
  return defineRelationsConfig({
    objectTypes: RELATIONS_CONTRACT_OBJECT_TYPES.map((type) => ({
      type,
      relations: [{ name: 'owner' }, { name: 'editor', includes: ['owner'] }, { name: 'viewer', includes: ['editor'] }],
    })),
    holderTypes: [...RELATIONS_HOLDER_TYPES],
    database: { membersOf: true },
  })
}

/**
 * **La config del contrato CON deny** (plan 2.5 · lote D · D1): los MISMOS dos tipos con el mismo retículo y, además,
 * un tercero sin opt-in —para que «deny sobre un tipo sin deny ⇒ 422» y «D8: un tipo sin opt-in también honra»
 * se juzguen con la config fija—:
 *
 *  - `document`: `deny: 'write'` (fase 2: se escriben denies);
 *  - `workspace`: `deny: 'read'` (fase 1: el modelo y las lecturas honran; `deny()` ⇒ 422);
 *  - `note`: sin opt-in.
 *
 * Es una config APARTE (no se tocó `contractRelationsConfig`): un tipo sin `deny` genera el modelo de 2.4.0-alpha.10
 * byte a byte (D-29) y los casos de antes no cambian de config.
 */
export const RELATIONS_CONTRACT_DENY_TYPES = { document: 'write', workspace: 'read', note: undefined } as const

export function contractDenyRelationsConfig(): RelationsConfig {
  return defineRelationsConfig({
    objectTypes: (Object.keys(RELATIONS_CONTRACT_DENY_TYPES) as Array<keyof typeof RELATIONS_CONTRACT_DENY_TYPES>).map((type) => {
      const relations = [{ name: 'owner' }, { name: 'editor', includes: ['owner'] }, { name: 'viewer', includes: ['editor'] }]
      const deny = RELATIONS_CONTRACT_DENY_TYPES[type]
      return deny === undefined ? { type, relations } : { type, relations, deny }
    }),
    holderTypes: [...RELATIONS_HOLDER_TYPES],
    database: { membersOf: true },
  })
}

export interface RelationsDriverContractHarness {
  name: string
  /** Lo que este driver DECLARA. Cada valor se juzga con su cara. */
  capabilities: RelationsDriverCapabilities
  /** Construye el driver sobre la config del contrato (fresco por caso). */
  makeDriver(config: RelationsConfig): RelationsDriver | Promise<RelationsDriver>
  /** Tope del backend para el truncado (whenTrue de `listObjectsTruncation`). */
  limits?: { listMaxResults?: number }
  /**
   * Solo con `transactionalWrites: true` (L-4, paridad con el hook
   * `transactions` del runner de roles): cómo abre el juez una transacción de
   * LA CONEXIÓN DEL DRIVER y cómo cuenta las tuplas de una partición en el
   * backend — el CENSO: el rollback se juzga por filas, no solo por la
   * respuesta de `check`. Default: `db.transaction()` de Lucid (conexión
   * primaria) y `authz_relations`, lo que vale para el driver `database`. Un
   * driver de terceros con otra conexión u otra tabla trae el suyo.
   */
  transactions?: RelationsContractTransactions
}

/** Ver `RelationsDriverContractHarness.transactions`. */
export interface RelationsContractTransactions {
  begin(): Promise<{ client: unknown; commit(): Promise<unknown>; rollback(): Promise<unknown> }>
  /** Cuántas tuplas hay en la partición, por la conexión del motor (fuera de toda transacción). */
  census(partition: ScopeRef): Promise<number>
}

/** El default de `RelationsDriverContractHarness.transactions`: Lucid + `authz_relations`. */
export function lucidRelationsContractTransactions(): RelationsContractTransactions {
  return {
    async begin() {
      const trx = await db.transaction()
      return { client: trx, commit: () => trx.commit(), rollback: () => trx.rollback() }
    },
    async census(partition) {
      const rows: any[] = await db.from('authz_relations').where('partition_key', scopeKey(partition)).count('* as n')
      return Number(rows[0]?.n ?? 0)
    },
  }
}

/* ── El DOBLE en memoria ─────────────────────────────────────────────────── */

interface Tuple {
  partition: string
  objectType: string
  objectId: string
  relation: string
  subject: RelSubject
  subjectKey: string
  /** R-15: la caducidad escrita (`null` = no caduca). */
  expiresAt: Date | null
}

/**
 * La clave de partición del doble pasa por `partitionKey` (`src/identity.ts`), la MISMA puerta que los dos
 * drivers reales (plan 2.5 · lote 0, cierre ⚪ 11; lote A, D4): una partición mal formada (`A#B`, mayúsculas) es
 * 422 `E_AUTHZ_INVALID_IDENTITY` también en el fixture, y un uuid de 32 hex SIN guiones también (D4). Hasta el
 * cierre del lote 0 componía la clave por plantilla y aceptaba cualquier cosa, así que la columna `partition`
 * de la guardia de superficie no podía decir nada del doble.
 */
function scopeKeyOf(scope: ScopeRef): string {
  return partitionKey(scope)
}

function subjectKeyOf(subject: RelSubject): string {
  if (isRelUserset(subject)) return `${subject.object.type}:${subject.object.id}#${subject.relation}`
  return `${subject.type}:${subject.uuid}`
}

export interface MakeRelationsDriverOptions {
  config: RelationsConfig
  capabilities: RelationsDriverCapabilities
  limits?: { listMaxResults?: number }
}

/**
 * Un `RelationsDriver` en memoria que satisface el puerto y HONRA las
 * capacidades declaradas (para poblar las dos caras del contrato). Es el doble
 * que prueba el CONTRATO —no el MODELO fusionado (eso es el `:8101` en 4-4)—.
 */
export function makeRelationsDriver(options: MakeRelationsDriverOptions): RelationsDriver {
  return buildRelationsDouble(options, [], systemClock)
}

/**
 * El doble, sobre un conjunto de tuplas COMPARTIDO y un reloj: `withClock`
 * (solo con `injectableClock: true`) devuelve otra vista sobre las MISMAS
 * tuplas con otro `now`, como los drivers reales (R-15).
 */
function buildRelationsDouble(options: MakeRelationsDriverOptions, tuples: Tuple[], now: Clock): RelationsDriver {
  const { config, capabilities, limits } = options

  /**
   * **F-05 en el DOBLE** (plan 2.5 · lote 0, D13; hallazgo H8 del tester): hasta el lote 0 el doble
   * publicado no re-validaba tipo/relación —solo el manager cortaba— y un driver de terceros podía
   * calcar esa forma y pasar el contrato. El doble aplica las MISMAS dos funciones que los dos drivers
   * reales (`assertRelationDeclared` estricta y `assertObjectTypeDeclared` de tipo), en las ocho
   * operaciones y en el userset del sujeto. La guardia de superficie (`tests/guard_surface.spec.ts`,
   * filas `double`) lo sondea en el doble y en su vista `withClock`.
   */
  function assertSubjectDeclared(subject: RelSubject): void {
    // B3 (lote B): F-05 del par y solo `group#member`, la MISMA función que las tres capas reales.
    if (isRelUserset(subject)) assertUsersetSubject(config, subject)
  }

  /** Caducidad ESTRICTA (R-15): la que vence AHORA ya no cuenta. `at` fija el instante (un `now` por lote en `checkMany`). */
  function active(t: Tuple, at: Clock = now): boolean {
    return t.expiresAt === null || t.expiresAt.getTime() > at().getTime()
  }

  /** `down*(R)` — la función ÚNICA de la config (lote D), la misma que los dos drivers reales. */
  function expandDown(objectType: string, relation: string): Set<string> {
    return new Set(relationsDown(config, objectType, relation))
  }

  /** Los hechos DIRECTOS vigentes (los caducados no conceden ni se enumeran, R-15). */
  function directSubjects(partition: string, objectType: string, objectId: string, relation: string, at: Clock = now): Tuple[] {
    return tuples.filter(
      (t) =>
        t.partition === partition &&
        t.objectType === objectType &&
        t.objectId === objectId &&
        t.relation === relation &&
        active(t, at)
    )
  }

  /**
   * **El PRINCIPAL del sujeto** (lote D, la misma CTE `principal` del driver `database`): él mismo y cada
   * `group:g#member` del que es miembro VIGENTE, transitivamente (grupos anidados). Un grant o un deny alcanzan al
   * sujeto si su sujeto directo está aquí — por eso un deny a `g#member` lo transporta una membresía, y deja de
   * transportarlo cuando esa membresía caduca (M6, caso C).
   */
  function principalOf(subject: RelSubject, partition: string, at: Clock = now): Set<string> {
    const out = new Set<string>([subjectKeyOf(subject)])
    let grew = true
    while (grew) {
      grew = false
      for (const t of tuples) {
        if (t.partition !== partition || t.objectType !== 'group' || t.relation !== 'member' || !active(t, at)) continue
        const key = `group:${t.objectId}#member`
        if (out.has(t.subjectKey) && !out.has(key)) {
          out.add(key)
          grew = true
        }
      }
    }
    return out
  }

  /** Las relaciones con grant (`allowed`) y con deny (`denied`, nombre PÚBLICO) que alcanzan al principal en el objeto. */
  function factsOn(principal: Set<string>, object: RelObject, partition: string, at: Clock = now): { allowed: Set<string>; denied: Set<string> } {
    const allowed = new Set<string>()
    const denied = new Set<string>()
    for (const t of tuples) {
      if (t.partition !== partition || t.objectType !== object.type || t.objectId !== object.id || !active(t, at)) continue
      if (!principal.has(t.subjectKey)) continue
      if (t.relation.startsWith(RELATION_DENY_PREFIX)) denied.add(t.relation.slice(RELATION_DENY_PREFIX.length))
      else allowed.add(t.relation)
    }
    return { allowed, denied }
  }

  /** `check` con CORTE DE CAMINO (D5): `cutPathAllows`, la regla ÚNICA (la misma que `database` y el oráculo). */
  function resolves(subject: RelSubject, relation: string, object: RelObject, partition: string, at: Clock = now): boolean {
    const { allowed, denied } = factsOn(principalOf(subject, partition, at), object, partition, at)
    return cutPathAllows(config, object.type, relation, allowed, denied)
  }

  function collectMembers(object: RelObject, relation: string, partition: string, seen = new Set<string>()): RelSubject[] {
    const key = `${object.type}:${object.id}#${relation}`
    if (seen.has(key)) return []
    seen.add(key)
    const out: RelSubject[] = []
    for (const rel of expandDown(object.type, relation)) {
      for (const t of directSubjects(partition, object.type, object.id, rel)) {
        if (isRelUserset(t.subject)) {
          out.push(...collectMembers(t.subject.object, t.subject.relation, partition, seen))
        } else {
          out.push(t.subject)
        }
      }
    }
    return dedupeSubjects(out)
  }

  function dedupeSubjects(subjects: RelSubject[]): RelSubject[] {
    const seen = new Set<string>()
    const out: RelSubject[] = []
    for (const s of subjects) {
      const k = subjectKeyOf(s)
      if (seen.has(k)) continue
      seen.add(k)
      out.push(s)
    }
    return out
  }

  const driver: RelationsDriver = {
    capabilities,

    async relate(subject, relation, object, partition, options) {
      assertRelationDeclared(config, object, relation)
      assertSubjectDeclared(subject)
      const partitionKey = scopeKeyOf(partition)
      const subjectKey = subjectKeyOf(subject)
      const existing = tuples.find(
        (t) =>
          t.partition === partitionKey &&
          t.objectType === object.type &&
          t.objectId === object.id &&
          t.relation === relation &&
          t.subjectKey === subjectKey
      )
      // R-15, los tres estados (invariante 10): omitido preserva la vigente
      // (una caducada revive sin caducidad), null la quita, Date la fija.
      const expiresAt = resolveGrantExpiry(existing?.expiresAt ?? null, options?.expiresAt, now())
      if (existing) {
        existing.expiresAt = expiresAt
        return
      }
      tuples.push({
        partition: partitionKey,
        objectType: object.type,
        objectId: object.id,
        relation,
        subject,
        subjectKey,
        expiresAt,
      })
    },

    async unrelate(subject, relation, object, partition) {
      assertRelationDeclared(config, object, relation)
      assertSubjectDeclared(subject)
      const partitionKey = scopeKeyOf(partition)
      const subjectKey = subjectKeyOf(subject)
      for (let i = tuples.length - 1; i >= 0; i--) {
        const t = tuples[i]
        if (
          t.partition === partitionKey &&
          t.objectType === object.type &&
          t.objectId === object.id &&
          t.relation === relation &&
          t.subjectKey === subjectKey
        ) {
          tuples.splice(i, 1)
        }
      }
    },

    async check(subject, relation, object, partition) {
      assertRelationDeclared(config, object, relation)
      assertSubjectDeclared(subject)
      return resolves(subject, relation, object, scopeKeyOf(partition))
    },

    async listObjects(subject, relation, objectType, partition, page): Promise<RelationObjectsPage> {
      assertRelationDeclared(config, { type: objectType }, relation)
      assertSubjectDeclared(subject)
      const partitionKey = scopeKeyOf(partition)
      const ids = new Set<string>()
      for (const t of tuples) {
        if (t.partition === partitionKey && t.objectType === objectType && active(t)) ids.add(t.objectId)
      }
      const matches: RelObject[] = []
      for (const id of ids) {
        if (resolves(subject, relation, { type: objectType, id }, partitionKey)) {
          matches.push({ type: objectType, id })
        }
      }
      matches.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
      // `listObjectsTruncation`: si el backend tiene tope y el driver lo
      // señala, la página trunca al tope y avisa. Si no, es exhaustiva.
      const cap = limits?.listMaxResults
      if (capabilities.listObjectsTruncation && cap && matches.length > cap) {
        return { objects: matches.slice(0, cap), truncated: true }
      }
      return { objects: matches }
    },

    async listSubjects(relation, object, partition, page): Promise<RelationSubjectsPage> {
      assertRelationDeclared(config, object, relation)
      const partitionKey = scopeKeyOf(partition)
      // DIRECTOS del relation EXACTO (invariante 7): ni transitivo (eso es
      // `membersOf`) ni derivado. `usersetSubjects` decide si los usersets
      // (`group:g#member`) salen o solo los holders.
      const direct = directSubjects(partitionKey, object.type, object.id, relation)
      const subjects = direct
        .map((t) => t.subject)
        .filter((s) => capabilities.usersetSubjects || !isRelUserset(s))
      return { subjects: dedupeSubjects(subjects) }
    },

    async purgeObject(object, partition) {
      assertObjectTypeDeclared(config, object)
      const partitionKey = scopeKeyOf(partition)
      for (let i = tuples.length - 1; i >= 0; i--) {
        const t = tuples[i]
        if (t.partition === partitionKey && t.objectType === object.type && t.objectId === object.id) {
          tuples.splice(i, 1)
        }
      }
    },

    async purgeSubject(subject, partition) {
      assertSubjectDeclared(subject)
      const partitionKey = scopeKeyOf(partition)
      const subjectKey = subjectKeyOf(subject)
      for (let i = tuples.length - 1; i >= 0; i--) {
        const t = tuples[i]
        if (t.partition === partitionKey && t.subjectKey === subjectKey) tuples.splice(i, 1)
      }
    },
  }

  // `checkMany` (plan 2.5 · lote A): el doble lo trae solo cuando declara
  // `singleCheckRelations` —el driver que resuelve en UNA llamada es el que
  // tiene un lote nativo—; el MÍNIMO no lo trae y así el runner ejerce el
  // respaldo del manager (N `check`, P4-9) sin una capacidad nueva.
  if (capabilities.singleCheckRelations) {
    driver.checkMany = async (subject, relation, objects, partition): Promise<boolean[]> => {
      assertCheckManyObjects(objects)
      for (const object of objects) assertRelationDeclared(config, object, relation)
      assertSubjectDeclared(subject)
      const key = scopeKeyOf(partition)
      const { distinct, index } = distinctObjects(objects)
      // UN solo `now` para todo el lote (A-18): se fija aquí y `resolves` lo lee.
      const at = now()
      const answers = distinct.map((object) => resolves(subject, relation, object, key, () => at))
      return expandByPosition(index, answers)
    }
  }
  // **El deny en el doble** (lote D · D1): solo con `relationDenies: true` —el MÍNIMO no lo trae y el runner juzga
  // la cara `false` (D-28)—. Las MISMAS guardas que los drivers reales (F-05, opt-in en fase 'write', sin caducidad,
  // ni `*` ni `group`) y la MISMA regla (`cutPathAllows`/`decideFrom`).
  if (capabilities.relationDenies) {
    driver.deny = async (subject, relation, object, partition, options) => {
      assertRelationDeclared(config, object, relation)
      assertRelationDenyable(config, object, relation)
      assertDenyNoExpiry(options)
      assertDenySubject(subject)
      assertSubjectDeclared(subject)
      const partitionKey = scopeKeyOf(partition)
      const subjectKey = subjectKeyOf(subject)
      const stored = deniedRelationOf(relation)
      const existing = tuples.find(
        (t) =>
          t.partition === partitionKey && t.objectType === object.type && t.objectId === object.id && t.relation === stored && t.subjectKey === subjectKey
      )
      if (existing) {
        existing.expiresAt = null
        return
      }
      tuples.push({ partition: partitionKey, objectType: object.type, objectId: object.id, relation: stored, subject, subjectKey, expiresAt: null })
    }
    driver.removeDeny = async (subject, relation, object, partition, options) => {
      assertRelationDeclared(config, object, relation)
      assertDenyNoExpiry(options)
      assertSubjectDeclared(subject)
      const partitionKey = scopeKeyOf(partition)
      const subjectKey = subjectKeyOf(subject)
      const stored = deniedRelationOf(relation)
      for (let i = tuples.length - 1; i >= 0; i--) {
        const t = tuples[i]
        if (t.partition === partitionKey && t.objectType === object.type && t.objectId === object.id && t.relation === stored && t.subjectKey === subjectKey) {
          tuples.splice(i, 1)
        }
      }
    }
    driver.listDenies = async (relation, object, partition): Promise<RelationSubjectsPage> => {
      assertRelationDeclared(config, object, relation)
      const direct = directSubjects(scopeKeyOf(partition), object.type, object.id, deniedRelationOf(relation))
      return { subjects: dedupeSubjects(direct.map((t) => t.subject)) }
    }
    driver.decideMany = async (subject, relation, objects, partition): Promise<RelationDecision[]> => {
      assertCheckManyObjects(objects, 'decideMany')
      for (const object of objects) assertRelationDeclared(config, object, relation)
      assertSubjectDeclared(subject)
      const key = scopeKeyOf(partition)
      const { distinct, index } = distinctObjects(objects)
      const at = now()
      const principal = principalOf(subject, key, () => at)
      const answers = distinct.map((object) => {
        const { allowed, denied } = factsOn(principal, object, key, () => at)
        return decideFrom(config, object.type, relation, allowed, denied)
      })
      return index.map((i) => answers[i])
    }
  }
  if (capabilities.membersOfNative) {
    driver.membersOf = async (object, relation, partition): Promise<RelationSubjectsPage> => {
      assertRelationDeclared(config, object, relation)
      // Lote D: `membersOf` RESTA (corte de camino por candidato, como `database`).
      const key = scopeKeyOf(partition)
      return { subjects: collectMembers(object, relation, key).filter((s) => resolves(s, relation, object, key)) }
    }
  }
  if (capabilities.enumerateRelations) {
    driver.enumerateRelations = async (partition): Promise<RelationTuplePage> => {
      const partitionKey = scopeKeyOf(partition)
      // SIN filtrar la caducada (R-15): llega con su `expiresAt` para que el
      // destino de reconcile la cuente en `skipped`, no para que desaparezca.
      const out = tuples
        .filter((t) => t.partition === partitionKey)
        .map((t) => ({
          subject: t.subject,
          relation: t.relation,
          object: { type: t.objectType, id: t.objectId },
          partition,
          expiresAt: t.expiresAt,
        }))
      return { tuples: out }
    }
  }
  if (capabilities.injectableClock) {
    // La vista con otro reloj comparte las tuplas (como `Object.create(this)`
    // en los drivers reales). Solo existe si se declara: la cara `false` del
    // juez exige que un driver sin la capacidad NO traiga `withClock`.
    driver.withClock = (next: Clock) => buildRelationsDouble(options, tuples, next)
  }

  return driver
}

/** El reloj fijo del juez (el mismo patrón que `fixedClock` del runner de roles). */
function fixedClock(start: Date): { now: () => Date; set(at: Date): void } {
  let current = new Date(start.getTime())
  return {
    now: () => new Date(current.getTime()),
    set: (at) => {
      current = new Date(at.getTime())
    },
  }
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms))

/* ── Lote D · T1: la tabla de 64 estados con CORTE DE CAMINO (tester ronda 2, §2.2) ─────────────────────────── */

/** Las tres preguntas de T1, en el orden de la tabla (v / e / o). */
const T1_QUESTIONS = ['viewer', 'editor', 'owner'] as const
/** Orden de los subconjuntos de la tabla del tester: ∅, {v}, {e}, {e,v}, {o}, {o,v}, {o,e}, {o,e,v} (bits v=1, e=2, o=4). */
function t1Subset(mask: number): string[] {
  const out: string[] = []
  if (mask & 4) out.push('owner')
  if (mask & 2) out.push('editor')
  if (mask & 1) out.push('viewer')
  return out
}
/** La fila `row` (0..63) de T1: allows = subconjunto `row >> 3`, denies = subconjunto `row & 7`. */
function t1State(row: number): { allows: string[]; denies: string[] } {
  return { allows: t1Subset(row >> 3), denies: t1Subset(row & 7) }
}
/**
 * **La tabla LITERAL del tester** (`panel-tenencia-2-tester.md` §2.2, 64 filas × v/e/o), copiada byte a byte: el
 * oráculo de abajo tiene que reproducirla (si no, el caso es rojo antes de preguntar nada al driver), y el driver
 * tiene que reproducir las dos. NO se calcula con `cutPathAllows` del paquete: un mutante de la regla cambiaría a la
 * vez la respuesta y la expectativa.
 */
const T1_EXPECTED: readonly string[] = (
  'FFF FFF FFF FFF FFF FFF FFF FFF ' +
  'TFF FFF TFF FFF TFF FFF TFF FFF ' +
  'TTF FFF FFF FFF TTF FFF FFF FFF ' +
  'TTF FFF TFF FFF TTF FFF TFF FFF ' +
  'TTT FFF FFF FFF FFF FFF FFF FFF ' +
  'TTT FFF TFF FFF TFF FFF TFF FFF ' +
  'TTT FFF FFF FFF TTF FFF FFF FFF ' +
  'TTT FFF TFF FFF TTF FFF TFF FFF'
).split(' ')
/** Las 37 filas PAR del tester (alguna semántica plausible en UN solo driver da otra respuesta): las del BRIDGE. */
const T1_PAR: ReadonlySet<number> = new Set([
  11, 13, 15, 18, 19, 21, 22, 23, 26, 27, 29, 30, 31, 34, 35, 36, 37, 38, 39, 42, 43, 44, 45, 46, 47, 50, 51, 52, 53,
  54, 55, 58, 59, 60, 61, 62, 63,
])
/** El retículo del contrato, escrito a mano (owner ⇒ editor ⇒ viewer). */
const T1_DOWN: Record<string, string[]> = { viewer: ['viewer', 'editor', 'owner'], editor: ['editor', 'owner'], owner: ['owner'] }
const T1_UP: Record<string, string[]> = { owner: ['owner', 'editor', 'viewer'], editor: ['editor', 'viewer'], viewer: ['viewer'] }
/** CORTE (D5), la fórmula del tester sobre el retículo a mano: ∃ T ∈ A ∩ down*(Q) con up*(T) ∩ D = ∅. */
function t1Oracle(allows: readonly string[], denies: readonly string[], q: string): boolean {
  return T1_DOWN[q].some((t) => allows.includes(t) && T1_UP[t].every((above) => !denies.includes(above)))
}
/** D9 (AMPLIO): ¿algún deny en up*(down*(Q))? */
function t1DeniedAbove(denies: readonly string[], q: string): boolean {
  return T1_DOWN[q].some((t) => T1_UP[t].some((above) => denies.includes(above)))
}
/** Las seis filas con NOMBRE (tester §2.2): cada una se lee sola cuando falla. */
const T1_NAMED: ReadonlyArray<readonly [string, number, string]> = [
  ['D-06 · un deny en viewer bloquea al owner: F/F/F', 34, 'FFF'],
  ['D-07 · un deny en editor anula el grant de owner ENTERO: F/F/F (la fila del juez: mata a las siete semánticas)', 35, 'FFF'],
  ['D-08 · …salvo un viewer directo: owner + viewer + deny(editor) ⇒ T/F/F', 43, 'TFF'],
  ['D-09 · deny en owner sin otro grant: F/F/F (no sobrevive ni el viewer derivado)', 37, 'FFF'],
  ['D-10 · owner + viewer + deny(owner) ⇒ T/F/F', 45, 'TFF'],
  ['D-11 · un deny en una relación MÁS FUERTE no toca un grant más débil: viewer + deny(editor) ⇒ T/F/F', 11, 'TFF'],
]

/* ── El runner ───────────────────────────────────────────────────────────── */

function holder(): SubjectRef {
  return { type: 'user', uuid: uuidv7() }
}
function docId(): string {
  return uuidv7()
}
function partition(): ScopeRef {
  return { type: 'unit', uuid: uuidv7() }
}

/**
 * Un driver que cuenta las llamadas a `relate`/`unrelate` (para probar «no tocó
 * el driver»). Es un `Proxy` —no un `{...driver}`— para no perder los métodos
 * de PROTOTIPO de un driver de CLASE (el `database` de 4-3): el spread solo
 * copia propiedades propias, así que un `check`/`membersOf` en el prototipo
 * desaparecía. Los métodos delegados se enlazan al `target` para que sus
 * campos privados (`#…`) sigan funcionando a través del proxy.
 */
function spy(driver: RelationsDriver): { driver: RelationsDriver; writes: () => number; calls: () => number } {
  let writes = 0
  let calls = 0
  const wrapped = new Proxy(driver, {
    get(target, prop, receiver) {
      // Un método OPCIONAL que el driver no trae se queda ausente (el manager decide por `typeof`: `checkMany`
      // compone, `decideMany`/`deny` son 500): envolverlo lo haría aparecer.
      if (typeof (target as any)[prop] !== 'function') return Reflect.get(target, prop, receiver)
      // L-2: las CUATRO escrituras (también `purge*`, que reciben `{ transaction }`).
      // Lote D: también `deny`/`removeDeny` (escrituras del deny).
      if (prop === 'relate' || prop === 'unrelate' || prop === 'purgeObject' || prop === 'purgeSubject' || prop === 'deny' || prop === 'removeDeny') {
        return async (...args: unknown[]) => {
          writes++
          calls++
          return (target as any)[prop](...args)
        }
      }
      // alpha.3 (cierre) · las TRES lecturas también cuentan: F-05 tiene que
      // cortarlas ANTES del driver («cero llamadas» = ni una lectura).
      // Lote D: y `checkMany`/`decideMany`/`listDenies`/`membersOf` (las lecturas del lote, «cero llamadas» = ninguna).
      if (
        prop === 'check' ||
        prop === 'listObjects' ||
        prop === 'listSubjects' ||
        prop === 'checkMany' ||
        prop === 'decideMany' ||
        prop === 'listDenies' ||
        prop === 'membersOf'
      ) {
        return async (...args: unknown[]) => {
          calls++
          return (target as any)[prop](...args)
        }
      }
      const value = Reflect.get(target, prop, receiver)
      return typeof value === 'function' ? value.bind(target) : value
    },
  })
  return { driver: wrapped, writes: () => writes, calls: () => calls }
}

export function runRelationsDriverContract(harness: RelationsDriverContractHarness) {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return registerRelationsDriverContract(harness, {
    group: (title, define) => japaTest.group(title, define as any),
    test: (title, fn) => japaTest(title, fn as any),
  })
}

/**
 * El MOTOR del runner (registro de casos), separado para que el propio paquete
 * pueda contar los casos (`relations_harness.spec.ts`). Devuelve el nº de
 * casos registrados y las capacidades cubiertas.
 */
export function registerRelationsDriverContract(
  harness: RelationsDriverContractHarness,
  api: { group: ContractTestApi['group']; test: ContractTestApi['test'] }
): { registered: number; covered: Set<keyof RelationsDriverCapabilities> } {
  // **«Una capacidad `true` sin su soporte se rechaza»** (paridad con el guard
  // de roles, `contract_harness.spec.ts`): `listObjectsTruncation: true` no se
  // puede JUZGAR sin conocer el tope del backend —el caso `whenTrue` siembra
  // `tope + 2` objetos y exige que la página trunque a `tope`—, así que sin
  // `limits.listMaxResults` es un skip disfrazado y se rechaza AL REGISTRAR, no
  // a mitad del caso. (Las demás capacidades sí tienen su whenTrue observable
  // con el doble; una capacidad `true` cuyo DRIVER no traiga el método —una
  // mentira— la corta el `RelationsManager` con 500, nunca un skip.)
  if (harness.capabilities.listObjectsTruncation && harness.limits?.listMaxResults === undefined) {
    throw new Error(
      `[contrato ${harness.name}] declara 'listObjectsTruncation: true' sin 'limits.listMaxResults': ` +
        `sin el tope del backend no hay forma de observar el truncado (un skip disfrazado).`
    )
  }

  const covered = new Set<keyof RelationsDriverCapabilities>()
  let registered = 0

  const state: {
    manager: RelationsManager
    base: RelationsDriver
    writes: () => number
    calls: () => number
    events: RelationWriteEvent[]
  } = {} as any

  async function freshManager(options?: ConstructorParameters<typeof RelationsManager>[2]) {
    const base = await harness.makeDriver(contractRelationsConfig())
    const s = spy(base)
    // L-2: el manager nombra al driver en las dos puertas de `{ transaction }`
    // como lo haría el provider (la clave en `relations.drivers`): aquí, el harness.
    return {
      manager: new RelationsManager(s.driver, contractRelationsConfig(), { driverName: harness.name, ...options }),
      writes: s.writes,
      calls: s.calls,
      base,
    }
  }

  api.group(`relations contract [${harness.name}]`, (group) => {
    group.each.setup(async () => {
      // alpha.3: el manager de cada caso captura `onRelationWrite` — el par
      // `transactionalWrites` juzga también el EVENTO (la otra cara observable
      // de la capacidad) y R-07/R-08 juzgan el evento de la purga.
      state.events = []
      const f = await freshManager({ onRelationWrite: (e) => void state.events.push(e) })
      state.manager = f.manager
      state.base = f.base
      state.writes = f.writes
      state.calls = f.calls
    })

    const test = (title: string, fn: (ctx: { assert: Assert }) => Promise<void>) => {
      registered++
      return api.test(title, fn)
    }

    function caseFor(
      capability: keyof RelationsDriverCapabilities,
      pair: { whenTrue: () => void; whenFalse: () => void }
    ) {
      // MÁS ESTRICTO que el guard de roles: las DOS caras tienen que existir
      // en el código del runner, o es un skip disfrazado (exigencia del tester).
      if (typeof pair.whenTrue !== 'function' || typeof pair.whenFalse !== 'function') {
        throw new Error(
          `[contrato ${harness.name}] la capacidad '${capability}' no declara sus dos caras ` +
            `(whenTrue Y whenFalse): una cara ausente es un skip disfrazado.`
        )
      }
      const before = registered
      ;(harness.capabilities[capability] ? pair.whenTrue : pair.whenFalse)()
      if (registered > before) covered.add(capability)
    }

    /* ── R-01: denegación por defecto y concesión directa ── */
    test('R-01 · relate concede; sin relate deniega (denegación por defecto)', async ({ assert }) => {
      const u = holder()
      const doc: RelObject = { type: 'document', id: docId() }
      const p = partition()
      assert.isFalse(await state.manager.check(u, 'viewer', doc, p))
      await state.manager.relate(u, 'viewer', doc, p)
      assert.isTrue(await state.manager.check(u, 'viewer', doc, p))
    })

    /* ── R-02: includes sin `from` (editor ⊆ viewer) ── */
    test('R-02 · includes: relate(editor) ⇒ check(viewer) true; el inverso NO', async ({ assert }) => {
      const u = holder()
      const doc: RelObject = { type: 'document', id: docId() }
      const p = partition()
      await state.manager.relate(u, 'editor', doc, p)
      assert.isTrue(await state.manager.check(u, 'viewer', doc, p))
      const v = holder()
      await state.manager.relate(v, 'viewer', doc, p)
      assert.isFalse(await state.manager.check(v, 'editor', doc, p))
    })

    /* ── R-03/R-04: usersets, grupos anidados ── */
    test('R-03/R-04 · userset: relate(group#member, viewer) + membresía anidada ⇒ check true', async ({
      assert,
    }) => {
      const u = holder()
      const doc: RelObject = { type: 'document', id: docId() }
      const g1: RelObject = { type: 'group', id: docId() }
      const g2: RelObject = { type: 'group', id: docId() }
      const p = partition()
      // g1 miembro de g2; u miembro de g1; g2#member es viewer del doc.
      await state.manager.relate(u, 'member', g1, p)
      await state.manager.relate({ object: g1, relation: 'member' }, 'member', g2, p)
      await state.manager.relate({ object: g2, relation: 'member' }, 'viewer', doc, p)
      assert.isTrue(await state.manager.check(u, 'viewer', doc, p))
    })

    /* ── R-05: la partición aísla ── */
    test('R-05 · partición: relate en A no concede en B', async ({ assert }) => {
      const u = holder()
      const doc: RelObject = { type: 'document', id: docId() }
      const a = partition()
      const b = partition()
      await state.manager.relate(u, 'viewer', doc, a)
      assert.isTrue(await state.manager.check(u, 'viewer', doc, a))
      assert.isFalse(await state.manager.check(u, 'viewer', doc, b))
    })

    /* ── R-06: idempotencia ── */
    test('R-06 · unrelate retira; re-relate no duplica; re-unrelate no-op', async ({ assert }) => {
      const u = holder()
      const doc: RelObject = { type: 'document', id: docId() }
      const p = partition()
      await state.manager.relate(u, 'viewer', doc, p)
      await state.manager.relate(u, 'viewer', doc, p) // idempotente
      const before = await state.manager.listSubjects('viewer', doc, p)
      assert.lengthOf(before.subjects, 1)
      await state.manager.unrelate(u, 'viewer', doc, p)
      assert.isFalse(await state.manager.check(u, 'viewer', doc, p))
      await state.manager.unrelate(u, 'viewer', doc, p) // no-op seguro
    })

    /* ── R-07/R-08: purga con demostración de cero ── */
    test('R-07/R-08 · purgeObject y purgeSubject retiran sus tuplas', async ({ assert }) => {
      const u = holder()
      const doc: RelObject = { type: 'document', id: docId() }
      const p = partition()
      await state.manager.relate(u, 'viewer', doc, p)
      await state.manager.purgeObject(doc, p)
      assert.isFalse(await state.manager.check(u, 'viewer', doc, p))
      const doc2: RelObject = { type: 'document', id: docId() }
      await state.manager.relate(u, 'owner', doc2, p)
      await state.manager.purgeSubject(u, p)
      assert.isFalse(await state.manager.check(u, 'owner', doc2, p))
    })

    /* ── R-09: listObjects/listSubjects directos ── */
    test('R-09 · listObjects devuelve los objetos del sujeto (directos + derivados)', async ({ assert }) => {
      const u = holder()
      const d1: RelObject = { type: 'document', id: docId() }
      const d2: RelObject = { type: 'document', id: docId() }
      const p = partition()
      await state.manager.relate(u, 'editor', d1, p)
      await state.manager.relate(u, 'viewer', d2, p)
      const page = await state.manager.listObjects(u, 'viewer', 'document', p)
      assert.sameMembers(page.objects.map((o) => o.id).sort(), [d1.id, d2.id].sort())
    })

    /* ── R-12: identidad mal formada ⇒ 422 ── */
    test('R-12 · partición mal formada ⇒ 422 con code', async ({ assert }) => {
      const u = holder()
      const doc: RelObject = { type: 'document', id: docId() }
      let caught: any
      try {
        await state.manager.relate(u, 'viewer', doc, { type: 'unit', uuid: 'NO-ES-UUID' } as any)
        assert.fail('debería haber lanzado')
      } catch (error) {
        caught = error
      }
      assert.equal(caught.status, 422)
      assert.equal(caught.code, 'E_AUTHZ_INVALID_IDENTITY')
      assert.equal(state.writes(), 0)
    })

    /* ── F-05 · el cierre del 🔴: tipo no declarado (role_binding) ⇒ 422 ANTES del driver ── */
    test('F-05 · relate(evil, assignee, role_binding, S) ⇒ 422 E_AUTHZ_RELATION_TYPE_UNKNOWN, driver intacto', async ({
      assert,
    }) => {
      const evil = holder()
      const roleUuid = uuidv7()
      const S = partition()
      let caught: any
      try {
        await state.manager.relate(evil, 'assignee', { type: 'role_binding', id: roleUuid }, S)
        assert.fail('debería haber lanzado')
      } catch (error) {
        caught = error
      }
      assert.equal(caught.status, 422)
      assert.equal(caught.code, 'E_AUTHZ_RELATION_TYPE_UNKNOWN')
      // El cierre estructural: el driver NUNCA se llamó, así que no pudo
      // componer el id del binding ni escribir la tupla `assignee`.
      assert.equal(state.writes(), 0)
    })

    test('F-05 · relate con una relación no declarada del tipo ⇒ 422 E_AUTHZ_RELATION_UNKNOWN, driver intacto', async ({
      assert,
    }) => {
      const u = holder()
      const doc: RelObject = { type: 'document', id: docId() }
      const p = partition()
      let caught: any
      try {
        await state.manager.relate(u, 'assignee', doc, p) // 'assignee' no es relación de 'document'
        assert.fail('debería haber lanzado')
      } catch (error) {
        caught = error
      }
      assert.equal(caught.status, 422)
      assert.equal(caught.code, 'E_AUTHZ_RELATION_UNKNOWN')
      assert.equal(state.writes(), 0)
    })

    /**
     * **F-05 en las PURGAS y las LECTURAS** (2.4.0-alpha.3, cierre del 🔴 1 /
     * 🟠 2 del auditor). Hasta el cierre F-05 solo cubría `relate`/`unrelate`,
     * y en el store COMPARTIDO de `openfga` `purgeObject({ type:
     * 'role_binding', id: R }, S)` borraba el binding REAL de un rol
     * (`authorize` de `true` a `false`, evento de auditoría limpio) y
     * `listSubjects('assignee', role_binding)` enumeraba sus asignados sin
     * catálogo ni `within`. Un driver de terceros que no lo corte por el
     * manager NO pasa: cero llamadas al driver (ni escrituras ni lecturas),
     * cero eventos. Una purga o un `listObjects` validan el TIPO; `check`/
     * `listSubjects` el par; `purgeSubject` el userset del sujeto.
     */
    test('F-05 · purgeObject/purgeSubject(userset)/check/listObjects/listSubjects/membersOf contra un tipo NO declarado (role_binding) ⇒ 422 E_AUTHZ_RELATION_TYPE_UNKNOWN con CERO llamadas al driver y CERO eventos; check/listObjects/listSubjects/membersOf con una relación no declarada, y relate/unrelate/check/listSubjects/listObjects/membersOf SIN relación (undefined) ⇒ 422 E_AUTHZ_RELATION_UNKNOWN', async ({
      assert,
    }) => {
      const u = holder()
      const roleUuid = uuidv7()
      const S = partition()
      const binding: RelObject = { type: 'role_binding', id: roleUuid }
      const attempts: Array<[string, () => Promise<unknown>]> = [
        ['purgeObject', () => state.manager.purgeObject(binding, S)],
        [
          'purgeSubject(userset)',
          () => state.manager.purgeSubject({ object: binding, relation: 'role' }, S),
        ],
        ['check', () => state.manager.check(u, 'assignee', binding, S)],
        ['listObjects', () => state.manager.listObjects(u, 'assignee', 'role_binding', S)],
        ['listSubjects', () => state.manager.listSubjects('assignee', binding, S)],
        // Cierre-2 · 🟡 3: `membersOf` es la octava operación (F-05 va ANTES de la capacidad).
        ['membersOf', () => state.manager.membersOf(binding, 'assignee', S)],
      ]
      for (const [label, run] of attempts) {
        const caught = await run().then(() => null, (e) => e)
        assert.isNotNull(caught, `ROJO (${label}): entró contra un tipo NO declarado (role_binding)`)
        assert.equal(caught.status, 422, `${label}: ${caught.message}`)
        assert.equal(caught.code, 'E_AUTHZ_RELATION_TYPE_UNKNOWN', label)
      }
      // Una relación no declarada del tipo declarado, en las lecturas que la nombran.
      const doc: RelObject = { type: 'document', id: docId() }
      for (const [label, run] of [
        ['check', () => state.manager.check(u, 'assignee', doc, S)],
        ['listObjects', () => state.manager.listObjects(u, 'assignee', 'document', S)],
        ['listSubjects', () => state.manager.listSubjects('assignee', doc, S)],
        ['membersOf', () => state.manager.membersOf(doc, 'assignee', S)],
      ] as Array<[string, () => Promise<unknown>]>) {
        const caught = await run().then(() => null, (e) => e)
        assert.equal(caught?.status, 422, `${label}: ${caught?.message}`)
        assert.equal(caught?.code, 'E_AUTHZ_RELATION_UNKNOWN', label)
      }
      // Cierre-2 · 🟠 1: SIN relación (`request.input('relation')` ausente) es
      // 422, no una tupla escrita, no un 503 del backend y no la unión de
      // `listSubjects`. Un driver de terceros lo hereda del manager.
      for (const [label, run] of [
        ['relate', () => state.manager.relate(u, undefined as any, doc, S)],
        ['unrelate', () => state.manager.unrelate(u, undefined as any, doc, S)],
        ['check', () => state.manager.check(u, undefined as any, doc, S)],
        ['listSubjects', () => state.manager.listSubjects(undefined as any, doc, S)],
        ['listObjects', () => state.manager.listObjects(u, undefined as any, 'document', S)],
        ['membersOf', () => state.manager.membersOf(doc, undefined as any, S)],
      ] as Array<[string, () => Promise<unknown>]>) {
        const caught = await run().then(() => null, (e) => e)
        assert.isNotNull(caught, `ROJO (${label}): ENTRÓ sin relación`)
        assert.equal(caught.status, 422, `${label}: ${caught.message}`)
        assert.equal(caught.code, 'E_AUTHZ_RELATION_UNKNOWN', label)
      }
      assert.equal(state.calls(), 0, 'CERO llamadas al driver: ni una escritura ni una lectura')
      assert.lengthOf(state.events, 0, 'CERO eventos: no hubo purga que auditar')
      // CONTROL: lo declarado sigue entrando por los mismos cinco caminos.
      await state.manager.relate(u, 'viewer', doc, S)
      assert.isTrue(await state.manager.check(u, 'viewer', doc, S))
      assert.lengthOf((await state.manager.listObjects(u, 'viewer', 'document', S)).objects, 1)
      assert.lengthOf((await state.manager.listSubjects('viewer', doc, S)).subjects, 1)
      await state.manager.purgeObject(doc, S)
      await state.manager.purgeSubject({ object: { type: 'group', id: docId() }, relation: 'member' }, S)
      assert.isFalse(await state.manager.check(u, 'viewer', doc, S))
    })

    /* ── R-13: assertWrite PURO + actor en onRelationWrite ── */
    test('R-13 · assertWrite rechaza ⇒ nada toca el driver; actor viaja en onRelationWrite', async ({
      assert,
    }) => {
      const events: any[] = []
      const rejected = await freshManager({
        assertWrite: (ref) => {
          if (ref.relation === 'owner') throw new Error('no se permite conceder owner')
        },
        onRelationWrite: (e) => events.push(e),
      })
      const u = holder()
      const doc: RelObject = { type: 'document', id: docId() }
      const p = partition()
      const actor = holder()
      let threw = false
      try {
        await rejected.manager.relate(u, 'owner', doc, p, { actor })
      } catch {
        threw = true
      }
      assert.isTrue(threw)
      assert.equal(rejected.writes(), 0) // assertWrite cortó ANTES del driver
      assert.lengthOf(events, 0)
      // Una escritura permitida sí llega y notifica con el actor.
      await rejected.manager.relate(u, 'viewer', doc, p, { actor })
      assert.equal(rejected.writes(), 1)
      assert.lengthOf(events, 1)
      assert.deepEqual(events[0].actor, actor)
      assert.equal(events[0].operation, 'relate')
    })

    /* ── R-17 · las purgas notifican (2.4.0-alpha.3 · E7) ── */
    test('R-17 · purgeObject/purgeSubject notifican UN evento por llamada con su forma (sin relation; purgeObject sin subject, purgeSubject sin object) y el actor, también cuando no borran nada; requireActor las alcanza (422 sin actor, cero llamadas, cero eventos)', async ({
      assert,
    }) => {
      const u = holder()
      const v = holder()
      const doc: RelObject = { type: 'document', id: docId() }
      const doc2: RelObject = { type: 'document', id: docId() }
      const p = partition()
      const actor = holder()
      await state.manager.relate(u, 'viewer', doc, p)
      await state.manager.relate(v, 'editor', doc, p)
      await state.manager.relate(u, 'owner', doc2, p)
      const before = state.events.length
      // purgeObject: dos tuplas borradas, UN evento, con la forma decidida.
      await state.manager.purgeObject(doc, p, { actor })
      assert.lengthOf(state.events, before + 1, 'ROJO: la purga no notifica exactamente UN evento por llamada')
      const purgedObject = state.events[before]
      assert.equal(purgedObject.operation, 'purgeObject')
      assert.deepEqual(purgedObject.object, doc)
      assert.deepEqual(purgedObject.partition, p)
      assert.deepEqual(purgedObject.actor, actor)
      assert.notProperty(purgedObject, 'subject')
      assert.notProperty(purgedObject, 'relation')
      assert.isFalse(await state.manager.check(u, 'viewer', doc, p))
      // purgeSubject: UN evento, sin object.
      await state.manager.purgeSubject(u, p, { actor })
      assert.lengthOf(state.events, before + 2)
      const purgedSubject = state.events[before + 1]
      assert.equal(purgedSubject.operation, 'purgeSubject')
      assert.deepEqual(purgedSubject.subject, u)
      assert.deepEqual(purgedSubject.partition, p)
      assert.deepEqual(purgedSubject.actor, actor)
      assert.notProperty(purgedSubject, 'object')
      assert.notProperty(purgedSubject, 'relation')
      assert.isFalse(await state.manager.check(u, 'owner', doc2, p))
      // Una purga que no borra nada notifica igual (sin actor, el evento no lo inventa).
      await state.manager.purgeObject({ type: 'document', id: docId() }, p)
      assert.lengthOf(state.events, before + 3)
      assert.equal(state.events[before + 2].operation, 'purgeObject')
      assert.notProperty(state.events[before + 2], 'actor')

      // requireActor alcanza a las purgas (D-3): 422 ANTES del driver.
      const strictEvents: RelationWriteEvent[] = []
      const strict = await freshManager({ requireActor: true, onRelationWrite: (e) => void strictEvents.push(e) })
      for (const [operation, run] of [
        ['purgeObject', () => strict.manager.purgeObject(doc, p)],
        ['purgeSubject', () => strict.manager.purgeSubject(u, p)],
      ] as const) {
        let caught: any
        try {
          await run()
          assert.fail(`${operation}: requireActor: true tenía que exigir actor a la purga`)
        } catch (error) {
          caught = error
        }
        assert.equal(caught.status, 422, `${operation}: ${caught.message}`)
        assert.equal(caught.code, 'E_AUTHZ_ACTOR_REQUIRED', operation)
      }
      assert.equal(strict.writes(), 0, 'cero llamadas al driver')
      assert.lengthOf(strictEvents, 0)
      await strict.manager.purgeObject(doc, p, { actor })
      assert.equal(strict.writes(), 1)
      assert.lengthOf(strictEvents, 1)
      assert.deepEqual(strictEvents[0].actor, actor)
    })

    /* ── P4 · checkMany (plan 2.5 · lote A; A-9…A-14 del tester) ────────── */

    /**
     * **`checkMany` ≡ N `check`, posición a posición** (A-9, P4-1): allow directo,
     * includes (`editor` ⊆ `viewer`), userset ANIDADO, caducado en el pasado y
     * «nada». Y el orden de la RESPUESTA es el de la PETICIÓN (A-10, P4-2): los
     * ids del lote van en orden inverso al de escritura y el patrón esperado
     * es F,T,F,T — un driver que mapease por orden de fila de SQL o por el
     * orden en que llegan los resultados del backend se pone rojo.
     */
    test('P4-1/P4-2 · checkMany ≡ N check posición a posición (allow, includes, userset anidado, caducado, nada) y responde en el ORDEN de la petición (F,T,F,T con ids en orden inverso)', async ({
      assert,
    }) => {
      const u = holder()
      const p = partition()
      const direct: RelObject = { type: 'document', id: docId() }
      const viaInclude: RelObject = { type: 'document', id: docId() }
      const viaNested: RelObject = { type: 'document', id: docId() }
      const expired: RelObject = { type: 'document', id: docId() }
      const nothing: RelObject = { type: 'document', id: docId() }
      const g1: RelObject = { type: 'group', id: docId() }
      const g2: RelObject = { type: 'group', id: docId() }
      await state.manager.relate(u, 'viewer', direct, p)
      await state.manager.relate(u, 'editor', viaInclude, p)
      await state.manager.relate(u, 'member', g1, p)
      await state.manager.relate({ object: g1, relation: 'member' }, 'member', g2, p)
      await state.manager.relate({ object: g2, relation: 'member' }, 'viewer', viaNested, p)
      await state.manager.relate(u, 'viewer', expired, p, { expiresAt: new Date(Date.now() - 60_000) })
      const objects = [direct, viaInclude, viaNested, expired, nothing]
      const one: boolean[] = []
      for (const object of objects) one.push(await state.manager.check(u, 'viewer', object, p))
      assert.deepEqual(one, [true, true, true, false, false], 'precondición: N check')
      assert.deepEqual(await state.manager.checkMany(u, 'viewer', objects, p), one, 'checkMany ≡ N check, posición a posición')
      // P4-2: ids en orden INVERSO al de escritura y respuesta F,T,F,T.
      const a: RelObject = { type: 'document', id: docId() }
      const b: RelObject = { type: 'document', id: docId() }
      const c: RelObject = { type: 'document', id: docId() }
      const d: RelObject = { type: 'document', id: docId() }
      await state.manager.relate(u, 'viewer', c, p)
      await state.manager.relate(u, 'viewer', a, p)
      const sorted = [a, b, c, d].sort((x, y) => (x.id < y.id ? -1 : 1))
      // [d', c', b', a'] con T solo en los que se escribieron (c y a): el patrón
      // depende del orden de ids, así que se calcula con N check y se exige igual.
      const request = [sorted[3], sorted[2], sorted[1], sorted[0]]
      const expected: boolean[] = []
      for (const object of request) expected.push(await state.manager.check(u, 'viewer', object, p))
      assert.sameMembers(expected, [true, true, false, false])
      assert.deepEqual(await state.manager.checkMany(u, 'viewer', request, p), expected, 'el orden de la respuesta es el de la petición')
      assert.deepEqual(await state.manager.checkMany(u, 'viewer', [...request].reverse(), p), [...expected].reverse())
    })

    /** A-11 (P4-4a): duplicados permitidos y respondidos por POSICIÓN. */
    test('P4-4a · checkMany con duplicados: [a, a, b] ⇒ [x, x, y] (por posición, sin deduplicar la respuesta)', async ({ assert }) => {
      const u = holder()
      const p = partition()
      const a: RelObject = { type: 'document', id: docId() }
      const b: RelObject = { type: 'document', id: docId() }
      await state.manager.relate(u, 'viewer', a, p)
      assert.deepEqual(await state.manager.checkMany(u, 'viewer', [a, a, b], p), [true, true, false])
      assert.deepEqual(await state.manager.checkMany(u, 'viewer', [b, a, b, a], p), [false, true, false, true])
    })

    /** A-12 (P4-5): el tope 50 responde; 51 y [] son 422 con CERO llamadas al driver. */
    test(`P4-5 · checkMany con ${RELATIONS_CHECK_MANY_MAX} objetos responde; ${RELATIONS_CHECK_MANY_MAX + 1} ⇒ 422 E_AUTHZ_CHECK_MANY_BATCH y [] ⇒ 422, ambos con CERO llamadas al driver`, async ({
      assert,
    }) => {
      const u = holder()
      const p = partition()
      const fifty: RelObject[] = []
      for (let i = 0; i < RELATIONS_CHECK_MANY_MAX; i++) fifty.push({ type: 'document', id: docId() })
      await state.manager.relate(u, 'viewer', fifty[RELATIONS_CHECK_MANY_MAX - 1], p)
      const answers = await state.manager.checkMany(u, 'viewer', fifty, p)
      assert.lengthOf(answers, RELATIONS_CHECK_MANY_MAX)
      assert.isTrue(answers[RELATIONS_CHECK_MANY_MAX - 1])
      assert.isFalse(answers[0])
      const before = state.calls()
      for (const [label, objects] of [
        ['51', [...fifty, { type: 'document', id: docId() }]],
        ['[]', []],
      ] as Array<[string, RelObject[]]>) {
        const caught = await state.manager.checkMany(u, 'viewer', objects, p).then(() => null, (e) => e)
        assert.isNotNull(caught, `ROJO (${label}): checkMany respondió en vez de rechazar`)
        assert.equal(caught.status, 422, `${label}: ${caught.message}`)
        assert.equal(caught.code, 'E_AUTHZ_CHECK_MANY_BATCH', label)
      }
      assert.equal(state.calls(), before, 'CERO llamadas al driver: el tope y el lote vacío se juzgan antes')
    })

    /** A-13 (P4-6): F-05 por ÍTEM — un `role_binding` en la ÚLTIMA posición es 422 con cero llamadas. */
    test('P4-6 · checkMany · F-05 por ítem: un role_binding en la posición 21 de 21 ⇒ 422 E_AUTHZ_RELATION_TYPE_UNKNOWN con CERO llamadas al driver; un id inválido en la última posición ⇒ 422 E_AUTHZ_INVALID_IDENTITY', async ({
      assert,
    }) => {
      const u = holder()
      const p = partition()
      const twenty: RelObject[] = []
      for (let i = 0; i < 20; i++) twenty.push({ type: 'document', id: docId() })
      const before = state.calls()
      const evil = await state.manager.checkMany(u, 'viewer', [...twenty, { type: 'role_binding', id: docId() }], p).then(() => null, (e) => e)
      assert.isNotNull(evil, 'ROJO: un role_binding en la posición 21 entró')
      assert.equal(evil.status, 422, String(evil?.message))
      assert.equal(evil.code, 'E_AUTHZ_RELATION_TYPE_UNKNOWN')
      const bad = await state.manager.checkMany(u, 'viewer', [...twenty, { type: 'document', id: 'A#B' }], p).then(() => null, (e) => e)
      assert.equal(bad?.status, 422, String(bad?.message))
      assert.equal(bad?.code, 'E_AUTHZ_INVALID_IDENTITY')
      const undeclared = await state.manager.checkMany(u, 'assignee', twenty, p).then(() => null, (e) => e)
      assert.equal(undeclared?.code, 'E_AUTHZ_RELATION_UNKNOWN', 'la relación no declarada también es 422')
      assert.equal(state.calls(), before, 'CERO llamadas al driver')
    })

    /** A-14 (P4-7, H10): tipos MEZCLADOS con la misma relación responden por ítem (`document` y `workspace`). */
    test('P4-7 · checkMany con tipos mezclados (document y workspace) y la misma relación responde por ítem, con los includes de CADA tipo', async ({
      assert,
    }) => {
      const u = holder()
      const p = partition()
      const doc: RelObject = { type: 'document', id: docId() }
      const ws: RelObject = { type: 'workspace', id: docId() }
      const otherWs: RelObject = { type: 'workspace', id: docId() }
      const otherDoc: RelObject = { type: 'document', id: docId() }
      await state.manager.relate(u, 'viewer', doc, p)
      await state.manager.relate(u, 'editor', ws, p) // includes del tipo workspace: editor ⊆ viewer
      // El mismo id en los DOS tipos: el tipo forma parte de la identidad (no se cruzan).
      const twin: RelObject = { type: 'workspace', id: doc.id }
      assert.deepEqual(
        await state.manager.checkMany(u, 'viewer', [doc, ws, otherWs, otherDoc, twin, ws, doc], p),
        [true, true, false, false, false, true, true]
      )
      assert.deepEqual(await state.manager.checkMany(u, 'owner', [doc, ws], p), [false, false], 'owner no se deriva de editor/viewer')
    })

    /* ── D13 · el DRIVER llamado directamente también corta F-05 (plan 2.5 · lote A) ── */

    /**
     * **F-05 vive también en el driver** (D13, decisión del dueño 2026-10-14;
     * tester H8): hasta el lote A el runner solo exigía el corte en el MANAGER,
     * así que un driver de terceros podía no re-validar y pasar el contrato —
     * y por `manager.driver()` o por `reconcileRelations` (que escribe por el
     * driver del destino) componer el id de un binding real en un store
     * compartido. Ahora se llama al driver del harness EN DIRECTO, sin manager:
     * las ocho operaciones (y `checkMany`, y `membersOf` cuando el driver lo
     * trae nativo: 🟡 A7) rechazan un tipo no declarado con el MISMO 422 que
     * el manager, y el `checkMany` directo corta el tope y el lote vacío (⚪ A12). **Ruptura declarada** para un harness de
     * terceros que sembrara tipos no declarados por el driver.
     */
    test('D13 · F-05 en el DRIVER llamado directamente (sin manager): relate/unrelate/check/checkMany/listObjects/listSubjects/purgeObject/purgeSubject(userset) —y membersOf si es nativo (A7)— contra role_binding ⇒ 422 E_AUTHZ_RELATION_TYPE_UNKNOWN, una relación no declarada ⇒ 422 E_AUTHZ_RELATION_UNKNOWN, y checkMany directo corta 51 y [] (A12)', async ({
      assert,
    }) => {
      const driver = state.base
      const u = holder()
      const S = partition()
      const binding: RelObject = { type: 'role_binding', id: docId() }
      const doc: RelObject = { type: 'document', id: docId() }
      const typeAttempts: Array<[string, () => Promise<unknown>]> = [
        ['relate', () => driver.relate(u, 'assignee', binding, S)],
        ['unrelate', () => driver.unrelate(u, 'assignee', binding, S)],
        ['check', () => driver.check(u, 'assignee', binding, S)],
        // `viewer` está declarada para `doc` ([0]): lo ÚNICO que falla es el role_binding de [1] (F-05 por ítem).
        ['checkMany', () => (typeof driver.checkMany === 'function' ? driver.checkMany(u, 'viewer', [doc, binding], S) : driver.check(u, 'assignee', binding, S))],
        ['listObjects', () => driver.listObjects(u, 'assignee', 'role_binding', S)],
        ['listSubjects', () => driver.listSubjects('assignee', binding, S)],
        ['purgeObject', () => driver.purgeObject(binding, S)],
        ['purgeSubject(userset)', () => driver.purgeSubject({ object: binding, relation: 'role' }, S)],
        // 🟡 A7 (auditor del lote A): la NOVENA operación, cuando el driver la trae nativa — un `membersOf`
        // sin F-05 enumera los asignados de un rol del store compartido (la clase del 🟠 2 de alpha.3).
        ...(harness.capabilities.membersOfNative && typeof driver.membersOf === 'function'
          ? ([['membersOf', () => driver.membersOf!(binding, 'assignee', S)]] as Array<[string, () => Promise<unknown>]>)
          : []),
      ]
      assert.equal(
        typeAttempts.length,
        harness.capabilities.membersOfNative && typeof driver.membersOf === 'function' ? 9 : 8,
        'las nueve operaciones del puerto (ocho sin membersOf nativo)'
      )
      for (const [label, run] of typeAttempts) {
        const caught = await run().then(() => null, (e) => e)
        assert.isNotNull(caught, `ROJO (D13 · driver.${label}): el driver ENTRÓ contra role_binding sin el manager delante`)
        assert.equal(caught.status, 422, `driver.${label}: ${caught.message}`)
        assert.equal(caught.code, 'E_AUTHZ_RELATION_TYPE_UNKNOWN', `driver.${label}`)
      }
      for (const [label, run] of [
        ['relate', () => driver.relate(u, 'assignee', doc, S)],
        ['check', () => driver.check(u, 'assignee', doc, S)],
        ['listSubjects', () => driver.listSubjects('assignee', doc, S)],
      ] as Array<[string, () => Promise<unknown>]>) {
        const caught = await run().then(() => null, (e) => e)
        assert.equal(caught?.status, 422, `driver.${label}: ${caught?.message}`)
        assert.equal(caught?.code, 'E_AUTHZ_RELATION_UNKNOWN', `driver.${label}`)
      }
      // ⚪ A12 (auditor del lote A): el tope y el lote vacío también se cortan en el DRIVER directo.
      if (typeof driver.checkMany === 'function') {
        const many: RelObject[] = []
        for (let i = 0; i <= RELATIONS_CHECK_MANY_MAX; i++) many.push({ type: 'document', id: docId() })
        for (const [label, objects] of [
          [`${RELATIONS_CHECK_MANY_MAX + 1}`, many],
          ['[]', []],
        ] as Array<[string, RelObject[]]>) {
          const caught = await driver.checkMany(u, 'viewer', objects, S).then(() => null, (e) => e)
          assert.isNotNull(caught, `ROJO (A12 · driver.checkMany ${label}): el driver directo no corta el lote`)
          assert.equal(caught.status, 422, `driver.checkMany ${label}: ${caught.message}`)
          assert.equal(caught.code, 'E_AUTHZ_CHECK_MANY_BATCH', `driver.checkMany ${label}`)
        }
        assert.lengthOf(await driver.checkMany(u, 'viewer', many.slice(0, RELATIONS_CHECK_MANY_MAX), S), RELATIONS_CHECK_MANY_MAX, 'el tope exacto responde')
      }
      // Control: lo declarado entra por el driver y el store no tiene ni rastro del binding.
      await driver.relate(u, 'viewer', doc, S)
      assert.isTrue(await driver.check(u, 'viewer', doc, S))
      if (typeof driver.enumerateRelations === 'function' && harness.capabilities.enumerateRelations) {
        const page = await driver.enumerateRelations(S)
        assert.isFalse(page.tuples.some((t) => t.object.type === 'role_binding'), 'cero tuplas role_binding')
      }
    })

    /* ── B3 · el userset del SUJETO: `group#member` y solo `group#member` (plan 2.5 · lote B; cierre 1 · 🟡 5) ── */

    /**
     * **B3 en el runner PUBLICADO** (cierre 1 del lote B · 🟡 5 del auditor):
     * hasta el cierre la variante `usersetUnsupported` solo vivía en la guardia
     * de superficie del paquete, así que un driver de terceros que guardara la
     * fila inerte (`document#viewer` como sujeto) —o respondiera 503— pasaba
     * `runRelationsDriverContract` entero, y el reconcile hacia él y
     * `manager.driver()` repetían los 🟠 1/🟠 2. Es «variante de F-05» (D13):
     * se exige por el MANAGER y por el DRIVER llamado en directo, en las seis
     * operaciones con sujeto, con el `code` propio; por el manager con CERO
     * llamadas al driver (espía) y CERO eventos. El userset legítimo
     * (`group#member`) sigue entrando por los mismos caminos (control).
     */
    test('B3 · un userset ≠ group#member como SUJETO (document#viewer, declarado) ⇒ 422 E_AUTHZ_RELATION_USERSET_UNSUPPORTED en relate/unrelate/check/checkMany/listObjects/purgeSubject, por el MANAGER (CERO llamadas al driver, CERO eventos) y por el DRIVER en directo; group#member entra (control)', async ({
      assert,
    }) => {
      const S = partition()
      const doc: RelObject = { type: 'document', id: docId() }
      const other: RelObject = { type: 'document', id: docId() }
      const stale: RelSubject = { object: other, relation: 'viewer' }
      const attemptsOn = (driver: RelationsDriver | RelationsManager): Array<[string, () => Promise<unknown>]> => [
        ['relate', () => driver.relate(stale, 'viewer', doc, S)],
        ['unrelate', () => driver.unrelate(stale, 'viewer', doc, S)],
        ['check', () => driver.check(stale, 'viewer', doc, S)],
        ['checkMany', () => (typeof driver.checkMany === 'function' ? driver.checkMany(stale, 'viewer', [doc], S) : driver.check(stale, 'viewer', doc, S))],
        ['listObjects', () => driver.listObjects(stale, 'viewer', 'document', S)],
        ['purgeSubject', () => driver.purgeSubject(stale, S)],
      ]
      for (const [path, target] of [
        ['manager', state.manager],
        ['driver', state.base],
      ] as Array<[string, RelationsDriver | RelationsManager]>) {
        for (const [label, run] of attemptsOn(target)) {
          const caught = await run().then(() => null, (e) => e)
          assert.isNotNull(caught, `ROJO (B3 · ${path}.${label}): el userset document#viewer ENTRÓ como sujeto`)
          assert.equal(caught.status, 422, `${path}.${label}: ${caught.message}`)
          assert.equal(caught.code, 'E_AUTHZ_RELATION_USERSET_UNSUPPORTED', `${path}.${label}`)
        }
      }
      // Por el manager, «cero llamadas» se observa con el espía.
      assert.equal(state.calls(), 0, 'por el manager: CERO llamadas al driver')
      assert.lengthOf(state.events, 0, 'CERO eventos')
      // Cierre 2 del lote B · 🟡 N4: por el driver en directo el runner SÍ ve su backend — por el PUERTO. Un
      // tercero que valida DESPUÉS de escribir (`relate` guarda la fila inerte y luego lanza el 422) pasaba el
      // contrato entero (medido: 58/58 verdes con ese mutante sobre el doble). Se afirma por `listSubjects`
      // (invariante 7: hechos directos; un userset guardado saldría ahí con `usersetSubjects: true`) y, con la
      // capacidad, por `enumerateRelations` (la partición entera): la fila NO quedó.
      // **Límite declarado (cierre 3 · ⚪ N11)**: el runner solo ve el backend por los puertos que el harness
      // DECLARA. Con `usersetSubjects: false` (`listSubjects` no devuelve usersets) y `enumerateRelations: false`
      // no hay puerto por el que observar la fila inerte, así que un tercero con ese harness mínimo que guarde y
      // DESPUÉS lance pasa este caso (medido con el mutante «guarda y luego lanza» sobre el doble mínimo). Declara
      // las capacidades que tu driver tiene; el runner no puede probar lo que no se le deja ver (README «Third-party
      // drivers»).
      const staleKey = `${other.type}:${other.id}#viewer`
      const describeSubject = (s: RelSubject) => (isRelUserset(s) ? `${s.object.type}:${s.object.id}#${s.relation}` : `${(s as SubjectRef).type}:${(s as SubjectRef).uuid}`)
      const listed = await state.base.listSubjects('viewer', doc, S)
      assert.notInclude(listed.subjects.map(describeSubject), staleKey, 'ROJO (N4): el driver GUARDÓ la fila inerte antes de lanzar el 422 — listSubjects la enumera')
      if (typeof state.base.enumerateRelations === 'function' && harness.capabilities.enumerateRelations) {
        const page = await state.base.enumerateRelations(S)
        assert.isFalse(page.tuples.some((t) => describeSubject(t.subject) === staleKey), 'ROJO (N4): la partición contiene la fila inerte que el 422 decía no haber escrito')
      }
      // Control: el userset legítimo entra por los dos caminos y concede.
      const u = holder()
      const g: RelObject = { type: 'group', id: docId() }
      await state.manager.relate(u, 'member', g, S)
      await state.manager.relate({ object: g, relation: 'member' }, 'viewer', doc, S)
      assert.isTrue(await state.manager.check(u, 'viewer', doc, S))
      assert.isTrue(await state.base.check({ object: g, relation: 'member' }, 'viewer', doc, S))
      await state.base.purgeSubject({ object: g, relation: 'member' }, S)
      assert.isFalse(await state.manager.check(u, 'viewer', doc, S))
    })

    /* ── R-15 · caducidad de la tupla (núcleo, sin reloj): estricta y validada ── */
    test('R-15 · relate con expiresAt pasado NO concede (check/listObjects/listSubjects); futuro sí; expiresAt inválido ⇒ 422 sin tocar el driver', async ({
      assert,
    }) => {
      const u = holder()
      const doc: RelObject = { type: 'document', id: docId() }
      const p = partition()
      // Caducada al escribirse: no concede y no se enumera (caducidad
      // estricta; sin reloj inyectado, un instante PASADO ya lo observa).
      await state.manager.relate(u, 'viewer', doc, p, { expiresAt: new Date(Date.now() - 60_000) })
      assert.isFalse(await state.manager.check(u, 'viewer', doc, p), 'caducada ⇒ check false')
      const objects = await state.manager.listObjects(u, 'viewer', 'document', p)
      assert.isFalse(objects.objects.some((o) => o.id === doc.id), 'caducada ⇒ listObjects no la lista')
      const subjects = await state.manager.listSubjects('viewer', doc, p)
      assert.isFalse(
        subjects.subjects.some((s) => !isRelUserset(s) && (s as SubjectRef).uuid === u.uuid),
        'caducada ⇒ listSubjects no la lista'
      )
      // Con caducidad futura concede (y `Date` sobre la caducada la FIJA: tercer estado).
      await state.manager.relate(u, 'viewer', doc, p, { expiresAt: new Date(Date.now() + 3_600_000) })
      assert.isTrue(await state.manager.check(u, 'viewer', doc, p), 'futura ⇒ concede')
      // Un `expiresAt` que no es Date válida/null/omitido es 422 ANTES del driver.
      const writes = state.writes()
      for (const bad of ['mañana', 12345, new Date('no-es-fecha')]) {
        let caught: any
        try {
          await state.manager.relate(u, 'viewer', doc, p, { expiresAt: bad as any })
          assert.fail(`debería haber lanzado con ${String(bad)}`)
        } catch (error) {
          caught = error
        }
        assert.equal(caught.status, 422)
        assert.equal(caught.code, 'E_AUTHZ_INVALID_IDENTITY')
      }
      assert.equal(state.writes(), writes, 'el driver no se tocó con un expiresAt inválido')
    })

    /* ── Capacidades, cada una con sus DOS caras ── */

    caseFor('singleCheckRelations', {
      // whenTrue: la derivación (includes + userset anidado) resuelve — la
      // propiedad de «un Check» se mide contra el `:8101` en 4-4 (espía).
      whenTrue: () =>
        test('singleCheckRelations · check resuelve includes + userset anidado', async ({ assert }) => {
          const u = holder()
          const doc: RelObject = { type: 'document', id: docId() }
          const g: RelObject = { type: 'group', id: docId() }
          const p = partition()
          await state.manager.relate(u, 'member', g, p)
          await state.manager.relate({ object: g, relation: 'member' }, 'editor', doc, p)
          assert.isTrue(await state.manager.check(u, 'viewer', doc, p)) // editor⊆viewer vía grupo
        }),
      whenFalse: () =>
        test('singleCheckRelations:false · check sigue dando la respuesta correcta', async ({ assert }) => {
          const u = holder()
          const doc: RelObject = { type: 'document', id: docId() }
          const p = partition()
          await state.manager.relate(u, 'viewer', doc, p)
          assert.isTrue(await state.manager.check(u, 'viewer', doc, p))
        }),
    })

    caseFor('listObjectsInherited', {
      // Siempre `false` en este paquete (invariante 7). whenTrue existe para
      // un driver hipotético que enumere lo heredado; no corre con los dobles.
      whenTrue: () =>
        test('listObjectsInherited:true · enumera lo heredado', async ({ assert }) => {
          assert.isTrue(true)
        }),
      whenFalse: () =>
        test('listObjectsInherited:false · listObjects NO abre un subárbol, da directos+derivados', async ({
          assert,
        }) => {
          const u = holder()
          const d1: RelObject = { type: 'document', id: docId() }
          const p = partition()
          await state.manager.relate(u, 'owner', d1, p)
          const page = await state.manager.listObjects(u, 'viewer', 'document', p)
          assert.deepEqual(page.objects.map((o) => o.id), [d1.id])
          assert.isUndefined(page.truncated)
        }),
    })

    caseFor('usersetSubjects', {
      whenTrue: () =>
        test('usersetSubjects:true · listSubjects incluye los usersets (group#member)', async ({ assert }) => {
          const doc: RelObject = { type: 'document', id: docId() }
          const g: RelObject = { type: 'group', id: docId() }
          const p = partition()
          await state.manager.relate({ object: g, relation: 'member' }, 'viewer', doc, p)
          const page = await state.manager.listSubjects('viewer', doc, p)
          assert.isTrue(page.subjects.some((s) => isRelUserset(s)))
        }),
      whenFalse: () =>
        test('usersetSubjects:false · listSubjects devuelve solo holders', async ({ assert }) => {
          const doc: RelObject = { type: 'document', id: docId() }
          const g: RelObject = { type: 'group', id: docId() }
          const u = holder()
          const p = partition()
          await state.manager.relate(u, 'viewer', doc, p)
          await state.manager.relate({ object: g, relation: 'member' }, 'viewer', doc, p)
          const page = await state.manager.listSubjects('viewer', doc, p)
          assert.isFalse(page.subjects.some((s) => isRelUserset(s)))
        }),
    })

    caseFor('membersOfNative', {
      whenTrue: () =>
        test('membersOfNative:true · membersOf da la membresía TRANSITIVA (distinta de listSubjects)', async ({
          assert,
        }) => {
          const u = holder()
          const g1: RelObject = { type: 'group', id: docId() }
          const g2: RelObject = { type: 'group', id: docId() }
          const p = partition()
          await state.manager.relate(u, 'member', g1, p)
          await state.manager.relate({ object: g1, relation: 'member' }, 'member', g2, p)
          const transitive = await state.manager.membersOf(g2, 'member', p)
          assert.isTrue(transitive.subjects.some((s) => !isRelUserset(s) && (s as SubjectRef).uuid === u.uuid))
          // listSubjects DIRECTO de g2 no lo trae (solo el userset g1#member).
          const direct = await state.manager.listSubjects('member', g2, p)
          assert.isFalse(direct.subjects.some((s) => !isRelUserset(s) && (s as SubjectRef).uuid === u.uuid))
        }),
      whenFalse: () =>
        test('membersOfNative:false · membersOf ⇒ 500 E_AUTHZ_UNSUPPORTED nombrándolo', async ({ assert }) => {
          const g: RelObject = { type: 'group', id: docId() }
          const p = partition()
          let caught: any
          try {
            await state.manager.membersOf(g, 'member', p)
            assert.fail('debería haber lanzado')
          } catch (error) {
            caught = error
          }
          assert.equal(caught.status, 500)
          assert.equal(caught.code, 'E_AUTHZ_UNSUPPORTED')
          assert.include(caught.message, 'membersOf')
        }),
    })

    caseFor('enumerateRelations', {
      whenTrue: () =>
        test('enumerateRelations:true · enumera las tuplas de la partición', async ({ assert }) => {
          const u = holder()
          const doc: RelObject = { type: 'document', id: docId() }
          const p = partition()
          await state.manager.relate(u, 'viewer', doc, p)
          const page = await state.manager.enumerateRelations(p)
          assert.lengthOf(page.tuples, 1)
          assert.equal(page.tuples[0].relation, 'viewer')
        }),
      whenFalse: () =>
        test('enumerateRelations:false · enumerateRelations ⇒ 500 E_AUTHZ_UNSUPPORTED', async ({ assert }) => {
          const p = partition()
          let caught: any
          try {
            await state.manager.enumerateRelations(p)
            assert.fail('debería haber lanzado')
          } catch (error) {
            caught = error
          }
          assert.equal(caught.status, 500)
          assert.equal(caught.code, 'E_AUTHZ_UNSUPPORTED')
          assert.include(caught.message, 'enumerateRelations')
        }),
    })

    caseFor('listObjectsTruncation', {
      whenTrue: () =>
        test('listObjectsTruncation:true · listObjects trunca al tope y SEÑALA truncated', async ({ assert }) => {
          const limit = harness.limits?.listMaxResults
          if (!limit) {
            throw new Error(
              `[contrato ${harness.name}] declara 'listObjectsTruncation: true' sin 'limits.listMaxResults'.`
            )
          }
          const u = holder()
          const p = partition()
          for (let i = 0; i < limit + 2; i++) {
            await state.manager.relate(u, 'viewer', { type: 'document', id: docId() }, p)
          }
          const page = await state.manager.listObjects(u, 'viewer', 'document', p)
          assert.lengthOf(page.objects, limit)
          assert.isTrue(page.truncated)
        }),
      whenFalse: () =>
        test('listObjectsTruncation:false · listObjects es exhaustiva (sin señal de truncado)', async ({
          assert,
        }) => {
          const u = holder()
          const p = partition()
          for (let i = 0; i < 5; i++) {
            await state.manager.relate(u, 'viewer', { type: 'document', id: docId() }, p)
          }
          const page = await state.manager.listObjects(u, 'viewer', 'document', p)
          assert.lengthOf(page.objects, 5)
          assert.isUndefined(page.truncated)
        }),
    })

    /* ── R-15 · el par `injectableClock` (paridad con roles, 2.5 · J1) ── */
    caseFor('injectableClock', {
      whenTrue: () =>
        test('injectableClock:true · expiresAt en tres estados con el reloj inyectado, y la caducidad EXACTA (T−1 ms concede, T no, T+1 no) en check/listObjects/listSubjects y a través de un userset; renovar y revivir sin dormir', async ({
          assert,
        }) => {
          assert.typeOf(state.base.withClock, 'function', 'injectableClock: true exige withClock en el puerto')
          // `T` lleva milisegundos a propósito (2.5 · J3): un motor que trunque
          // a segundos falla aquí (DATETIME(3) en MySQL).
          const T = new Date('2030-06-15T12:34:56.789Z')
          const clock = fixedClock(new Date(T.getTime() - 60_000))
          const clocked = new RelationsManager(state.base.withClock!(clock.now), contractRelationsConfig())
          const u = holder()
          const doc: RelObject = { type: 'document', id: docId() }
          const viaGroup: RelObject = { type: 'document', id: docId() }
          const g: RelObject = { type: 'group', id: docId() }
          const p = partition()
          await clocked.relate(u, 'viewer', doc, p, { expiresAt: T })
          // La MEMBRESÍA caduca: g#member es editor de `viaGroup` sin plazo, pero
          // u es member de g solo hasta T ⇒ en T deja de ser viewer de viaGroup.
          await clocked.relate(u, 'member', g, p, { expiresAt: T })
          await clocked.relate({ object: g, relation: 'member' }, 'editor', viaGroup, p)

          const observe = async () => ({
            check: await clocked.check(u, 'viewer', doc, p),
            listObjects: (await clocked.listObjects(u, 'viewer', 'document', p)).objects.some((o) => o.id === doc.id),
            listSubjects: (await clocked.listSubjects('viewer', doc, p)).subjects.some(
              (s) => !isRelUserset(s) && (s as SubjectRef).uuid === u.uuid
            ),
            viaGroup: await clocked.check(u, 'viewer', viaGroup, p),
            ...(harness.capabilities.membersOfNative
              ? {
                  membersOf: (await clocked.membersOf(g, 'member', p)).subjects.some(
                    (s) => !isRelUserset(s) && (s as SubjectRef).uuid === u.uuid
                  ),
                }
              : {}),
          })
          const alive = {
            check: true,
            listObjects: true,
            listSubjects: true,
            viaGroup: true,
            ...(harness.capabilities.membersOfNative ? { membersOf: true } : {}),
          }
          const gone = {
            check: false,
            listObjects: false,
            listSubjects: false,
            viaGroup: false,
            ...(harness.capabilities.membersOfNative ? { membersOf: false } : {}),
          }

          clock.set(new Date(T.getTime() - 1))
          assert.deepEqual(await observe(), alive, 'T−1 ms')
          clock.set(T)
          assert.deepEqual(await observe(), gone, 'T: la que vence ahora ya no cuenta (estricta)')
          clock.set(new Date(T.getTime() + 1))
          assert.deepEqual(await observe(), gone, 'T+1 ms')

          // Renovación: `Date` posterior vuelve a conceder hasta ESE instante.
          const T2 = new Date(T.getTime() + 1_000)
          await clocked.relate(u, 'viewer', doc, p, { expiresAt: T2 })
          await clocked.relate(u, 'member', g, p, { expiresAt: T2 })
          assert.deepEqual(await observe(), alive, 'renovada en T+1 ms')
          clock.set(new Date(T2.getTime() - 1))
          assert.deepEqual(await observe(), alive, 'T2−1 ms')
          clock.set(T2)
          assert.deepEqual(await observe(), gone, 'T2')

          // Los tres estados (invariante 10), con el reloj en T2 (u ya caducado):
          // omitido sobre una CADUCADA revive sin caducidad;
          await clocked.relate(u, 'viewer', doc, p)
          await clocked.relate(u, 'member', g, p)
          clock.set(new Date('2099-12-31T23:59:59.999Z'))
          assert.deepEqual(await observe(), alive, 'revivida sin caducidad: vigente en 2099')
          // omitido sobre una VIGENTE la preserva (no la convierte en permanente);
          const keep = holder()
          const soon = new Date(clock.now().getTime() + 1_500)
          await clocked.relate(keep, 'viewer', doc, p, { expiresAt: soon })
          await clocked.relate(keep, 'viewer', doc, p)
          // null la quita.
          const lift = holder()
          await clocked.relate(lift, 'viewer', doc, p, { expiresAt: soon })
          await clocked.relate(lift, 'viewer', doc, p, { expiresAt: null })
          clock.set(new Date(soon.getTime() - 1))
          assert.isTrue(await clocked.check(keep, 'viewer', doc, p), 'preservada: vigente en soon−1')
          clock.set(soon)
          assert.isFalse(await clocked.check(keep, 'viewer', doc, p), 'preservada: vence en soon (omitido NO la hizo permanente)')
          assert.isTrue(await clocked.check(lift, 'viewer', doc, p), 'null la quitó: sigue vigente')
          // El driver del harness (sin reloj inyectado) no se ha tocado: para él
          // (hoy) T2 —2030— es futuro y la relación renovada concede.
          assert.isTrue(await state.manager.check(lift, 'viewer', doc, p))

          // **A-18 · un solo `now` por lote** (plan 2.5 · lote A): un reloj que
          // AVANZA 1 ms por lectura y tres tuplas que caducan en T3+1, T3+2 y
          // T3+3. `checkMany` lee el reloj UNA vez (T3) y las tres conceden;
          // un driver que leyera `now()` por ítem vería caducar la segunda o
          // la tercera entre ítems (mutante: `now()` por ítem ⇒ rojo). Solo
          // donde el driver trae `checkMany`: el respaldo del manager son N
          // `check`, cada uno con su instante (y así va escrito en el README).
          if (typeof state.base.checkMany === 'function') {
            const T3 = new Date('2031-01-01T00:00:00.000Z')
            const tickClock = fixedClock(T3)
            const batch = holder()
            const b1: RelObject = { type: 'document', id: docId() }
            const b2: RelObject = { type: 'document', id: docId() }
            const b3: RelObject = { type: 'document', id: docId() }
            const ticking = new RelationsManager(state.base.withClock!(tickClock.now), contractRelationsConfig())
            await ticking.relate(batch, 'viewer', b1, p, { expiresAt: new Date(T3.getTime() + 1) })
            await ticking.relate(batch, 'viewer', b2, p, { expiresAt: new Date(T3.getTime() + 2) })
            await ticking.relate(batch, 'viewer', b3, p, { expiresAt: new Date(T3.getTime() + 3) })
            let reads = 0
            const advancing = new RelationsManager(
              state.base.withClock!(() => new Date(T3.getTime() + reads++)),
              contractRelationsConfig()
            )
            assert.deepEqual(await advancing.checkMany(batch, 'viewer', [b1, b2, b3, b1, b2, b3], p), [true, true, true, true, true, true], 'un solo now por lote: las tres conceden en T3')
            assert.equal(reads, 1, 'checkMany leyó el reloj EXACTAMENTE una vez para todo el lote')
            // Y con el reloj ya en T3+3 ninguna concede (estricta): el lote decide con UN instante, no con el primero cacheado.
            reads = 3
            assert.deepEqual(await advancing.checkMany(batch, 'viewer', [b1, b2, b3], p), [false, false, false])
          }
        }),
      whenFalse: () =>
        test('injectableClock:false · expiresAt en tres estados en tiempo real (1,5 s): omitido preserva, null quita, caducada revive; sin withClock', async ({
          assert,
        }) => {
          assert.notTypeOf(
            (state.base as { withClock?: unknown }).withClock,
            'function',
            'el harness declara injectableClock: false y el driver trae withClock: declara lo observable'
          )
          const doc: RelObject = { type: 'document', id: docId() }
          const p = partition()
          const keep = holder()
          const lift = holder()
          const revive = holder()
          const soon = new Date(Date.now() + 1_500)
          await state.manager.relate(keep, 'viewer', doc, p, { expiresAt: soon })
          await state.manager.relate(keep, 'viewer', doc, p) // omitido: preserva `soon`
          await state.manager.relate(lift, 'viewer', doc, p, { expiresAt: soon })
          await state.manager.relate(lift, 'viewer', doc, p, { expiresAt: null }) // la quita
          await state.manager.relate(revive, 'viewer', doc, p, { expiresAt: new Date(Date.now() - 60_000) })
          assert.isFalse(await state.manager.check(revive, 'viewer', doc, p), 'caducada no concede')
          await state.manager.relate(revive, 'viewer', doc, p) // omitido sobre caducada: revive sin caducidad
          assert.isTrue(await state.manager.check(keep, 'viewer', doc, p))
          assert.isTrue(await state.manager.check(lift, 'viewer', doc, p))
          assert.isTrue(await state.manager.check(revive, 'viewer', doc, p))
          await sleep(1_700)
          assert.isFalse(await state.manager.check(keep, 'viewer', doc, p), 'preservada: venció')
          assert.isTrue(await state.manager.check(lift, 'viewer', doc, p), 'sin caducidad: sigue')
          assert.isTrue(await state.manager.check(revive, 'viewer', doc, p), 'revivida sin caducidad: sigue')
        }),
    })

    /* ── L-2 · el par `transactionalWrites` (panel `{trx}`, (C); mismo nombre que en roles) ── */
    caseFor('transactionalWrites', {
      // L-4: la cara `true`. Lo que se juzga es «los dos o ninguno con TU
      // transacción» POR CENSO (paridad con la cara `true` de roles, L-3): el
      // rollback deja CERO tuplas nuevas en la partición (no solo `check`
      // false — una respuesta puede salir bien con la fila viva), el commit
      // las deja escritas, mientras la transacción está abierta la autoridad
      // (que lee por la conexión del motor) no ve nada, y `purgeObject`/
      // `purgeSubject` borran y REVIERTEN juntos (tras el rollback todo lo
      // purgado está de vuelta). Y la otra mitad: una transacción que NO es
      // la del driver no recibe ni una sentencia. Necesita un motor con
      // transacciones reales y pool ≥ 2: el harness `database` lo declara
      // `true` en `sqlite-file`/PG/MySQL y `false` en `:memory:`.
      whenTrue: () =>
        test('transactionalWrites:true · relate/unrelate/purgeObject/purgeSubject con { transaction } + rollback ⇒ check sin cambio Y CERO tuplas nuevas (censo); + commit ⇒ aplicado; purge* borran y revierten JUNTOS; el EVENTO de las cuatro lleva transactional: true (y sin { transaction }, no); una transacción ajena, un cliente sin transacción o el `db` entero ⇒ 500 E_AUTHZ_CONFIG sin UNA sentencia por ella', async ({
          assert,
        }) => {
          assert.equal(
            state.base.capabilities?.transactionalWrites,
            true,
            'el harness declara transactionalWrites: true y el driver no: declara lo observable'
          )
          const tx = harness.transactions ?? lucidRelationsContractTransactions()
          const u = holder()
          const v = holder()
          const doc: RelObject = { type: 'document', id: docId() }
          const other: RelObject = { type: 'document', id: docId() }
          const p = partition()
          const can = () => state.manager.check(u, 'viewer', doc, p)
          const census = () => tx.census(p)
          // Una transacción que se queda abierta tras una aserción fallida
          // retiene una conexión del pool y arrastra a los casos siguientes:
          // el rollback va en `finally`, y el commit solo si nada falló.
          const rolledBack = async (fn: (client: unknown) => Promise<void>) => {
            const t = await tx.begin()
            try {
              await fn(t.client)
            } finally {
              await t.rollback()
            }
          }
          const committed = async (fn: (client: unknown) => Promise<void>) => {
            const t = await tx.begin()
            try {
              await fn(t.client)
            } catch (error) {
              await t.rollback()
              throw error
            }
            await t.commit()
          }

          // relate: dentro no se ve desde fuera; rollback ⇒ nada; commit ⇒ concede.
          let seenInside: boolean | undefined
          await rolledBack(async (transaction) => {
            await state.manager.relate(u, 'viewer', doc, p, { transaction })
            seenInside = await can()
          })
          assert.equal(await census(), 0, 'ROJO: la relación sobrevivió al rollback (la escritura NO fue por la transacción del llamante)')
          assert.isFalse(await can(), 'relate + rollback ⇒ no concede')
          assert.isFalse(seenInside, 'la autoridad lee por la conexión del motor: el relate sin confirmar no concede')
          await committed(async (transaction) => {
            await state.manager.relate(u, 'viewer', doc, p, { transaction })
          })
          assert.isTrue(await can(), 'relate + commit ⇒ concede')
          assert.equal(await census(), 1)

          // unrelate: rollback ⇒ la tupla sigue; commit ⇒ se va.
          await rolledBack(async (transaction) => {
            await state.manager.unrelate(u, 'viewer', doc, p, { transaction })
            seenInside = await can()
          })
          assert.equal(await census(), 1, 'ROJO: el unrelate sobrevivió al rollback')
          assert.isTrue(await can(), 'unrelate + rollback ⇒ sigue concediendo')
          assert.isTrue(seenInside, 'el unrelate sin confirmar no se ve desde la conexión del motor')
          await committed(async (transaction) => {
            await state.manager.unrelate(u, 'viewer', doc, p, { transaction })
          })
          assert.isFalse(await can(), 'unrelate + commit ⇒ no concede')
          assert.equal(await census(), 0)

          // purgeObject: dos sujetos sobre `doc` + uno sobre `other`; rollback ⇒
          // los tres siguen (borran y revierten JUNTOS); commit ⇒ quedan solo
          // los de `other`.
          await state.manager.relate(u, 'viewer', doc, p)
          await state.manager.relate(v, 'editor', doc, p)
          await state.manager.relate(u, 'owner', other, p)
          assert.equal(await census(), 3)
          await rolledBack(async (transaction) => {
            await state.manager.purgeObject(doc, p, { transaction })
            seenInside = await can()
          })
          assert.equal(await census(), 3, 'ROJO: purgeObject sobrevivió al rollback (algo de lo purgado no volvió)')
          assert.isTrue(await can(), 'purgeObject + rollback ⇒ sigue concediendo')
          assert.isTrue(await state.manager.check(v, 'viewer', doc, p))
          assert.isTrue(seenInside, 'el purgeObject sin confirmar no se ve desde la conexión del motor')
          await committed(async (transaction) => {
            await state.manager.purgeObject(doc, p, { transaction })
          })
          assert.equal(await census(), 1, 'purgeObject + commit ⇒ solo queda la tupla de `other`')
          assert.isFalse(await can())
          assert.isFalse(await state.manager.check(v, 'viewer', doc, p))
          assert.isTrue(await state.manager.check(u, 'owner', other, p))

          // purgeSubject: `u` es owner de `other` y viewer de `doc` de nuevo;
          // rollback ⇒ las dos siguen; commit ⇒ las dos se van y `v` no se toca.
          await state.manager.relate(u, 'viewer', doc, p)
          await state.manager.relate(v, 'viewer', doc, p)
          assert.equal(await census(), 3)
          await rolledBack(async (transaction) => {
            await state.manager.purgeSubject(u, p, { transaction })
            seenInside = await can()
          })
          assert.equal(await census(), 3, 'ROJO: purgeSubject sobrevivió al rollback')
          assert.isTrue(await can(), 'purgeSubject + rollback ⇒ sigue concediendo')
          assert.isTrue(await state.manager.check(u, 'owner', other, p))
          assert.isTrue(seenInside, 'el purgeSubject sin confirmar no se ve desde la conexión del motor')
          await committed(async (transaction) => {
            await state.manager.purgeSubject(u, p, { transaction })
          })
          assert.equal(await census(), 1, 'purgeSubject + commit ⇒ solo queda la tupla de `v`')
          assert.isFalse(await can())
          assert.isFalse(await state.manager.check(u, 'owner', other, p))
          assert.isTrue(await state.manager.check(v, 'viewer', doc, p))

          // alpha.3 · B3: la OTRA cara observable de la capacidad — el evento.
          // Cada escritura inscrita en `{ transaction }` (rollback o commit,
          // da igual: el paquete no ve el desenlace) publica `transactional:
          // true`; las que fueron SIN transacción, no (ausente, no `false`).
          const inTrx = state.events.filter((e) => e.transactional === true).map((e) => e.operation)
          assert.deepEqual(
            inTrx,
            ['relate', 'relate', 'unrelate', 'unrelate', 'purgeObject', 'purgeObject', 'purgeSubject', 'purgeSubject'],
            'ROJO: el evento de una escritura inscrita en tu transacción no lleva transactional: true (las ocho: 2 por operación, rollback + commit)'
          )
          const outside = state.events.filter((e) => e.transactional !== true)
          assert.isAbove(outside.length, 0, 'las escrituras sin transacción también notifican')
          for (const e of outside) assert.notProperty(e, 'transactional', `${e.operation} sin { transaction }: la marca está AUSENTE`)

          // Una transacción que NO es la del driver (`assertCallerTransaction`):
          // 500 `E_AUTHZ_CONFIG` y ni una sentencia por ella (espía).
          const statements: string[] = []
          const spyTrx = (shape: Record<string, unknown>) =>
            new Proxy(shape, {
              get(target, prop) {
                if (prop === 'from' || prop === 'table' || prop === 'raw' || prop === 'query' || prop === 'knexQuery' || prop === 'rawQuery' || prop === 'transaction') {
                  return (...args: unknown[]) => {
                    statements.push(`${String(prop)}(${String(args[0] ?? '')})`)
                    return { where: () => ({}), select: async () => [], insert: async () => [], delete: async () => 0 }
                  }
                }
                return Reflect.get(target, prop)
              },
            })
          const foreign = spyTrx({ isTransaction: true, connectionName: `not-${harness.name}-${uuidv7()}` })
          const notATransaction = spyTrx({ isTransaction: false, connectionName: 'primary' })
          const wholeDb = spyTrx({ connection() {}, primaryConnectionName: 'primary' })
          const w = holder()
          const writesBefore = state.writes()
          for (const [label, transaction] of [
            ['otra conexión', foreign],
            ['un cliente sin transacción', notATransaction],
            ['el db entero', wholeDb],
          ] as const) {
            for (const [operation, run] of [
              ['relate', () => state.manager.relate(w, 'viewer', doc, p, { transaction })],
              ['unrelate', () => state.manager.unrelate(w, 'viewer', doc, p, { transaction })],
              ['purgeObject', () => state.manager.purgeObject(doc, p, { transaction })],
              ['purgeSubject', () => state.manager.purgeSubject(w, p, { transaction })],
            ] as const) {
              let caught: any
              try {
                await run()
                assert.fail(`${label}/${operation}: debería haber lanzado`)
              } catch (error) {
                caught = error
              }
              assert.equal(caught.status, 500, `${label}/${operation}: ${caught.message}`)
              assert.equal(caught.code, 'E_AUTHZ_CONFIG', `${label}/${operation}`)
              assert.include(caught.message, operation, `${label}/${operation}: nombra la operación`)
            }
          }
          assert.deepEqual(statements, [], 'ni una sentencia por una transacción que no es la del driver')
          assert.isAbove(state.writes(), writesBefore, 'la trx ajena la juzga el DRIVER (assertCallerTransaction), no la puerta 1')
          assert.equal(await census(), 1, 'la trx ajena no escribió nada')
          assert.isFalse(await state.manager.check(w, 'viewer', doc, p))
          // Y la trx ajena (500 del driver) tampoco notifica: no hubo escritura.
          assert.equal(state.events.length, inTrx.length + outside.length, 'una escritura rechazada por assertCallerTransaction no notifica')
        })?.timeout(30_000),
      whenFalse: () =>
        test('transactionalWrites:false · { transaction } en relate/unrelate/purgeObject/purgeSubject ⇒ 500 E_AUTHZ_UNSUPPORTED nombrando driver y operación, con CERO llamadas al driver (espía) y CERO eventos; y requireTransactionalWrites: true ⇒ 500 E_AUTHZ_CONFIG al construir el manager (= al resolver el driver)', async ({
          assert,
        }) => {
          assert.notEqual(
            state.base.capabilities?.transactionalWrites,
            true,
            'el harness declara transactionalWrites: false y el driver declara true: declara lo observable'
          )
          const trx = { from() {}, table() {}, isTransaction: true, connectionName: 'primary' }
          const u = holder()
          const doc: RelObject = { type: 'document', id: docId() }
          const p = partition()
          const writes: Array<[string, () => Promise<unknown>]> = [
            ['relate', () => state.manager.relate(u, 'viewer', doc, p, { transaction: trx })],
            ['unrelate', () => state.manager.unrelate(u, 'viewer', doc, p, { transaction: trx })],
            ['purgeObject', () => state.manager.purgeObject(doc, p, { transaction: trx })],
            ['purgeSubject', () => state.manager.purgeSubject(u, p, { transaction: trx })],
          ]
          for (const [operation, run] of writes) {
            let caught: any
            try {
              await run()
              assert.fail(`${operation}: debería haber lanzado`)
            } catch (error) {
              caught = error
            }
            assert.equal(caught.status, 500, `${operation}: ${caught.message}`)
            assert.equal(caught.code, 'E_AUTHZ_UNSUPPORTED', operation)
            assert.include(caught.message, `'${harness.name}'`, `${operation}: nombra el driver`)
            assert.include(caught.message, operation, `${operation}: nombra la operación`)
            assert.include(caught.message, 'requireTransactionalWrites', `${operation}: la letra lleva la salida`)
          }
          assert.equal(state.writes(), 0, 'cero llamadas al driver: el rechazo va ANTES del backend')
          assert.deepEqual(state.events, [], 'alpha.3 · B3: una escritura que no ocurre no notifica (cero eventos)')
          // Sin `{ transaction }` la MISMA escritura entra, y notifica SIN la marca.
          await state.manager.relate(u, 'viewer', doc, p)
          assert.isTrue(await state.manager.check(u, 'viewer', doc, p))
          assert.equal(state.writes(), 1)
          assert.lengthOf(state.events, 1)
          assert.notProperty(state.events[0], 'transactional', 'con transactionalWrites: false la marca NUNCA aparece')

          // Puerta 2, opt-in: al construir el manager (= resolver el driver).
          let atResolve: any
          try {
            new RelationsManager(state.base, contractRelationsConfig(), {
              requireTransactionalWrites: true,
              driverName: harness.name,
            })
            assert.fail('requireTransactionalWrites: true sobre un driver que declara false tenía que lanzar al construir')
          } catch (error) {
            atResolve = error
          }
          assert.equal(atResolve.status, 500, String(atResolve?.message))
          assert.equal(atResolve.code, 'E_AUTHZ_CONFIG')
          assert.include(atResolve.message, `'${harness.name}'`)
          assert.include(atResolve.message, 'transactionalWrites')
        }),
    })

    /* ── Lote D · D1 · el par `relationDenies` (D5 corte de camino, D8, D9, D10, D3, S8–S10, S12–S15, P-2) ── */

    /** Un manager sobre la config del contrato CON deny (`document` 'write', `workspace` 'read', `note` sin opt-in). */
    async function denyManager(options?: ConstructorParameters<typeof RelationsManager>[2]) {
      const config = contractDenyRelationsConfig()
      const base = await harness.makeDriver(config)
      const s = spy(base)
      return {
        manager: new RelationsManager(s.driver, config, { driverName: harness.name, ...options }),
        base,
        config,
        writes: s.writes,
        calls: s.calls,
      }
    }

    /** Siembra un estado de T1 sobre un objeto: allows `A` y denies `D` (subconjuntos de owner/editor/viewer) para `u`. */
    async function seedState(m: RelationsManager, u: RelSubject, object: RelObject, p: ScopeRef, allows: readonly string[], denies: readonly string[]) {
      for (const r of allows) await m.relate(u, r, object, p)
      for (const r of denies) await m.deny(u, r, object, p)
    }

    caseFor('relationDenies', {
      whenTrue: () => {
        test('D-05 · corte de camino: las 192 respuestas de T1 (64 estados × viewer/editor/owner) por check; checkMany, decideMany (D9) y listObjects (D-15) dicen lo MISMO sobre los 64 objetos; P1-M monotonía (D-12)', async ({
          assert,
        }) => {
          // El oráculo es INDEPENDIENTE del código del paquete (la tabla literal del tester §2.2 y su fórmula con el
          // retículo escrito a mano): si fuera `cutPathAllows`, un mutante de la regla cambiaría a la vez el driver y
          // la expectativa y viviría.
          for (let row = 0; row < 64; row++) {
            const { allows, denies } = t1State(row)
            const oracle = T1_QUESTIONS.map((q) => (t1Oracle(allows, denies, q) ? 'T' : 'F')).join('')
            assert.equal(oracle, T1_EXPECTED[row], `T1 fila ${row + 1}: el oráculo y la tabla del tester divergen`)
          }
          const { manager } = await denyManager()
          const u = holder()
          const p = partition()
          const objects: RelObject[] = []
          for (let row = 0; row < 64; row++) {
            const object = { type: 'document', id: docId() }
            objects.push(object)
            const { allows, denies } = t1State(row)
            await seedState(manager, u, object, p, allows, denies)
          }
          const observed: string[] = []
          for (let row = 0; row < 64; row++) {
            let answer = ''
            for (const q of T1_QUESTIONS) answer += (await manager.check(u, q, objects[row], p)) ? 'T' : 'F'
            observed.push(answer)
          }
          const wrong = observed
            .map((got, row) => [row, got] as const)
            .filter(([row, got]) => got !== T1_EXPECTED[row])
            .map(([row, got]) => `fila ${row + 1} (A=${t1State(row).allows.join('+') || '∅'} D=${t1State(row).denies.join('+') || '∅'}${T1_PAR.has(row + 1) ? ', PAR' : ''}): esperado ${T1_EXPECTED[row]} (v/e/o), obtenido ${got}`)
          assert.deepEqual(wrong, [], 'T1 · check con corte de camino')
          // checkMany (sin cambio de contrato) y decideMany (D9 AMPLIO), por lotes de ≤ 50, y listObjects (resta).
          for (const [qi, q] of T1_QUESTIONS.entries()) {
            const many: boolean[] = []
            const decided: string[] = []
            for (let start = 0; start < 64; start += RELATIONS_CHECK_MANY_MAX) {
              const batch = objects.slice(start, start + RELATIONS_CHECK_MANY_MAX)
              many.push(...(await manager.checkMany(u, q, batch, p)))
              decided.push(...(await manager.decideMany(u, q, batch, p)))
            }
            assert.deepEqual(
              many.map((b) => (b ? 'T' : 'F')).join(''),
              T1_EXPECTED.map((x) => x[qi]).join(''),
              `checkMany(${q}) honra el deny igual que check (sin cambio de contrato)`
            )
            const expectedDecisions = T1_EXPECTED.map((x, row) => (x[qi] === 'T' ? 'allow' : t1DeniedAbove(t1State(row).denies, q) ? 'deny' : 'none'))
            assert.deepEqual(decided, expectedDecisions, `decideMany(${q}) · D9 amplio sobre los 64 estados`)
            const page = await manager.listObjects(u, q, 'document', p)
            const listed = page.objects.map((o) => o.id)
            const expectedIds = objects.filter((_, row) => T1_EXPECTED[row][qi] === 'T').map((o) => o.id)
            const intruders = listed.filter((id) => !expectedIds.includes(id))
            assert.deepEqual(intruders, [], `listObjects(${q}) RESTA (D-15): ni un objeto denegado (S16: tampoco con el tope)`)
            if (page.truncated === true) {
              // S16 (tope bajo, :8103 o el doble con tope): la página cortada es un SUBCONJUNTO de lo concedido, y el
              // truncado solo se señala si hay concedidos de más — nunca porque los denegados llenen el tope.
              assert.isAbove(expectedIds.length, listed.length, `listObjects(${q}) · truncated solo si hay allows de más`)
            } else {
              assert.sameMembers(listed, expectedIds, `listObjects(${q}) RESTA (D-15) y es exhaustiva sin truncated`)
            }
          }
          // D-12 · P1-M: más allows o menos denies nunca quita acceso (sobre lo OBSERVADO).
          const nonMonotone: string[] = []
          for (let a = 0; a < 64; a++) {
            for (let b = 0; b < 64; b++) {
              const A = t1State(a)
              const B = t1State(b)
              const moreOrEqual = A.allows.every((r) => B.allows.includes(r)) && B.denies.every((r) => A.denies.includes(r))
              if (!moreOrEqual) continue
              for (let qi = 0; qi < 3; qi++) {
                if (observed[a][qi] === 'T' && observed[b][qi] === 'F') nonMonotone.push(`${a + 1}→${b + 1} (${T1_QUESTIONS[qi]})`)
              }
            }
          }
          assert.deepEqual(nonMonotone, [], 'D-12 · P1-M: monotonía en los 64 estados')
        })

        for (const [name, row, expected] of T1_NAMED) {
          test(`${name} (T1 fila ${row})`, async ({ assert }) => {
            const { manager } = await denyManager()
            const u = holder()
            const p = partition()
            const object = { type: 'document', id: docId() }
            const { allows, denies } = t1State(row - 1)
            await seedState(manager, u, object, p, allows, denies)
            const got = []
            for (const q of T1_QUESTIONS) got.push((await manager.check(u, q, object, p)) ? 'T' : 'F')
            assert.equal(got.join(''), expected, `${name}: v/e/o`)
          })
        }

        test('D-01/D-02/D-03 · deny gana sobre el allow directo y removeDeny lo restaura; el ORDEN de escritura no importa; deny y removeDeny idempotentes (re-deny no duplica, un removeDeny levanta un deny repetido, re-removeDeny es no-op)', async ({ assert }) => {
          const { manager } = await denyManager()
          const p = partition()
          const u = holder()
          const a = { type: 'document', id: docId() }
          await manager.relate(u, 'viewer', a, p)
          assert.isTrue(await manager.check(u, 'viewer', a, p))
          await manager.deny(u, 'viewer', a, p)
          assert.isFalse(await manager.check(u, 'viewer', a, p), 'D-01: deny gana')
          await manager.removeDeny(u, 'viewer', a, p)
          assert.isTrue(await manager.check(u, 'viewer', a, p), 'D-01: removeDeny restaura')
          // D-02: deny ANTES que el allow, mismo resultado.
          const b = { type: 'document', id: docId() }
          await manager.deny(u, 'viewer', b, p)
          await manager.relate(u, 'viewer', b, p)
          assert.isFalse(await manager.check(u, 'viewer', b, p), 'D-02: deny→allow = allow→deny')
          // D-03: idempotencia.
          await manager.deny(u, 'viewer', b, p)
          await manager.deny(u, 'viewer', b, p)
          assert.lengthOf((await manager.listDenies('viewer', b, p)).subjects, 1, 're-deny no duplica')
          await manager.removeDeny(u, 'viewer', b, p)
          assert.isTrue(await manager.check(u, 'viewer', b, p), 'un removeDeny levanta un deny repetido')
          await manager.removeDeny(u, 'viewer', b, p)
          assert.isTrue(await manager.check(u, 'viewer', b, p), 're-removeDeny es no-op')
          assert.deepEqual((await manager.listDenies('viewer', b, p)).subjects, [])
        })

        test('D-04 · allow y deny del MISMO hecho conviven: unrelate no levanta el deny, removeDeny no quita el allow; listSubjects NO resta (D-15) y listDenies da los hechos directos', async ({ assert }) => {
          const { manager } = await denyManager()
          const p = partition()
          const u = holder()
          const v = holder()
          const a = { type: 'document', id: docId() }
          await manager.relate(u, 'viewer', a, p)
          await manager.relate(v, 'viewer', a, p)
          await manager.deny(u, 'viewer', a, p)
          const subjects = (await manager.listSubjects('viewer', a, p)).subjects.map((s) => (s as SubjectRef).uuid)
          assert.sameMembers(subjects, [u.uuid, v.uuid], 'listSubjects da HECHOS: no resta el deny')
          assert.deepEqual((await manager.listDenies('viewer', a, p)).subjects.map((s) => (s as SubjectRef).uuid), [u.uuid])
          await manager.unrelate(u, 'viewer', a, p)
          await manager.relate(u, 'viewer', a, p)
          assert.isFalse(await manager.check(u, 'viewer', a, p), 'unrelate no tocó el deny')
          assert.lengthOf((await manager.listDenies('viewer', a, p)).subjects, 1)
          await manager.removeDeny(u, 'viewer', a, p)
          assert.isTrue(await manager.check(u, 'viewer', a, p), 'removeDeny no quitó el allow')
          assert.isTrue(await manager.check(v, 'viewer', a, p), 'el deny de u nunca tocó a v')
        })

        test('D-13 · deny a g#member bloquea a sus miembros, también ANIDADOS (g1 ⊂ g2, deny a g2#member); un deny DIRECTO bloquea aunque el allow llegue por grupo', async ({ assert }) => {
          const { manager } = await denyManager()
          const p = partition()
          const u = holder()
          const g1 = { type: 'group', id: docId() }
          const g2 = { type: 'group', id: docId() }
          await manager.relate(u, 'member', g1, p)
          await manager.relate({ object: g1, relation: 'member' }, 'member', g2, p)
          const a = { type: 'document', id: docId() }
          await manager.relate(u, 'owner', a, p)
          await manager.deny({ object: g2, relation: 'member' }, 'editor', a, p)
          assert.isFalse(await manager.check(u, 'viewer', a, p), 'deny(editor) a g2#member alcanza a u por g1 ⊂ g2 (fila 35)')
          const b = { type: 'document', id: docId() }
          await manager.relate({ object: g1, relation: 'member' }, 'viewer', b, p)
          assert.isTrue(await manager.check(u, 'viewer', b, p))
          await manager.deny(u, 'viewer', b, p)
          assert.isFalse(await manager.check(u, 'viewer', b, p), 'deny directo gana al allow que llega por el grupo')
        })

        test('D-14 · check de un USERSET: el deny de un miembro NO sube al grupo (check(g#member) sigue siendo la fila de g)', async ({ assert }) => {
          const { manager } = await denyManager()
          const p = partition()
          const u = holder()
          const g = { type: 'group', id: docId() }
          const a = { type: 'document', id: docId() }
          await manager.relate(u, 'member', g, p)
          await manager.relate({ object: g, relation: 'member' }, 'viewer', a, p)
          await manager.deny(u, 'viewer', a, p)
          assert.isFalse(await manager.check(u, 'viewer', a, p))
          assert.isTrue(await manager.check({ object: g, relation: 'member' }, 'viewer', a, p), 'el grupo conserva su viewer')
        })

        test('D-16 · purgeObject y purgeSubject borran también los denies (después del objeto, nada del sujeto sobrevive; re-relate concede)', async ({ assert }) => {
          const { manager } = await denyManager()
          const p = partition()
          const u = holder()
          const a = { type: 'document', id: docId() }
          await manager.relate(u, 'viewer', a, p)
          await manager.deny(u, 'viewer', a, p)
          await manager.purgeObject(a, p)
          assert.deepEqual((await manager.listDenies('viewer', a, p)).subjects, [], 'purgeObject borró el deny')
          await manager.relate(u, 'viewer', a, p)
          assert.isTrue(await manager.check(u, 'viewer', a, p))
          await manager.deny(u, 'viewer', a, p)
          await manager.purgeSubject(u, p)
          assert.deepEqual((await manager.listDenies('viewer', a, p)).subjects, [], 'purgeSubject borró el deny')
          await manager.relate(u, 'viewer', a, p)
          assert.isTrue(await manager.check(u, 'viewer', a, p), 'ni allow ni deny viejos: el re-relate concede')
        })

        test('D-15b · membersOf RESTA (si el driver es nativo): un miembro TRANSITIVO con deny directo, o alcanzado por un deny al grupo, no sale; sin deny, la lista de siempre', async ({ assert }) => {
          if (!harness.capabilities.membersOfNative) {
            // Cara sin membersOf nativo: la operación es 500 E_AUTHZ_UNSUPPORTED (su par lo juzga); aquí se afirma que el deny no la abre.
            const { manager } = await denyManager()
            const caught = await manager.membersOf({ type: 'document', id: docId() }, 'viewer', partition()).then(() => null, (e) => e)
            assert.equal(caught?.code, 'E_AUTHZ_UNSUPPORTED')
            return
          }
          const { manager } = await denyManager()
          const p = partition()
          const a = holder()
          const b = holder()
          const c = holder()
          const g = { type: 'group', id: docId() }
          const doc = { type: 'document', id: docId() }
          await manager.relate(a, 'member', g, p)
          await manager.relate(b, 'member', g, p)
          await manager.relate({ object: g, relation: 'member' }, 'viewer', doc, p)
          await manager.relate(c, 'owner', doc, p)
          const before = (await manager.membersOf(doc, 'viewer', p)).subjects.map((s) => (s as SubjectRef).uuid)
          assert.sameMembers(before, [a.uuid, b.uuid, c.uuid])
          await manager.deny(b, 'viewer', doc, p)
          await manager.deny(c, 'editor', doc, p)
          const after = (await manager.membersOf(doc, 'viewer', p)).subjects.map((s) => (s as SubjectRef).uuid)
          assert.sameMembers(after, [a.uuid], 'b (deny directo) y c (owner cortado por deny(editor), fila 35) no salen')
        })

        test('S8–S10 · FILAS DECLARADAS (quitar acceso que DA acceso): unrelate(u, member, g) con deny a g#member ⇒ u recupera su allow directo (S8); purgeObject(group:g) ⇒ igual (S9); purgeSubject(g#member) borra los denies del grupo (S10)', async ({ assert }) => {
          const { manager } = await denyManager()
          const run = async (lift: (u: SubjectRef, g: RelObject, p: ScopeRef) => Promise<void>, label: string) => {
            const p = partition()
            const u = holder()
            const g = { type: 'group', id: docId() }
            const a = { type: 'document', id: docId() }
            await manager.relate(u, 'viewer', a, p)
            await manager.relate(u, 'member', g, p)
            await manager.deny({ object: g, relation: 'member' }, 'viewer', a, p)
            assert.isFalse(await manager.check(u, 'viewer', a, p), `${label}: antes, el deny del grupo bloquea`)
            await lift(u, g, p)
            assert.isTrue(await manager.check(u, 'viewer', a, p), `${label}: FILA DECLARADA — la escritura que «quita» devuelve el acceso`)
          }
          await run((u, g, p) => manager.unrelate(u, 'member', g, p), 'S8 · salir del grupo denegado')
          await run((_u, g, p) => manager.purgeObject(g, p), 'S9 · purgar el grupo')
          await run((_u, g, p) => manager.purgeSubject({ object: g, relation: 'member' }, p), 'S10 · purgar el userset del grupo')
        })

        test('D-17 · deny sobre un tipo SIN opt-in (note), en FASE 1 (workspace, deny: read), sobre group, con `*` o con un userset ≠ group#member ⇒ 422 con CERO llamadas al driver y CERO eventos; removeDeny y listDenies SÍ aceptan esos tipos declarados (D8: retirar el opt-in es reversible)', async ({ assert }) => {
          const events: RelationWriteEvent[] = []
          const f = await denyManager({ onRelationWrite: (e) => void events.push(e) })
          const p = partition()
          const u = holder()
          const cases: Array<[string, () => Promise<unknown>, string]> = [
            ['tipo sin opt-in', () => f.manager.deny(u, 'viewer', { type: 'note', id: docId() }, p), 'E_AUTHZ_RELATION_NOT_DENYABLE'],
            ["fase 1 (deny: 'read')", () => f.manager.deny(u, 'viewer', { type: 'workspace', id: docId() }, p), 'E_AUTHZ_RELATION_NOT_DENYABLE'],
            ['group', () => f.manager.deny(u, 'member', { type: 'group', id: docId() }, p), 'E_AUTHZ_RELATION_NOT_DENYABLE'],
            ["comodín '*'", () => f.manager.deny({ type: 'user', uuid: '*' }, 'viewer', { type: 'document', id: docId() }, p), 'E_AUTHZ_RELATION_NOT_DENYABLE'],
            ['userset ≠ group#member', () => f.manager.deny({ object: { type: 'document', id: docId() }, relation: 'viewer' }, 'viewer', { type: 'document', id: docId() }, p), 'E_AUTHZ_RELATION_USERSET_UNSUPPORTED'],
          ]
          for (const [label, run, code] of cases) {
            const caught = await run().then(() => null, (e) => e)
            assert.isNotNull(caught, `${label}: entró`)
            assert.equal(caught?.status, 422, `${label}: ${caught?.message}`)
            assert.equal(caught?.code, code, `${label}: ${caught?.message}`)
          }
          assert.equal(f.calls(), 0, 'CERO llamadas al driver')
          assert.lengthOf(events, 0, 'CERO eventos')
          for (const type of ['note', 'workspace']) {
            await f.manager.removeDeny(u, 'viewer', { type, id: docId() }, p)
            assert.deepEqual((await f.manager.listDenies('viewer', { type, id: docId() }, p)).subjects, [], `${type}: listDenies responde`)
          }
        })

        test('D-19 (reescrito por D3) · expiresAt en deny/removeDeny ⇒ 422 E_AUTHZ_DENY_EXPIRY_UNSUPPORTED con la razón medida (Date y null), CERO llamadas', async ({ assert }) => {
          const f = await denyManager()
          const p = partition()
          const a = { type: 'document', id: docId() }
          for (const expiresAt of [new Date(Date.now() + 60_000), null]) {
            for (const op of ['deny', 'removeDeny'] as const) {
              const caught = await f.manager[op](holder(), 'viewer', a, p, { expiresAt } as any).then(() => null, (e) => e)
              assert.equal(caught?.status, 422, `${op}(${String(expiresAt)}): ${caught?.message}`)
              assert.equal(caught?.code, 'E_AUTHZ_DENY_EXPIRY_UNSUPPORTED')
              assert.include(String(caught?.message), 'M5')
            }
          }
          assert.equal(f.calls(), 0)
        })

        test('D-20 · eventos: deny/removeDeny notifican con operation y el nombre PÚBLICO de la relación, el actor y sin expiresAt; requireActor los alcanza; assertWrite ve operation deny/removeDeny y si lanza no hay escritura ni evento', async ({ assert }) => {
          const events: RelationWriteEvent[] = []
          const seen: string[] = []
          const actor = holder()
          const f = await denyManager({
            onRelationWrite: (e) => void events.push(e),
            assertWrite: (ref) => {
              seen.push(ref.operation)
              if (ref.object.id === 'vetado') throw new Error('policy')
            },
          })
          const p = partition()
          const u = holder()
          const a = { type: 'document', id: docId() }
          await f.manager.deny(u, 'viewer', a, p, { actor })
          await f.manager.removeDeny(u, 'viewer', a, p, { actor })
          assert.deepEqual(events.map((e) => e.operation), ['deny', 'removeDeny'])
          assert.equal(events[0].relation, 'viewer', 'el nombre PÚBLICO, nunca denied_viewer')
          assert.deepEqual(events[0].actor, actor)
          assert.notProperty(events[0], 'expiresAt')
          assert.deepEqual(seen, ['deny', 'removeDeny'])
          const vetoed = await f.manager.deny(u, 'viewer', { type: 'document', id: 'vetado' }, p).then(() => null, (e) => e)
          assert.equal(vetoed?.message, 'policy')
          assert.lengthOf(events, 2, 'assertWrite que lanza: sin evento')
          const strict = await denyManager({ requireActor: true })
          const missing = await strict.manager.deny(u, 'viewer', a, p).then(() => null, (e) => e)
          assert.equal(missing?.code, 'E_AUTHZ_ACTOR_REQUIRED')
          const missing2 = await strict.manager.removeDeny(u, 'viewer', a, p).then(() => null, (e) => e)
          assert.equal(missing2?.code, 'E_AUTHZ_ACTOR_REQUIRED')
          assert.equal(strict.calls(), 0)
        })

        test('D9 · decideMany: fila 35 preguntada en viewer ⇒ deny (amplio); fila 43 ⇒ allow; nada ⇒ none; el caso Nóminas (deny en Nóminas con allow heredado de Finanzas ⇒ [none, deny, allow] recorriendo hoja → raíz); orden y duplicados por posición', async ({ assert }) => {
          const { manager } = await denyManager()
          const p = partition()
          const u = holder()
          const row35 = { type: 'document', id: docId() }
          const row43 = { type: 'document', id: docId() }
          const nothing = { type: 'document', id: docId() }
          await seedState(manager, u, row35, p, ['owner'], ['editor'])
          await seedState(manager, u, row43, p, ['owner', 'viewer'], ['editor'])
          assert.deepEqual(await manager.decideMany(u, 'viewer', [row35, row43, nothing, row35], p), ['deny', 'allow', 'none', 'deny'])
          // Nóminas (juez ronda 2 §4; auditor R2-1): la cadena la recorre el LLAMANTE.
          const informe = { type: 'document', id: docId() }
          const nominas = { type: 'document', id: docId() }
          const finanzas = { type: 'document', id: docId() }
          await manager.relate(u, 'viewer', finanzas, p)
          await manager.deny(u, 'viewer', nominas, p)
          assert.deepEqual(await manager.decideMany(u, 'viewer', [informe, nominas, finanzas], p), ['none', 'deny', 'allow'], 'el primer no-none desde la hoja es deny')
          assert.deepEqual(await manager.checkMany(u, 'viewer', [informe, nominas, finanzas], p), [false, false, true], 'con checkMany el mismo escenario es INDISTINGUIBLE (limitación declarada)')
        })

        test(`D9 · decideMany con las MISMAS garantías que checkMany: ${RELATIONS_CHECK_MANY_MAX} responde, ${RELATIONS_CHECK_MANY_MAX + 1} y [] ⇒ 422 E_AUTHZ_CHECK_MANY_BATCH; F-05 por ÍTEM (role_binding en la última posición) y un id inválido ⇒ 422; todo con CERO llamadas`, async ({ assert }) => {
          const f = await denyManager()
          const p = partition()
          const u = holder()
          const ids = Array.from({ length: RELATIONS_CHECK_MANY_MAX }, () => ({ type: 'document', id: docId() }))
          assert.lengthOf(await f.manager.decideMany(u, 'viewer', ids, p), RELATIONS_CHECK_MANY_MAX)
          const before = f.calls()
          for (const objects of [[...ids, { type: 'document', id: docId() }], []]) {
            const caught = await f.manager.decideMany(u, 'viewer', objects, p).then(() => null, (e) => e)
            assert.equal(caught?.code, 'E_AUTHZ_CHECK_MANY_BATCH')
            assert.include(String(caught?.message), 'decideMany')
          }
          const typed = await f.manager.decideMany(u, 'viewer', [...ids.slice(0, 20), { type: 'role_binding', id: docId() }], p).then(() => null, (e) => e)
          assert.equal(typed?.code, 'E_AUTHZ_RELATION_TYPE_UNKNOWN')
          const badId = await f.manager.decideMany(u, 'viewer', [...ids.slice(0, 3), { type: 'document', id: 'A#B' }], p).then(() => null, (e) => e)
          assert.equal(badId?.code, 'E_AUTHZ_INVALID_IDENTITY')
          assert.equal(f.calls(), before, 'CERO llamadas: el lote se juzga antes')
        })

        test('P-2 (COGNITIV) · decideMany para un holder de OTRA organización responde por la partición del OBJETO — y su gemelo en check/checkMany: el mismo holder con allow en A y deny en B sobre el mismo id', async ({ assert }) => {
          const { manager } = await denyManager()
          const orgA = partition()
          const orgB = partition()
          const guest = holder()
          const shared = { type: 'document', id: docId() }
          await manager.relate(guest, 'viewer', shared, orgA)
          await manager.relate(guest, 'viewer', shared, orgB)
          await manager.deny(guest, 'viewer', shared, orgB)
          assert.deepEqual(await manager.decideMany(guest, 'viewer', [shared], orgA), ['allow'], 'decideMany responde por la partición del objeto (A)')
          assert.deepEqual(await manager.decideMany(guest, 'viewer', [shared], orgB), ['deny'], 'y en B, por B')
          assert.isTrue(await manager.check(guest, 'viewer', shared, orgA), 'gemelo check en A')
          assert.isFalse(await manager.check(guest, 'viewer', shared, orgB), 'gemelo check en B')
          assert.deepEqual(await manager.checkMany(guest, 'viewer', [shared], orgA), [true], 'gemelo checkMany en A')
          assert.deepEqual(await manager.checkMany(guest, 'viewer', [shared], orgB), [false], 'gemelo checkMany en B')
        })

        test('D-30 · un alias de la partición jamás evade un deny: con el deny en la canónica, la ortografía sin guiones es 422 en check/checkMany/decideMany/listObjects/deny/removeDeny/listDenies (nunca true)', async ({ assert }) => {
          const { manager } = await denyManager()
          const canonical: ScopeRef = { type: 'unit', uuid: uuidv7() }
          const alias: ScopeRef = { type: 'unit', uuid: canonical.uuid!.replace(/-/g, '') }
          const u = holder()
          const a = { type: 'document', id: docId() }
          await manager.relate(u, 'viewer', a, canonical)
          await manager.deny(u, 'viewer', a, canonical)
          const runs: Array<[string, () => Promise<unknown>]> = [
            ['check', () => manager.check(u, 'viewer', a, alias)],
            ['checkMany', () => manager.checkMany(u, 'viewer', [a], alias)],
            ['decideMany', () => manager.decideMany(u, 'viewer', [a], alias)],
            ['listObjects', () => manager.listObjects(u, 'viewer', 'document', alias)],
            ['deny', () => manager.deny(u, 'viewer', a, alias)],
            ['removeDeny', () => manager.removeDeny(u, 'viewer', a, alias)],
            ['listDenies', () => manager.listDenies('viewer', a, alias)],
          ]
          for (const [op, run] of runs) {
            const caught = await run().then((r) => ({ answered: r }), (e) => e)
            assert.equal(caught?.code, 'E_AUTHZ_INVALID_IDENTITY', `${op} por el alias: ${JSON.stringify(caught?.answered ?? caught?.message)}`)
          }
          assert.isFalse(await manager.check(u, 'viewer', a, canonical), 'el deny sigue en la canónica')
        })

        test('M6 · el deny TRANSPORTADO por una membresía de grupo con caducidad: viva ⇒ deny (check F, decideMany deny); caducada ⇒ el allow vuelve (check T, decideMany allow); S13: un solo now por lote en decideMany', async ({ assert }) => {
          const config = contractDenyRelationsConfig()
          const base = await harness.makeDriver(config)
          const u = holder()
          const g = { type: 'group', id: docId() }
          const a = { type: 'document', id: docId() }
          const p = partition()
          if (harness.capabilities.injectableClock) {
            const T = new Date('2031-03-03T03:03:03.303Z')
            const clock = fixedClock(new Date(T.getTime() - 60_000))
            const m = new RelationsManager(base.withClock!(clock.now), config)
            await m.relate(u, 'viewer', a, p)
            await m.relate(u, 'member', g, p, { expiresAt: T })
            await m.deny({ object: g, relation: 'member' }, 'viewer', a, p)
            clock.set(new Date(T.getTime() - 1))
            assert.isFalse(await m.check(u, 'viewer', a, p), 'T−1 ms: la membresía viva transporta el deny')
            assert.deepEqual(await m.decideMany(u, 'viewer', [a], p), ['deny'])
            clock.set(T)
            assert.isTrue(await m.check(u, 'viewer', a, p), 'T: la membresía caducó y el allow vuelve')
            assert.deepEqual(await m.decideMany(u, 'viewer', [a], p), ['allow'])
            // S13 · UN solo `now` por lote también en decideMany (el patrón A-18): un reloj que AVANZA 1 ms por lectura
            // y tres allows que caducan en T3+1, T3+2, T3+3 ⇒ las tres `allow` y el reloj se lee UNA vez.
            const T3 = new Date('2031-04-04T00:00:00.000Z')
            const setup = new RelationsManager(base.withClock!(fixedClock(T3).now), config)
            const batch = holder()
            const docs = [docId(), docId(), docId()].map((id) => ({ type: 'document', id }))
            for (const [i, d] of docs.entries()) await setup.relate(batch, 'viewer', d, p, { expiresAt: new Date(T3.getTime() + i + 1) })
            let reads = 0
            const ticking = new RelationsManager(base.withClock!(() => new Date(T3.getTime() + reads++)), config)
            assert.deepEqual(await ticking.decideMany(batch, 'viewer', [...docs, ...docs], p), ['allow', 'allow', 'allow', 'allow', 'allow', 'allow'])
            assert.equal(reads, 1, 'S13: decideMany leyó el reloj EXACTAMENTE una vez para todo el lote')
            return
          }
          const m = new RelationsManager(base, config)
          await m.relate(u, 'viewer', a, p)
          await m.relate(u, 'member', g, p, { expiresAt: new Date(Date.now() + 1_500) })
          await m.deny({ object: g, relation: 'member' }, 'viewer', a, p)
          assert.isFalse(await m.check(u, 'viewer', a, p), 'viva: el deny viaja por la membresía')
          await sleep(1_700)
          assert.isTrue(await m.check(u, 'viewer', a, p), 'caducada: el allow vuelve')
        })
      },
      whenFalse: () =>
        test('relationDenies:false · D-28 · deny/removeDeny/listDenies/decideMany ⇒ 500 E_AUTHZ_UNSUPPORTED nombrándolos, con CERO llamadas al driver y CERO eventos; F-05 va antes (un role_binding sigue siendo 422)', async ({ assert }) => {
          const p = partition()
          const u = holder()
          const a = { type: 'document', id: docId() }
          const runs: Array<[string, () => Promise<unknown>]> = [
            ['deny', () => state.manager.deny(u, 'viewer', a, p)],
            ['removeDeny', () => state.manager.removeDeny(u, 'viewer', a, p)],
            ['listDenies', () => state.manager.listDenies('viewer', a, p)],
            ['decideMany', () => state.manager.decideMany(u, 'viewer', [a], p)],
          ]
          for (const [op, run] of runs) {
            const caught = await run().then(() => null, (e) => e)
            assert.equal(caught?.status, 500, `${op}: ${caught?.message}`)
            assert.equal(caught?.code, 'E_AUTHZ_UNSUPPORTED')
            assert.include(String(caught?.message), op)
          }
          const typed = await state.manager.deny(u, 'assignee', { type: 'role_binding', id: docId() }, p).then(() => null, (e) => e)
          assert.equal(typed?.code, 'E_AUTHZ_RELATION_TYPE_UNKNOWN', 'F-05 antes que la capacidad')
          assert.equal(state.calls(), 0, 'CERO llamadas al driver')
          assert.lengthOf(state.events, 0, 'CERO eventos')
        }),
    })

    // Al cerrar: toda capacidad declarada tiene que haber registrado su cara.
    group.teardown(async () => {
      const uncovered = (Object.keys(harness.capabilities) as (keyof RelationsDriverCapabilities)[]).filter(
        (c) => !covered.has(c)
      )
      if (uncovered.length) {
        throw new Error(
          `[contrato ${harness.name}] no cubrió ${uncovered.join(', ')}: cada capacidad necesita su caso.`
        )
      }
    })
  })

  return { registered, covered }
}
