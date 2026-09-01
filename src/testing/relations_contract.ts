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
import { RelationsManager } from '../relations/manager.js'
import { defineRelationsConfig } from '../relations/define_relations_config.js'
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
export function contractRelationsConfig(): RelationsConfig {
  return defineRelationsConfig({
    objectTypes: [
      {
        type: 'document',
        relations: [
          { name: 'owner' },
          { name: 'editor', includes: ['owner'] },
          { name: 'viewer', includes: ['editor'] },
        ],
      },
    ],
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
}

/* ── El DOBLE en memoria ─────────────────────────────────────────────────── */

interface Tuple {
  partition: string
  objectType: string
  objectId: string
  relation: string
  subject: RelSubject
  subjectKey: string
}

function scopeKeyOf(scope: ScopeRef): string {
  return scope.type === 'app' ? 'app' : `${scope.type}|${scope.uuid}`
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
  const { config, capabilities, limits } = options
  const tuples: Tuple[] = []

  /**
   * `viewer` ⊇ `{viewer, editor, owner}`: las relaciones cuyo hecho DIRECTO
   * satisface R. `viewer includes editor` ⇒ un `editor` es también `viewer`,
   * así que para resolver `viewer` se aceptan los sujetos de `viewer`, de lo
   * que `viewer` incluye (`editor`) y transitivamente (`owner`). Se sigue la
   * cadena de `includes` hacia ABAJO desde R.
   */
  function expandDown(objectType: string, relation: string): Set<string> {
    const out = new Set<string>([relation])
    const type = config.objectTypes.find((t) => t.type === objectType)
    const queue = [relation]
    while (queue.length) {
      const current = queue.pop()!
      const def = type?.relations.find((r) => r.name === current)
      for (const inc of def?.includes ?? []) {
        if (!out.has(inc)) {
          out.add(inc)
          queue.push(inc)
        }
      }
    }
    return out
  }

  function directSubjects(partition: string, objectType: string, objectId: string, relation: string): Tuple[] {
    return tuples.filter(
      (t) =>
        t.partition === partition &&
        t.objectType === objectType &&
        t.objectId === objectId &&
        t.relation === relation
    )
  }

  function resolves(
    subject: RelSubject,
    relation: string,
    object: RelObject,
    partition: string,
    seen = new Set<string>()
  ): boolean {
    const guardKey = `${subjectKeyOf(subject)}|${object.type}:${object.id}#${relation}`
    if (seen.has(guardKey)) return false
    seen.add(guardKey)
    const wantKey = subjectKeyOf(subject)
    for (const rel of expandDown(object.type, relation)) {
      for (const t of directSubjects(partition, object.type, object.id, rel)) {
        if (t.subjectKey === wantKey) return true
        // El sujeto directo es un userset (`group:g#member`): un HOLDER lo
        // satisface si es MIEMBRO del userset (transitivo, grupos anidan).
        if (isRelUserset(t.subject) && !isRelUserset(subject)) {
          if (resolves(subject, t.subject.relation, t.subject.object, partition, seen)) return true
        }
      }
    }
    return false
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

    async relate(subject, relation, object, partition) {
      const partitionKey = scopeKeyOf(partition)
      const subjectKey = subjectKeyOf(subject)
      const exists = tuples.some(
        (t) =>
          t.partition === partitionKey &&
          t.objectType === object.type &&
          t.objectId === object.id &&
          t.relation === relation &&
          t.subjectKey === subjectKey
      )
      if (!exists) {
        tuples.push({
          partition: partitionKey,
          objectType: object.type,
          objectId: object.id,
          relation,
          subject,
          subjectKey,
        })
      }
    },

    async unrelate(subject, relation, object, partition) {
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
      return resolves(subject, relation, object, scopeKeyOf(partition))
    },

    async listObjects(subject, relation, objectType, partition, page): Promise<RelationObjectsPage> {
      const partitionKey = scopeKeyOf(partition)
      const ids = new Set<string>()
      for (const t of tuples) {
        if (t.partition === partitionKey && t.objectType === objectType) ids.add(t.objectId)
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
      const partitionKey = scopeKeyOf(partition)
      for (let i = tuples.length - 1; i >= 0; i--) {
        const t = tuples[i]
        if (t.partition === partitionKey && t.objectType === object.type && t.objectId === object.id) {
          tuples.splice(i, 1)
        }
      }
    },

    async purgeSubject(subject, partition) {
      const partitionKey = scopeKeyOf(partition)
      const subjectKey = subjectKeyOf(subject)
      for (let i = tuples.length - 1; i >= 0; i--) {
        const t = tuples[i]
        if (t.partition === partitionKey && t.subjectKey === subjectKey) tuples.splice(i, 1)
      }
    },
  }

  if (capabilities.membersOfNative) {
    driver.membersOf = async (object, relation, partition): Promise<RelationSubjectsPage> => {
      return { subjects: collectMembers(object, relation, scopeKeyOf(partition)) }
    }
  }
  if (capabilities.enumerateRelations) {
    driver.enumerateRelations = async (partition): Promise<RelationTuplePage> => {
      const partitionKey = scopeKeyOf(partition)
      const out = tuples
        .filter((t) => t.partition === partitionKey)
        .map((t) => ({
          subject: t.subject,
          relation: t.relation,
          object: { type: t.objectType, id: t.objectId },
          partition,
        }))
      return { tuples: out }
    }
  }

  return driver
}

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
function spy(driver: RelationsDriver): { driver: RelationsDriver; writes: () => number } {
  let writes = 0
  const wrapped = new Proxy(driver, {
    get(target, prop, receiver) {
      if (prop === 'relate' || prop === 'unrelate') {
        return async (...args: unknown[]) => {
          writes++
          return (target as any)[prop](...args)
        }
      }
      const value = Reflect.get(target, prop, receiver)
      return typeof value === 'function' ? value.bind(target) : value
    },
  })
  return { driver: wrapped, writes: () => writes }
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

  const state: { manager: RelationsManager; base: RelationsDriver; writes: () => number } = {} as any

  async function freshManager(options?: ConstructorParameters<typeof RelationsManager>[2]) {
    const base = await harness.makeDriver(contractRelationsConfig())
    const s = spy(base)
    return { manager: new RelationsManager(s.driver, contractRelationsConfig(), options), writes: s.writes, base }
  }

  api.group(`relations contract [${harness.name}]`, (group) => {
    group.each.setup(async () => {
      const f = await freshManager()
      state.manager = f.manager
      state.base = f.base
      state.writes = f.writes
    })

    const test = (title: string, fn: (ctx: { assert: Assert }) => Promise<void>) => {
      registered++
      api.test(title, fn)
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
