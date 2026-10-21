/**
 * **Guardia de superficie L1** (plan 2.5 · lote 0 y su cierre; CLAUDE.md «Cómo se decide un cambio» punto 6;
 * `linajes.md` L1: el punto de paso único de F-05 ES esta guardia).
 *
 * Qué hace: enumera POR REFLEXIÓN la superficie de `RelationsManager`, `DatabaseRelationsDriver` y
 * `OpenFgaRelationsDriver` —toda la cadena de prototipos, los campos de instancia que son funciones (arrow
 * como campo de clase) y los estáticos (cierre 🟡 3)—, sus vistas `withClock` (H11), las operaciones del doble
 * publicado `makeRelationsDriver` (D13), lo que sale por `exports` (por IDENTIDAD, ⚪ 9) y lo que construye el
 * provider (`buildRelationsManager`, 🟡 6), y exige que cada operación tenga su fila en
 * `tests/fixtures/guard_manifest.ts` (G-0). Después corre UNA sonda por celda `probe` de la tabla
 * «operaciones × {F-05, puerta trx, freeze, `#write` (timeout Y parcial, 🟡 5), actor, partición canónica}»,
 * comprueba que las lecturas no escriben ni notifican invocando TODOS los métodos del manager y de los drivers
 * (G-R, 🟠 2), cruza la tabla con el manifiesto de mutantes (G-M: cada celda con sonda tiene ≥ 1 mutante cuyo
 * `find` casa exactamente una vez; toda celda `na` está admitida por la matriz cerrada `NA_MATRIX`, 🟠 2) y que
 * las exenciones son EXACTAMENTE las cinco firmadas por el dueño, atadas a capa×columna y leídas del extracto
 * VERSIONADO `tests/fixtures/exemptions_d6.json` (G-X, 🟠 1 / 🟡 4; en local se cruza además con el párrafo D6
 * del fichero de decisiones, que está fuera de git).
 *
 * Un método nuevo sin fila ⇒ rojo con su nombre. Una fila sin método ⇒ rojo. Una celda sin mutante ⇒ rojo.
 * Una sonda F-05 sin variantes ⇒ rojo (🟡 7). Una fila nueva NO entra tocando solo el manifiesto: necesita su
 * entrada en `INVOKE` y en `F05_VARIANTS` de este spec y sus mutantes.
 * El corredor `scripts/check_guard_mutants.mjs` aplica cada mutante en una copia del árbol y exige que se
 * ponga rojo EL caso nombrado (`expectRed`), no cualquiera.
 *
 * Va dentro de `bootApp()` (medido por el tester, §0): el manager y el driver `database` no se importan sin la
 * app arrancada (`@adonisjs/lucid/services/db`, vía `src/freeze.ts`).
 */
import { test } from '@japa/runner'
import { bruteForce, bruteForceVigencia, ORDER_CUTS, packageOrder, pick, walkPair, walkVigencia } from './helpers/order_bruteforce.js'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { types as utilTypes } from 'node:util'
import { v7 as uuidv7 } from 'uuid'
import { Container } from '@adonisjs/fold'
import db from '@adonisjs/lucid/services/db'
import AuthzProvider from '../providers/authz_provider.js'
import { KNOWN_WRITE_OPTION_KEYS, RelationsManager } from '../src/relations/manager.js'
import type { RelationsManagerOptions } from '../src/relations/manager.js'
import { DatabaseRelationsDriver } from '../src/drivers/database_relations_driver.js'
import { MONOTONIC_CLOCK, OpenFgaRelationsDriver, purgeWrites } from '../src/drivers/openfga_relations_driver.js'
// Lote D · D1: la guardia sondea TODA la superficie con la config del contrato CON deny (`document` en fase 'write'):
// las celdas de antes (relate/check… sobre `document`) pasan ahora también por el corte de camino y la guarda del
// modelo (D-31), y las del deny tienen un tipo denegable que sondear.
import { makeRelationsDriver, contractDenyRelationsConfig as contractRelationsConfig } from '../src/testing/relations_contract.js'
import { openFgaFactsModel, factsModelDifferences } from '../src/drivers/openfga_facts.js'
import { fgaTupleExpiry } from '../src/expiry.js'
import http from 'node:http'
import OpenFgaProvision from '../commands/openfga_provision.js'
import { aceFor } from './helpers/ace.js'
import { TEST_MODEL_ID, generatedModel } from './helpers/fga_model.js'
import { AuthorizationManager } from '../src/manager.js'
import { OpenFgaAuthorizationDriver } from '../src/drivers/openfga_driver.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { buildRelationsManager } from '../providers/authz_provider.js'
import { AuthorizationBackendError, AuthorizationBackendTimeoutError, AuthorizationConfigError, isDeploymentFailure, isPartialWrite, isTransientRelayFailure, markPartialWrite } from '../src/errors.js'
import { classifyFgaFailure, fgaFailureError, isTimeoutLike } from '../src/shared/backend_guard.js'
import { FgaRequiredParamError } from '@openfga/sdk'
import { alignBatchResults, isDuplicateWrite } from '../src/drivers/openfga_driver.js'
import {
  FGA_FIXTURE_CLASS,
  FGA_ITEM_CLASS,
  FGA_PUBLIC_ERROR,
  POISONED_MESSAGES,
  assertFixtureShape,
  fgaErrorFromFixture,
  loadFgaFixtures,
  throwingFgaFixtures,
} from './helpers/fga_fixtures.js'
import { countQueries } from './helpers/spies.js'
import { TupleStore, checkTuples, compileModel, impossibleTrues } from './helpers/fga_interpreter.js'
import { FgaMemoryStore, installMemoryClient, sdkError } from './helpers/fga_memory_client.js'
import type { WriteStep } from './helpers/fga_interpreter.js'
import { memoryScopeTree, resolveChainFrom } from '../src/testing/main.js'
import {
  factsBindingObject,
  factsBindingTuples,
  factsCatalogTuples,
  factsDenyTuple,
  factsParentTuple,
  factsRootTuples,
  factsScopeObject,
} from '../src/drivers/openfga_facts.js'
import { APP_SCOPE } from '../src/types.js'
import { reconcileRelations } from '../src/relations/reconcile.js'
import { defineRelationsConfig } from '../src/relations/define_relations_config.js'
import type { RelationsDriver, RelationsDriverCapabilities, ScopeRef, SubjectRef } from '../src/types.js'
import {
  GUARD_MANIFEST,
  GUARD_COLUMNS,
  GUARD_PROPERTIES,
  PORT_OPERATIONS,
  PORT_WRITES,
  PORT_READS,
  PLATFORM_OPERATIONS,
  VIEW_OPERATIONS,
  NA_MATRIX,
  F05_NA_OPERATIONS,
  NON_SURFACE_CLASSES,
  NON_SURFACE_FUNCTIONS,
  SIGNED_EXEMPTIONS,
  NA_REASONS,
  DASHLESS_PARTITION,
  row,
  cellTitle,
  cellId,
  FGA_MESSAGE_READ_EXEMPT,
} from './fixtures/guard_manifest.js'
import type {
  ExemptionExtractEntry,
  GuardCell,
  GuardColumn,
  GuardLayer,
  GuardMutant,
  GuardRow,
  NaRule,
  SignedExemption,
} from './fixtures/guard_manifest.js'

const TYPE_UNKNOWN = 'E_AUTHZ_RELATION_TYPE_UNKNOWN'
const REL_UNKNOWN = 'E_AUTHZ_RELATION_UNKNOWN'
/** Lote B · B3: un userset DECLARADO que no es `group#member` como sujeto (la fila inerte / el 400 del servidor). */
const USERSET_UNSUPPORTED = 'E_AUTHZ_RELATION_USERSET_UNSUPPORTED'
/**
 * **`WRITES` NO es una lista a mano** (cierre-2, 🟡 E): se DERIVA de la clasificación obligatoria del manifiesto
 * (`PORT_WRITES`/`PORT_READS`), que el caso «G-R · clasificación obligatoria» cruza con el inventario por reflexión
 * (una operación en ninguna lista ⇒ rojo con su nombre), con el COMPORTAMIENTO de los drivers (una escritura ejecuta
 * INSERT/UPDATE/DELETE en `database` y `write`/`deleteTuples` en `openfga`; una lectura, no) y con el `kind` de cada fila.
 */
const WRITES = new Set<string>(PORT_WRITES)
const TEST_TIMEOUT = 20_000
const ROOT = fileURLToPath(new URL('../', import.meta.url))
const EXTRACT_PATH = `${ROOT}tests/fixtures/exemptions_d6.json`
const DECISIONS_PATH = `${ROOT}.claude/contexto/decisiones-dueno-2026-08-28.md`
const CLAUDE_MD_PATH = `${ROOT}CLAUDE.md`
/** La frase del LÍMITE DECLARADO (cierre-2, 🟡 D): tiene que estar en la cabecera del extracto Y en CLAUDE.md (punto 6). */
const DECLARED_LIMIT = 'en CI y en los worktrees no hay fichero de decisiones'
/** Las CINCO exenciones firmadas en D6 (2026-10-14): ni una más, ni una menos (G-X, cierre 🟡 4). */
const FIVE_SIGNED = ['D6-driver', 'D6-capabilities', 'D6-enumerateRelations', 'D6-enumerateRelationsMany', 'D6-membersOf-openfga'] as const
const SIGNED_AT = '2026-10-14'

const FULL: RelationsDriverCapabilities = {
  singleCheckRelations: true,
  listObjectsInherited: false,
  usersetSubjects: true,
  membersOfNative: true,
  enumerateRelations: true,
  listObjectsTruncation: false,
  injectableClock: true,
  transactionalWrites: false,
  relationDenies: true,
  // Cierre 2 de D2 · 🟠 N1: la clave nueva (D15: opcional, normalizada a `false`); el doble con `false` NIEGA renovar una
  // membresía que transporta un deny, como `openfga`.
  atomicRenewal: false,
}

function rows(layer: GuardLayer): GuardRow[] {
  return GUARD_MANIFEST.filter((r) => r.layer === layer)
}

/* ── Entradas por operación y variante ──────────────────────────────────── */

type Variant = 'valid' | 'type' | 'relation' | 'undefined' | 'userset' | 'usersetUnsupported' | 'badPartition' | 'dashless' | 'misdashed' | 'noOptIn' | 'readPhase' | 'groupDeny'

const U: SubjectRef = { type: 'user', uuid: uuidv7() }
const P: ScopeRef = { type: 'unit', uuid: uuidv7() }
/** Una segunda partición VÁLIDA: en `*Many` va en la posición 0 para que la mala NUNCA sea `[0]` (cierre ⚪ 8). */
const P2: ScopeRef = { type: 'unit', uuid: uuidv7() }
/** Gramática rota (`#` y mayúsculas): lo que `assertScope` corta hoy. */
const BAD: ScopeRef = { type: 'unit', uuid: 'A#B' }
/** D4: uuid canónico escrito SIN guiones (32 hex). Desde el lote A ⇒ 422 en toda operación con partición. */
const DASHLESS: ScopeRef = { type: 'unit', uuid: uuidv7().replace(/-/g, '') }
/** 🟠 A2 (cierre del lote A): los MISMOS 32 hex con otra colocación de guiones (`8-4-4-16`, lo que PG funde) ⇒ el mismo 422. */
const MISDASHED: ScopeRef = { type: 'unit', uuid: `${DASHLESS.uuid!.slice(0, 8)}-${DASHLESS.uuid!.slice(8, 12)}-${DASHLESS.uuid!.slice(12, 16)}-${DASHLESS.uuid!.slice(16)}` }
/** Las dos formas no canónicas que la columna `partition` sondea en cada celda (D4 + A2). */
const NON_CANONICAL: Array<['dashless' | 'misdashed', ScopeRef, string]> = [
  ['dashless', DASHLESS, 'uuid sin guiones (D4)'],
  ['misdashed', MISDASHED, 'guiones mal colocados 8-4-4-16 (A2)'],
]
const DOC = { type: 'document', id: uuidv7() }
const GROUP = { type: 'group', id: uuidv7() }
const BINDING = { type: 'role_binding', id: uuidv7() }

// B3: `document#viewer` pasa F-05 (tipo y relación DECLARADOS) y NO es `group#member`: la variante que separa la guarda nueva de F-05.
const subj = (v: Variant) => (v === 'userset' ? { object: BINDING, relation: 'assignee' } : v === 'usersetUnsupported' ? { object: DOC, relation: 'viewer' } : U)
const rel = (v: Variant) => (v === 'relation' || v === 'type' ? 'assignee' : v === 'undefined' ? (undefined as any) : v === 'groupDeny' ? 'member' : 'viewer')
/** Cierre 1 de D1 · 🟡 2 (columna `denyable`): tipo sin opt-in, tipo en fase 'read' y `group` — los tres pasan F-05. */
const NOTE = { type: 'note', id: uuidv7() }
const WORKSPACE = { type: 'workspace', id: uuidv7() }
const obj = (v: Variant) => (v === 'type' ? BINDING : v === 'noOptIn' ? NOTE : v === 'readPhase' ? WORKSPACE : v === 'groupDeny' ? GROUP : DOC)
const objType = (v: Variant) => (v === 'type' ? 'role_binding' : 'document')
const part = (v: Variant) => (v === 'badPartition' ? BAD : v === 'dashless' ? DASHLESS : v === 'misdashed' ? MISDASHED : P)

/** Cómo se invoca cada operación con una variante de entrada. `options` solo lo reciben las escrituras. */
const INVOKE: Record<string, (t: any, v: Variant, options?: any) => Promise<unknown>> = {
  relate: (t, v, o) => t.relate(subj(v), rel(v), obj(v), part(v), o),
  unrelate: (t, v, o) => t.unrelate(subj(v), rel(v), obj(v), part(v), o),
  check: (t, v) => t.check(subj(v), rel(v), obj(v), part(v)),
  // Plan 2.5 · lote A (A-13, P4-6): F-05 es POR ÍTEM — la variante va en la posición 1, nunca en `[0]` (⚪ 8).
  // Con la variante `type` la relación es `viewer` (declarada para DOC, el [0]): así el role_binding de [1] es lo
  // ÚNICO que falla, con TYPE_UNKNOWN, y «validar solo objects[0]» no lo ve (mutante `manager.checkMany.f05.first-only`).
  checkMany: (t, v) => t.checkMany(subj(v), v === 'type' ? 'viewer' : rel(v), [DOC, obj(v)], part(v)),
  listObjects: (t, v) => t.listObjects(subj(v), rel(v), objType(v), part(v)),
  listSubjects: (t, v) => t.listSubjects(rel(v), obj(v), part(v)),
  membersOf: (t, v) =>
    v === 'type' || v === 'relation' || v === 'undefined'
      ? t.membersOf(obj(v), rel(v), part(v))
      : t.membersOf(GROUP, 'member', part(v)),
  // Lote D · D1: el deny tiene la forma de `relate` (sin caducidad), `listDenies` la de `listSubjects` y `decideMany`
  // la de `checkMany` (F-05 POR ÍTEM: la variante en la posición 1, nunca en [0]).
  deny: (t, v, o) => t.deny(subj(v), rel(v), obj(v), part(v), o),
  removeDeny: (t, v, o) => t.removeDeny(subj(v), rel(v), obj(v), part(v), o),
  listDenies: (t, v) => t.listDenies(rel(v), obj(v), part(v)),
  decideMany: (t, v) => t.decideMany(subj(v), v === 'type' ? 'viewer' : rel(v), [DOC, obj(v)], part(v)),
  // Lote D · D2: la pregunta del plan del reconcile (fase del opt-in del tipo; config del driver, sin partición).
  denyPhase: (t, v) => t.denyPhase(obj(v), rel(v)),
  // Lote «antes de RC» · R1: el techo de anidación del driver (sin argumentos: la variante no entra).
  groupDepthLimit: (t) => t.groupDepthLimit(),
  purgeObject: (t, v, o) => t.purgeObject(obj(v), part(v), o),
  purgeSubject: (t, v, o) =>
    t.purgeSubject(
      v === 'userset' ? { object: BINDING, relation: 'role' } : v === 'usersetUnsupported' ? { object: DOC, relation: 'viewer' } : v === 'undefined' ? { object: DOC, relation: undefined } : U,
      part(v),
      o
    ),
  enumerateRelations: (t, v) => t.enumerateRelations(part(v)),
  // ⚪ 8: SIEMPRE ≥ 2 particiones y la variante en la posición 1 — validar solo `partitions[0]` es rojo.
  enumerateRelationsMany: (t, v) => t.enumerateRelationsMany([P2, part(v)]),
  // Plataforma (D6): las sondas sustitutas también pasan por aquí, para que EJECUTEN la operación exenta (🟡 D).
  driver: async (t) => t.driver(),
  capabilities: async (t) => t.capabilities(),
}

/** La sonda de `op` invocó OTRO método (o ninguno): el caso es rojo diga lo que diga la aserción de después. */
class ProbeMisroutedError extends Error {}

/**
 * **La única puerta entre la fila y el método, vigilada** (cierre-2, 🟡 A): `INVOKE[op]` corre sobre un Proxy del
 * objetivo que registra qué propiedades toca, y tiene que haber accedido a `t[op]` —y a NINGÚN otro método del
 * objetivo—. Un copy-paste (`probeMany: (t, v) => t.check(…)`) dejaba verdes las celdas y G-R de la operación nueva
 * sondeando OTRA; ahora es rojo con los dos nombres. Las llamadas internas (`this.x` dentro del método) van sobre el
 * objetivo real (el método se liga a él), así que no cuentan: solo cuenta lo que la SONDA toca.
 */
async function probeInvoke(op: string, target: any, variant: Variant, options?: any, table: typeof INVOKE = INVOKE): Promise<unknown> {
  const fn = table[op]
  if (typeof fn !== 'function') throw new ProbeMisroutedError(`ROJO: no hay forma de invocar '${op}' — añade la entrada en INVOKE`)
  const touched: string[] = []
  const proxy = new Proxy(target, {
    get(t, prop) {
      if (typeof prop === 'string') touched.push(prop)
      const value = Reflect.get(t, prop, t)
      return typeof value === 'function' ? value.bind(t) : value
    },
  })
  try {
    return await fn(proxy, variant, options)
  } finally {
    const methods = [...new Set(touched)].filter((p) => typeof Reflect.get(target, p, target) === 'function')
    if (methods.length !== 1 || methods[0] !== op) {
      throw new ProbeMisroutedError(
        `ROJO (🟡 A · sonda mal enrutada): INVOKE.${op} tiene que invocar '${op}' y solo '${op}' sobre el objetivo, y tocó [${methods.join(', ') || 'ningún método'}] — ` +
          `una celda o un G-R que sondea OTRA operación no juzga nada`
      )
    }
  }
}

/** Variantes de F-05 por operación y el `code` exacto que cada una tiene que producir. */
const F05_VARIANTS: Record<string, Array<[Variant, string]>> = {
  // B3 (lote B): toda operación que recibe SUJETO lleva la variante `usersetUnsupported` (userset declarado ≠ group#member).
  relate: [['type', TYPE_UNKNOWN], ['relation', REL_UNKNOWN], ['undefined', REL_UNKNOWN], ['userset', TYPE_UNKNOWN], ['usersetUnsupported', USERSET_UNSUPPORTED]],
  unrelate: [['type', TYPE_UNKNOWN], ['relation', REL_UNKNOWN], ['undefined', REL_UNKNOWN], ['userset', TYPE_UNKNOWN], ['usersetUnsupported', USERSET_UNSUPPORTED]],
  check: [['type', TYPE_UNKNOWN], ['relation', REL_UNKNOWN], ['undefined', REL_UNKNOWN], ['userset', TYPE_UNKNOWN], ['usersetUnsupported', USERSET_UNSUPPORTED]],
  checkMany: [['type', TYPE_UNKNOWN], ['relation', REL_UNKNOWN], ['undefined', REL_UNKNOWN], ['userset', TYPE_UNKNOWN], ['usersetUnsupported', USERSET_UNSUPPORTED]],
  listObjects: [['type', TYPE_UNKNOWN], ['relation', REL_UNKNOWN], ['undefined', REL_UNKNOWN], ['userset', TYPE_UNKNOWN], ['usersetUnsupported', USERSET_UNSUPPORTED]],
  listSubjects: [['type', TYPE_UNKNOWN], ['relation', REL_UNKNOWN], ['undefined', REL_UNKNOWN]],
  membersOf: [['type', TYPE_UNKNOWN], ['relation', REL_UNKNOWN], ['undefined', REL_UNKNOWN]],
  purgeObject: [['type', TYPE_UNKNOWN]],
  purgeSubject: [['userset', TYPE_UNKNOWN], ['undefined', REL_UNKNOWN], ['usersetUnsupported', USERSET_UNSUPPORTED]],
  deny: [['type', TYPE_UNKNOWN], ['relation', REL_UNKNOWN], ['undefined', REL_UNKNOWN], ['userset', TYPE_UNKNOWN], ['usersetUnsupported', USERSET_UNSUPPORTED]],
  removeDeny: [['type', TYPE_UNKNOWN], ['relation', REL_UNKNOWN], ['undefined', REL_UNKNOWN], ['userset', TYPE_UNKNOWN], ['usersetUnsupported', USERSET_UNSUPPORTED]],
  listDenies: [['type', TYPE_UNKNOWN], ['relation', REL_UNKNOWN], ['undefined', REL_UNKNOWN]],
  decideMany: [['type', TYPE_UNKNOWN], ['relation', REL_UNKNOWN], ['undefined', REL_UNKNOWN], ['userset', TYPE_UNKNOWN], ['usersetUnsupported', USERSET_UNSUPPORTED]],
  denyPhase: [['type', TYPE_UNKNOWN], ['relation', REL_UNKNOWN], ['undefined', REL_UNKNOWN]],
}

/**
 * **Una sonda F-05 nunca está vacía** (cierre 🟡 7): una fila nueva con celda `f05: probe` y sin variantes
 * daba una sonda que no afirmaba nada y quedaba verde. Aquí es rojo con la receta.
 */
function f05VariantsOf(assert: any, label: string, op: string): Array<[Variant, string]> {
  const variants = F05_VARIANTS[op]
  assert.isTrue(
    Array.isArray(variants) && variants.length > 0,
    `ROJO (${label} · F-05): sonda F-05 VACÍA — la operación '${op}' no tiene variantes en F05_VARIANTS del spec; una fila nueva ` +
      `no entra tocando solo el manifiesto: añade sus variantes (tipo/relación/undefined/userset con el code exacto)`
  )
  return variants ?? []
}

async function catching(run: () => Promise<unknown>): Promise<any> {
  return run().then(
    () => null,
    (e) => {
      if (e instanceof ProbeMisroutedError) throw e
      return e
    }
  )
}

/**
 * **Columna `denyable`** (cierre 1 de D1, 🟡 2): las tres entradas que la puerta de ESCRITURA del opt-in tiene que
 * cortar —tipo sin opt-in, fase `'read'`, `group`—, todas DECLARADAS (pasan F-05) y con partición válida.
 */
const NOT_DENYABLE_VARIANTS: Array<['noOptIn' | 'readPhase' | 'groupDeny', string]> = [
  ['noOptIn', "tipo sin opt-in ('note')"],
  ['readPhase', "tipo en fase 1 ('workspace', deny: 'read')"],
  ['groupDeny', "'group' (built-in)"],
]
const NOT_DENYABLE = 'E_AUTHZ_RELATION_NOT_DENYABLE'

function expectError(assert: any, caught: any, status: number, code: string, label: string): void {
  assert.isNotNull(caught, `ROJO (${label}): la operación ENTRÓ (no lanzó)`)
  assert.equal(caught?.status, status, `${label}: ${caught?.message}`)
  assert.equal(caught?.code, code, `${label}: ${caught?.message}`)
}

/* ── Capa MANAGER: RelationsManager sobre un driver espía, por las DOS vías de construcción ── */

/**
 * Un Proxy (no un spread: los métodos de prototipo se perderían) que cuenta cada llamada al driver por nombre
 * de operación del puerto y, si se pide, hace fallar una operación como el caso necesite.
 */
function spiedDouble(failing: Record<string, () => Error> = {}) {
  const base = makeRelationsDriver({ config: contractRelationsConfig(), capabilities: FULL })
  const log: string[] = []
  const driver = new Proxy(base, {
    get(target, prop, receiver) {
      if (typeof prop === 'string' && (PORT_OPERATIONS as readonly string[]).includes(prop)) {
        const fn = (target as any)[prop]
        if (typeof fn !== 'function') return fn
        return async (...args: unknown[]) => {
          log.push(prop)
          const fail = failing[prop]
          if (fail) throw fail()
          return fn.apply(target, args)
        }
      }
      const value = Reflect.get(target, prop, receiver)
      return typeof value === 'function' ? value.bind(target) : value
    },
  }) as RelationsDriver
  return { base, driver, log, calls: () => log.length, writes: () => log.filter((op) => WRITES.has(op)).length }
}

type ManagerBuild = (driver: RelationsDriver, options: RelationsManagerOptions) => Promise<RelationsManager>

/**
 * **Las filas `manager` se sondean por las DOS vías de construcción** (cierre 🟡 6): `new RelationsManager`
 * y lo que devuelve el provider (`buildRelationsManager`, lo que el contenedor sirve como `authz.relations`).
 * Un envoltorio del provider (subclase, Proxy) que saltara a `driver()` cumpliría `instanceOf` y la identidad
 * del driver —lo único que afirmaba el caso «el servicio»— y escribiría `role_binding` sin F-05; sondeado,
 * nace rojo en cada celda de la fila.
 */
function serviceConfig(driver: RelationsDriver, options: RelationsManagerOptions): any {
  return {
    default: 'database',
    drivers: {},
    warnOnOptInSecurity: false,
    relations: {
      config: contractRelationsConfig(),
      drivers: { database: () => driver },
      requireActor: options.requireActor,
      assertWrite: options.assertWrite,
      onRelationWrite: options.onRelationWrite,
    },
  }
}

/**
 * **Lo que SIRVE el contenedor** (cierre-2, 🟡 B): el provider REAL (`AuthzProvider.register()`) registra sus
 * singletons en un `Container` de `@adonisjs/fold` con una `app` mínima que devuelve este config, y se resuelve
 * `container.make('authz.relations')` — exactamente lo que `services/relations.ts` hace al arrancar. Hasta el
 * cierre-2 se sondeaba `buildRelationsManager` a secas, y un envoltorio en el CLOSURE del contenedor
 * (`providers/authz_provider.ts`, `singleton('authz.relations', …)`) no lo veía ninguna celda.
 */
async function resolveService(config: any, provider: new (app: any) => { register(): void } = AuthzProvider): Promise<RelationsManager> {
  const container = new Container()
  const app = { container, config: { get: (key: string) => (key === 'authorization' ? config : undefined) } }
  new provider(app).register()
  return container.make('authz.relations') as Promise<RelationsManager>
}

/** G-0 «el servicio», como función PURA sobre lo resuelto: prototipo EXACTO, no Proxy, mismo inventario que la clase. */
function serviceViolations(resolved: unknown): string[] {
  const out: string[] = []
  if (!(resolved instanceof RelationsManager)) return [`lo que sirve el contenedor como authz.relations no es un RelationsManager (${String(resolved)})`]
  if (utilTypes.isProxy(resolved)) out.push('lo que sirve el contenedor es un Proxy de RelationsManager (puede servir cualquier nombre sin tenerlo)')
  if (Object.getPrototypeOf(resolved) !== RelationsManager.prototype) {
    out.push(`lo que sirve el contenedor es un ENVOLTORIO (subclase ${Object.getPrototypeOf(resolved)?.constructor?.name ?? '?'}) de RelationsManager: no es la clase que las filas juzgan`)
  }
  const extra = surfaceOperations(resolved.constructor as Function, resolved).filter((n) => !rows('manager').some((r) => r.operation === n))
  if (extra.length) out.push(`lo que sirve el contenedor expone operaciones sin fila: ${extra.join(', ')}`)
  return out
}

const MANAGER_BUILDS: Array<[string, ManagerBuild]> = [
  ['new RelationsManager', async (driver, options) => new RelationsManager(driver, contractRelationsConfig(), options)],
  ['buildRelationsManager (provider)', (driver, options) => buildRelationsManager(serviceConfig(driver, options))],
  // 🟡 B: lo que el CONTENEDOR sirve, por el closure real del provider.
  ["container.make('authz.relations') (AuthzProvider.register)", (driver, options) => resolveService(serviceConfig(driver, options))],
]

async function managerOver(build: ManagerBuild, spy: ReturnType<typeof spiedDouble>, options: RelationsManagerOptions = {}) {
  const events: any[] = []
  const manager = await build(spy.driver, {
    onRelationWrite: (e) => void events.push(e),
    ...options,
  })
  return { manager, events }
}

const directBuild = MANAGER_BUILDS[0][1]

function rolesManager(): AuthorizationManager {
  return new AuthorizationManager({
    default: 'database',
    drivers: { database: () => new DatabaseAuthorizationDriver({}) },
    holderTypes: { users: 'user' },
    warnOnOptInSecurity: false,
  } as any)
}

/** Una fila `authz_relations` de holder (sin userset: el trigger de partición no la mira). */
function relationRow(partition: ScopeRef, objectType: string) {
  return {
    uuid: uuidv7(),
    partition_key: `${partition.type}|${partition.uuid}`,
    object_type: objectType,
    object_uuid: uuidv7(),
    relation: objectType === 'document' ? 'viewer' : 'assignee',
    subject_type: 'user',
    subject_uuid: uuidv7(),
    subject_relation: '',
    subject_partition: null,
    created_at: new Date(),
  }
}

const WHITELIST_OPERATIONS = ['enumerateRelations', 'enumerateRelationsMany']

/** La sonda sustituta `whitelist` SOLO vale para las enumeraciones (cierre-2, 🟡 D): sobre otra operación es rojo, no un pase. */
function assertWhitelistOp(assert: any, label: string, op: string): void {
  assert.include(
    WHITELIST_OPERATIONS,
    op,
    `ROJO (${label} · 🟡 D): la sonda 'whitelist' es la de la lista blanca de ${WHITELIST_OPERATIONS.join('/')}; '${op}' no es una enumeración y una exención sobre ella no tiene sonda que la justifique`
  )
}

/**
 * La sonda de LISTA BLANCA (exención D6 de `enumerateRelations(Many)`): una fila `role_binding` sembrada en `P` no
 * sale. **Ejecuta LA operación exenta** (cierre-2, 🟡 D): por `probeInvoke(op)`, que exige que la sonda toque `op`.
 */
async function probeWhitelistSql(assert: any, target: any, label: string, op: string): Promise<void> {
  assertWhitelistOp(assert, label, op)
  await db.table('authz_relations').multiInsert([relationRow(P, 'document'), relationRow(P, 'role_binding')])
  try {
    const page = (await probeInvoke(op, target, 'valid')) as { tuples: Array<{ object: { type: string } }> }
    assert.deepEqual(
      page.tuples.map((t) => t.object.type),
      ['document'],
      `ROJO (${label} · ${op}): la enumeración devuelve un tipo NO declarado (role_binding) — la lista blanca no filtra`
    )
  } finally {
    await db.from('authz_relations').where('partition_key', `${P.type}|${P.uuid}`).delete()
  }
}

async function probeManager(assert: any, r: GuardRow, column: GuardColumn, cell: GuardCell, builds = MANAGER_BUILDS): Promise<void> {
  const op = r.operation
  // 🟡 A: toda invocación pasa por el Proxy que exige que la sonda toque `op` (y solo `op`).
  const invoke = (t: any, v: Variant, o?: any) => probeInvoke(op, t, v, o)
  if ('exempt' in cell) {
    for (const [via, build] of builds) {
      const spy = spiedDouble()
      const { manager } = await managerOver(build, spy)
      if (cell.probe === 'identity') {
        assert.strictEqual(await invoke(manager, 'valid'), spy.driver, `[${via}] driver() devuelve el driver tal cual (salida documentada)`)
        continue
      }
      if (cell.probe === 'frozen-copy') {
        const caps = (await invoke(manager, 'valid')) as RelationsDriverCapabilities
        assert.isTrue(Object.isFrozen(caps), `[${via}] capabilities() es una copia congelada`)
        assert.deepEqual({ ...caps }, { ...FULL })
        continue
      }
      if (cell.probe === 'whitelist') {
        const real = await build(new DatabaseRelationsDriver(contractRelationsConfig(), { transactionalWrites: false }), {})
        await probeWhitelistSql(assert, real, `manager.${op} [${via}]`, op)
        continue
      }
      assert.fail(`sonda de exención desconocida para manager.${op}: ${cell.probe}`)
    }
    return
  }
  if (!('probe' in cell)) return
  assert.isFunction(INVOKE[op], `no hay forma de invocar manager.${op}: añade la entrada en INVOKE`)

  for (const [via, build] of builds) {
    const label = `manager.${op} [${via}]`
    if (column === 'f05') {
      for (const [variant, code] of f05VariantsOf(assert, label, op)) {
        const spy = spiedDouble()
        const { manager, events } = await managerOver(build, spy)
        const caught = await catching(() => invoke(manager, variant))
        expectError(assert, caught, 422, code, `${label} · F-05 · ${variant}`)
        assert.equal(spy.calls(), 0, `${label} · F-05 · ${variant}: CERO llamadas al driver`)
        assert.lengthOf(events, 0, `${label} · F-05 · ${variant}: CERO eventos`)
      }
      continue
    }
    if (column === 'trx') {
      const spy = spiedDouble()
      const { manager, events } = await managerOver(build, spy)
      const caught = await catching(() => invoke(manager, 'valid', { transaction: {} }))
      expectError(assert, caught, 500, 'E_AUTHZ_UNSUPPORTED', `${label} · puerta 1 de { transaction }`)
      assert.equal(spy.calls(), 0, `${label} · trx: CERO llamadas al driver`)
      assert.lengthOf(events, 0, `${label} · trx: CERO eventos`)
      continue
    }
    if (column === 'freeze') {
      const spy = spiedDouble()
      const { manager, events } = await managerOver(build, spy)
      const roles = rolesManager()
      const token = await roles.freeze(`guardia L1 · ${op}`)
      try {
        const frozen = await catching(() => invoke(manager, 'valid'))
        expectError(assert, frozen, 503, 'E_AUTHZ_FROZEN', `${label} · freeze`)
        assert.isTrue(frozen?.retryable, `${label} · freeze: reintentable`)
        // ORDEN (tester §4.3): la barrera va ANTES de F-05 — role_binding y congelado a la vez ⇒ 503, no 422.
        const [typeVariant] = F05_VARIANTS[op]?.[0] ?? []
        if (typeVariant) {
          const both = await catching(() => invoke(manager, typeVariant))
          expectError(assert, both, 503, 'E_AUTHZ_FROZEN', `${label} · freeze antes que F-05`)
        }
      } finally {
        await roles.unfreeze(token)
      }
      assert.equal(spy.calls(), 0, `${label} · freeze: CERO llamadas al driver`)
      assert.lengthOf(events, 0, `${label} · freeze: CERO eventos`)
      continue
    }
    if (column === 'write') {
      // Invariante 13, las DOS mitades (cierre 🟡 5): el deadline vencido Y la escritura PARCIAL marcada por el driver.
      const faces: Array<[string, () => Error, string]> = [
        ['deadline', () => new AuthorizationBackendTimeoutError('fake-relations', op, 5), 'E_AUTHZ_BACKEND_TIMEOUT'],
        ['parcial', () => markPartialWrite(new AuthorizationBackendError('fake-relations', op, new Error('cayó tras borrar parte'))), 'E_AUTHZ_BACKEND_UNAVAILABLE'],
      ]
      for (const [face, fail, code] of faces) {
        const spy = spiedDouble({ [op]: fail })
        const sequence: string[] = []
        const { manager, events } = await managerOver(build, spy, {
          onRelationWrite: (e: any) => {
            events.push(e)
            sequence.push(`event:${e.indeterminate === true}`)
          },
        })
        const caught = await catching(() => invoke(manager, 'valid'))
        sequence.push('caught')
        expectError(assert, caught, 503, code, `${label} · #write · ${face}`)
        assert.deepEqual(
          sequence,
          ['event:true', 'caught'],
          `ROJO (${label} · #write · ${face}): la escritura ${face === 'deadline' ? 'con deadline vencido' : 'PARCIAL (markPartialWrite)'} no notificó indeterminate: true ANTES de propagar el 503`
        )
        assert.equal(events[0]?.operation, op)
      }
      // Control: un 503 que NO es timeout ni parcial ⇒ «no ocurrió», SIN evento.
      const spy = spiedDouble({ [op]: () => new AuthorizationBackendError('fake-relations', op, new Error('rechazada antes de escribir')) })
      const { manager, events } = await managerOver(build, spy)
      const caught = await catching(() => invoke(manager, 'valid'))
      expectError(assert, caught, 503, 'E_AUTHZ_BACKEND_UNAVAILABLE', `${label} · #write · control`)
      assert.lengthOf(events, 0, `${label} · #write · control: un 503 sin marca no notifica`)
      continue
    }
    if (column === 'actor') {
      const spy = spiedDouble()
      const { manager, events } = await managerOver(build, spy, { requireActor: true })
      const missing = await catching(() => invoke(manager, 'valid'))
      expectError(assert, missing, 422, 'E_AUTHZ_ACTOR_REQUIRED', `${label} · requireActor sin actor`)
      const malformed = await catching(() => invoke(manager, 'valid', { actor: { type: 'user', uuid: 'A#B' } }))
      expectError(assert, malformed, 422, 'E_AUTHZ_INVALID_IDENTITY', `${label} · actor mal formado`)
      assert.equal(spy.calls(), 0, `${label} · actor: CERO llamadas al driver`)
      assert.lengthOf(events, 0, `${label} · actor: CERO eventos`)
      continue
    }
    if (column === 'denyable') {
      for (const [variant, what] of NOT_DENYABLE_VARIANTS) {
        const spy = spiedDouble()
        const { manager, events } = await managerOver(build, spy)
        const caught = await catching(() => invoke(manager, variant))
        expectError(assert, caught, 422, NOT_DENYABLE, `${label} · denyable · ${what}`)
        assert.equal(spy.calls(), 0, `${label} · denyable · ${what}: CERO llamadas al driver`)
        assert.lengthOf(events, 0, `${label} · denyable · ${what}: CERO eventos`)
      }
      continue
    }
    if (column === 'partition') {
      const spy = spiedDouble()
      const { manager, events } = await managerOver(build, spy)
      const bad = await catching(() => invoke(manager, 'badPartition'))
      expectError(assert, bad, 422, 'E_AUTHZ_INVALID_IDENTITY', `${label} · partición con gramática rota`)
      assert.equal(spy.calls(), 0, `${label} · partición rota: CERO llamadas al driver`)
      assert.lengthOf(events, 0, `${label} · partición rota: CERO eventos`)
      // D4 + A2: las dos ortografías NO canónicas (sin guiones; guiones mal colocados) ⇒ 422 sin tocar el driver.
      for (const [variant, scope, what] of NON_CANONICAL) {
        const caught = await catching(() => invoke(manager, variant))
        if (DASHLESS_PARTITION === 'accepted') {
          assert.isNull(caught, `${label} · ${what}: hoy se ACEPTA (${caught?.message})`)
          assert.isAtLeast(spy.calls(), 1, `${label} · ${what}: llegó al driver`)
          if (r.kind === 'write') {
            assert.lengthOf(events, 1)
            assert.equal(events[0].partition.uuid, scope.uuid, 'el evento lleva la partición TAL COMO la pasó el llamante')
          }
        } else {
          expectError(assert, caught, DASHLESS_PARTITION.status, DASHLESS_PARTITION.code, `${label} · ${what}`)
          assert.equal(spy.calls(), 0, `${label} · ${what}: CERO llamadas al driver`)
          assert.lengthOf(events, 0, `${label} · ${what}: CERO eventos`)
        }
      }
      continue
    }
    assert.fail(`columna sin sonda en el manager: ${column}`)
  }
}

/* ── Capa DATABASE: el driver real con la conexión espiada, base y vista ─── */

function spiedDbDriver(transactionalWrites = false) {
  let connections = 0
  const driver = new DatabaseRelationsDriver(contractRelationsConfig(), { transactionalWrites }, {
    connection: (name?: string) => {
      connections += 1
      return db.connection(name)
    },
    primaryConnectionName: db.primaryConnectionName,
  })
  return { driver, connections: () => connections }
}

/** Base y vista `withClock` (H11): la MISMA tabla se corre sobre las dos. */
function dbTargets(transactionalWrites = false): Array<[string, DatabaseRelationsDriver, () => number]> {
  const base = spiedDbDriver(transactionalWrites)
  const view = base.driver.withClock(() => new Date()) as DatabaseRelationsDriver
  return [
    ['base', base.driver, base.connections],
    ['vista withClock', view, base.connections],
  ]
}

const WRITE_SQL = /^\s*(insert|update|delete)\b/i

async function probeDatabase(assert: any, r: GuardRow, column: GuardColumn, cell: GuardCell): Promise<void> {
  const op = r.operation
  const invoke = (t: any, v: Variant, o?: any) => probeInvoke(op, t, v, o)
  if ('exempt' in cell) {
    assert.equal(cell.probe, 'whitelist', `database.${op}: única exención admitida aquí es la lista blanca`)
    for (const [label, target] of dbTargets()) await probeWhitelistSql(assert, target, `database.${op} [${label}]`, op)
    return
  }
  if (!('probe' in cell)) return
  assert.isFunction(INVOKE[op], `no hay forma de invocar database.${op}: añade la entrada en INVOKE`)

  if (column === 'f05') {
    for (const [variant, code] of f05VariantsOf(assert, `database.${op}`, op)) {
      for (const [label, target, connections] of dbTargets()) {
        const before = connections()
        const { result: caught, queries } = await countQueries(() => catching(() => invoke(target, variant)))
        expectError(assert, caught, 422, code, `database.${op} [${label}] · F-05 · ${variant}`)
        assert.equal(connections(), before, `database.${op} [${label}] · F-05 · ${variant}: CERO accesos a la conexión`)
        assert.lengthOf(queries, 0, `database.${op} [${label}] · F-05 · ${variant}: CERO sentencias`)
      }
    }
    return
  }
  if (column === 'trx') {
    // Cara 1: el despliegue declara `transactionalWrites: false` (pool 1) ⇒ 500 E_AUTHZ_UNSUPPORTED.
    for (const [label, target] of dbTargets(false)) {
      const { result: caught, queries } = await countQueries(() => catching(() => invoke(target, 'valid', { transaction: {} })))
      expectError(assert, caught, 500, 'E_AUTHZ_UNSUPPORTED', `database.${op} [${label}] · { transaction } con transactionalWrites: false`)
      assert.lengthOf(queries, 0, `database.${op} [${label}] · trx cara 1: CERO sentencias`)
    }
    // Cara 2: `transactionalWrites: true` y una transacción que NO es la abierta del llamante ⇒ 500 E_AUTHZ_CONFIG, cero sentencias.
    const fake = { from() {}, table() {}, isTransaction: false }
    for (const [label, target] of dbTargets(true)) {
      const { result: caught, queries } = await countQueries(() => catching(() => invoke(target, 'valid', { transaction: fake })))
      expectError(assert, caught, 500, 'E_AUTHZ_CONFIG', `database.${op} [${label}] · { transaction } ajena/cerrada`)
      assert.lengthOf(queries, 0, `database.${op} [${label}] · trx cara 2: CERO sentencias (#writer juzga ANTES de la primera)`)
    }
    return
  }
  if (column === 'denyable') {
    // `driver()` no es una salida (precedente L-5): el DRIVER re-aplica la puerta del opt-in, base y vista.
    for (const [variant, what] of NOT_DENYABLE_VARIANTS) {
      for (const [label, target, connections] of dbTargets()) {
        const before = connections()
        const { result: caught, queries } = await countQueries(() => catching(() => invoke(target, variant)))
        expectError(assert, caught, 422, NOT_DENYABLE, `database.${op} [${label}] · denyable · ${what}`)
        assert.equal(connections(), before, `database.${op} [${label}] · denyable · ${what}: CERO accesos a la conexión`)
        assert.lengthOf(queries, 0, `database.${op} [${label}] · denyable · ${what}: CERO sentencias`)
      }
    }
    return
  }
  if (column === 'partition') {
    for (const [label, target] of dbTargets()) {
      const { result: bad, queries } = await countQueries(() => catching(() => invoke(target, 'badPartition')))
      expectError(assert, bad, 422, 'E_AUTHZ_INVALID_IDENTITY', `database.${op} [${label}] · partición con gramática rota`)
      assert.lengthOf(queries, 0, `database.${op} [${label}] · partición rota: CERO sentencias`)
      for (const [variant, , what] of NON_CANONICAL) {
        const { result: caught, queries: ran } = await countQueries(() => catching(() => invoke(target, variant)))
        if (DASHLESS_PARTITION === 'accepted') {
          assert.isNull(caught, `database.${op} [${label}] · ${what}: hoy se ACEPTA (${caught?.message})`)
          assert.isAtLeast(ran.length, 1, `database.${op} [${label}] · ${what}: llegó al motor`)
        } else {
          expectError(assert, caught, DASHLESS_PARTITION.status, DASHLESS_PARTITION.code, `database.${op} [${label}] · ${what}`)
          assert.lengthOf(ran, 0, `database.${op} [${label}] · ${what}: CERO sentencias`)
        }
      }
    }
    await db.from('authz_relations').whereIn('partition_key', NON_CANONICAL.map(([, s]) => `${s.type}|${s.uuid}`)).delete()
    return
  }
  assert.fail(`columna sin sonda en database: ${column}`)
}

/* ── Capa OPENFGA: el driver real con un cliente FALSO que cuenta, base y vista ── */

type FgaTuple = { user: string; relation: string; object: string }
type FgaScript = {
  failOn?: (method: string, nth: number) => Error | undefined
  /** B4: respuesta scriptada para la enésima llamada a un método (una página vacía con token, una respuesta sin `tuples`, N objetos). */
  respond?: (method: string, nth: number) => unknown
  /** B4: qué pasa DURANTE la llamada (avanzar el reloj monótono inyectado: la llamada «tardó»). */
  during?: (method: string, nth: number) => void
}

/**
 * Sustituye `driver.client` (propiedad pública en runtime, como hace `spyFgaClient`) por un cliente que anota
 * cada método y responde vacío (o con `tuples` en `read`); `script.failOn(method, nth)` hace fallar la enésima
 * llamada a un método (la purga PARCIAL, 🟡 5). Cero llamadas = la guarda cortó ANTES de componer una request;
 * ≥ 1 = entró. Sin servidor: el `:8101` no hace falta para juzgar guardas que cortan antes del cliente.
 */
function fakeFgaClient(driver: object, tuples: FgaTuple[] = [], script: FgaScript = {}) {
  const calls: string[] = []
  const counts = new Map<string, number>()
  // Lote D · D-31: la guarda del modelo lee el modelo FIJADO una vez por proceso; el falso sirve el de la config del
  // contrato con deny (declara `denied_*` de `document` y `workspace`).
  const model = { authorization_model: openFgaFactsModel(GUARD_HOLDERS, [], { objectTypes: contractRelationsConfig().objectTypes }) }
  const responses: Record<string, unknown> = {
    readAuthorizationModel: model,
    readLatestAuthorizationModel: model,
    read: { tuples: tuples.map((key) => ({ key })), continuation_token: '' },
    check: { allowed: false },
    batchCheck: { result: {} },
    listObjects: { objects: [] },
    listUsers: { users: [] },
    write: {},
    writeTuples: {},
    deleteTuples: {},
  }
  ;(driver as { client: unknown }).client = new Proxy(
    {},
    {
      get(_target, prop) {
        if (typeof prop !== 'string') return undefined
        return async () => {
          calls.push(prop)
          const nth = (counts.get(prop) ?? 0) + 1
          counts.set(prop, nth)
          const fail = script.failOn?.(prop, nth)
          if (fail) throw fail
          script.during?.(prop, nth)
          const scripted = script.respond?.(prop, nth)
          return scripted !== undefined ? scripted : (responses[prop] ?? {})
        }
      },
    }
  )
  return { calls, total: () => calls.length }
}

const GUARD_HOLDERS = { user: 'user', admin: 'admin', integration: 'integration' } as const

function fgaDriver(options: Partial<ConstructorParameters<typeof OpenFgaRelationsDriver>[1]> = {}): OpenFgaRelationsDriver {
  return new OpenFgaRelationsDriver(contractRelationsConfig(), {
    apiUrl: 'http://127.0.0.1:9',
    storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
    // D14: con un tipo con deny, el modelId fijado es obligatorio.
    modelId: '01ARZ3NDEKTSV4RRFFQ69G5FAW',
    holderTypes: GUARD_HOLDERS,
    timeoutMs: 1000,
    // Cierre 3 · ⚪ N10: D ≤ timeoutMs del cliente (la señal tiene que poder saltar antes de que el cliente corte).
    listObjectsDeadlineMs: 1000,
    logger: { warn: () => {} },
    ...options,
  })
}

/** Base y vista `withClock` (H11), cada una con su cliente falso (la vista hereda el del momento de crearse; se le pone el suyo). */
function fgaTargets(
  tuples?: FgaTuple[],
  script?: FgaScript,
  options: Partial<ConstructorParameters<typeof OpenFgaRelationsDriver>[1]> = {}
): Array<[string, OpenFgaRelationsDriver, ReturnType<typeof fakeFgaClient>]> {
  const base = fgaDriver(options)
  const baseSpy = fakeFgaClient(base, tuples, script)
  const view = base.withClock(() => new Date()) as OpenFgaRelationsDriver
  const viewSpy = fakeFgaClient(view, tuples, script)
  return [
    ['base', base, baseSpy],
    ['vista withClock', view, viewSpy],
  ]
}

const FGA_WRITE_METHODS = new Set(['write', 'writeTuples', 'deleteTuples'])

async function probeOpenFga(assert: any, r: GuardRow, column: GuardColumn, cell: GuardCell): Promise<void> {
  const op = r.operation
  const invoke = (t: any, v: Variant, o?: any) => probeInvoke(op, t, v, o)
  if ('exempt' in cell) {
    if (cell.probe === 'unsupported') {
      assert.equal(op, 'membersOf', `openfga.${op}: la sonda 'unsupported' es la de membersOf (D6-membersOf-openfga)`)
      for (const [label, target, spy] of fgaTargets()) {
        const caught = await catching(() => invoke(target, 'valid'))
        expectError(assert, caught, 500, 'E_AUTHZ_UNSUPPORTED', `openfga.membersOf [${label}]`)
        assert.equal(spy.total(), 0, `openfga.membersOf [${label}]: CERO llamadas al cliente`)
      }
      return
    }
    if (cell.probe === 'whitelist') {
      assertWhitelistOp(assert, `openfga.${op}`, op)
      const key = `${P.type}|${P.uuid}`
      const stored = [
        { user: `user:${uuidv7()}`, relation: 'viewer', object: `document:${key}|${uuidv7()}` },
        { user: `user:${uuidv7()}`, relation: 'assignee', object: `role_binding:${key}|${uuidv7()}` },
        { user: `user:${uuidv7()}`, relation: 'parent', object: `scope:${key}|${uuidv7()}` },
      ]
      for (const [label, target] of fgaTargets(stored)) {
        const page = await invoke(target, 'valid') as { tuples: Array<{ object: { type: string } }> }
        assert.deepEqual(
          page.tuples.map((t) => t.object.type),
          ['document'],
          `ROJO (openfga.${op} [${label}]): el barrido devuelve un tipo NO declarado (role_binding/scope) — la lista blanca no filtra`
        )
      }
      return
    }
    assert.fail(`sonda de exención desconocida para openfga.${op}: ${cell.probe}`)
  }
  if (!('probe' in cell)) return
  assert.isFunction(INVOKE[op], `no hay forma de invocar openfga.${op}: añade la entrada en INVOKE`)

  if (column === 'f05') {
    for (const [variant, code] of f05VariantsOf(assert, `openfga.${op}`, op)) {
      for (const [label, target, spy] of fgaTargets()) {
        const caught = await catching(() => invoke(target, variant))
        expectError(assert, caught, 422, code, `openfga.${op} [${label}] · F-05 · ${variant}`)
        assert.equal(spy.total(), 0, `openfga.${op} [${label}] · F-05 · ${variant}: CERO llamadas al cliente`)
      }
    }
    return
  }
  if (column === 'trx') {
    for (const [label, target, spy] of fgaTargets()) {
      const caught = await catching(() => invoke(target, 'valid', { transaction: {} }))
      expectError(assert, caught, 500, 'E_AUTHZ_UNSUPPORTED', `openfga.${op} [${label}] · { transaction } rechazada por el DRIVER`)
      assert.equal(spy.total(), 0, `openfga.${op} [${label}] · trx: CERO llamadas al cliente`)
    }
    return
  }
  if (column === 'write') {
    // Invariante 13, mitad PARCIAL (cierre 🟡 5): la purga es multi-request (Read + deleteTuples + Read de residuo);
    // si el backend cae DESPUÉS de haber borrado ≥ 1 tupla, el error tiene que venir marcado (markPartialWrite)
    // para que el manager notifique indeterminate: true. Cliente falso: el primer `read` trae tuplas, `deleteTuples`
    // va bien y el segundo `read` (la demostración de cero) lanza un fallo que NO es timeout.
    const stored: FgaTuple[] = [{ user: `user:${uuidv7()}`, relation: 'viewer', object: `document:${P.type}|${P.uuid}|${uuidv7()}` }]
    // Lote D · D-26: la purga lee TODOS sus filtros antes de borrar (orden GLOBAL allows → denies), así que «tras
    // borrar» es la primera `read` DESPUÉS de un `deleteTuples` (la demostración de cero), no la segunda a secas.
    const afterDelete = (): FgaScript => {
      let deleted = false
      return {
        failOn: (m) => (m === 'read' && deleted ? new Error('backend caído tras borrar (no es timeout)') : undefined),
        during: (m) => {
          if (m === 'deleteTuples') deleted = true
        },
      }
    }
    for (const at of [0, 1]) {
      const [label, target, spy] = fgaTargets(stored, afterDelete())[at]
      const caught = await catching(() => invoke(target, 'valid'))
      expectError(assert, caught, 503, 'E_AUTHZ_BACKEND_UNAVAILABLE', `openfga.${op} [${label}] · purga que muere tras borrar`)
      assert.include(spy.calls, 'deleteTuples', `openfga.${op} [${label}]: llegó a borrar antes de caer`)
      assert.isTrue(
        isPartialWrite(caught),
        `ROJO (openfga.${op} [${label}] · invariante 13): ya había borrado ≥ 1 tupla y el error NO viene marcado como escritura PARCIAL (markPartialWrite)`
      )
    }
    // Control: si cae ANTES de borrar nada, «esa escritura no ocurrió»: sin marca.
    const beforeDelete: FgaScript = { failOn: (m, nth) => (m === 'read' && nth === 1 ? new Error('backend caído antes de borrar') : undefined) }
    for (const [label, target, spy] of fgaTargets(stored, beforeDelete)) {
      const caught = await catching(() => invoke(target, 'valid'))
      expectError(assert, caught, 503, 'E_AUTHZ_BACKEND_UNAVAILABLE', `openfga.${op} [${label}] · purga que muere antes de borrar`)
      assert.notInclude(spy.calls, 'deleteTuples')
      assert.isFalse(isPartialWrite(caught), `openfga.${op} [${label}]: sin borrado no hay marca de parcial`)
    }
    // Y la composición con el MANAGER sobre el driver real: el evento indeterminate: true ANTES del 503.
    const [[, base]] = fgaTargets(stored, afterDelete())
    const sequence: string[] = []
    const manager = new RelationsManager(base, contractRelationsConfig(), {
      onRelationWrite: (e: any) => void sequence.push(`event:${e.indeterminate === true}`),
    })
    const caught = await catching(() => invoke(manager, 'valid'))
    sequence.push('caught')
    expectError(assert, caught, 503, 'E_AUTHZ_BACKEND_UNAVAILABLE', `manager sobre openfga.${op} · purga parcial`)
    assert.deepEqual(sequence, ['event:true', 'caught'], `ROJO (openfga.${op} · invariante 13): la purga PARCIAL no llegó al manager como indeterminada`)
    return
  }
  if (column === 'truncation') {
    // B4 · «toda enumeración que se puede cortar devuelve `truncated` o lanza» (linaje L8 ⇒ M8), sondeado en el
    // único backend que corta. `listObjects`: las DOS causas de la MISMA señal —el tope del servidor y el
    // deadline (≥ 0,9 × `listObjectsDeadlineMs`, medido con el reloj monótono INYECTADO, sin sleep)— y el
    // control (ni tope ni deadline ⇒ sin señal falsa). Lo que entra por `Read`: exhaustivo o 503, nunca una
    // página corta (una página vacía con token que no avanza; una respuesta sin `tuples`), y una purga con el
    // Read roto NO borra nada.
    if (op === 'listObjects') {
      const ids = (n: number) => Array.from({ length: n }, () => `document:${P.type}|${P.uuid}|${uuidv7()}`)
      const faces: Array<[string, number, number, boolean]> = [
        ['tope alcanzado (2 de 2)', 2, 1, true],
        ['deadline rozado (900 de 1000 ms)', 1, 900, true],
        ['control: 1 de 2, 899 ms', 1, 899, false],
      ]
      for (const [face, count, elapsedMs, expected] of faces) {
        let clock = 10_000
        const script: FgaScript = {
          respond: (m) => (m === 'listObjects' ? { objects: ids(count) } : undefined),
          during: (m) => {
            if (m === 'listObjects') clock += elapsedMs
          },
        }
        for (const [label, target] of fgaTargets(undefined, script, { listObjectsMaxResults: 2, listObjectsDeadlineMs: 1_000, [MONOTONIC_CLOCK]: () => clock } as any)) {
          const page = (await invoke(target, 'valid')) as { objects: unknown[]; truncated?: boolean }
          assert.equal(
            page.truncated === true,
            expected,
            `ROJO (openfga.listObjects [${label}] · truncation · ${face}): ${expected ? 'la lista salió como COMPLETA (lista parcial muda)' : 'se inventó un truncado'}`
          )
          assert.lengthOf(page.objects, count, `openfga.listObjects [${label}] · ${face}: lo que llegó se devuelve`)
        }
      }
      // 🟡 4 (cierre 1 del lote B): la CUARTA cara — un 200 sin `objects` no es una lista completa vacía: 503,
      // como `#readAll` sin `tuples` (M8: «devuelve `truncated` o lanza»; «{ objects: [] }» mudo era la tercera forma).
      for (const [label, target] of fgaTargets(undefined, { respond: (m) => (m === 'listObjects' ? {} : undefined) })) {
        const caught = await catching(() => invoke(target, 'valid'))
        expectError(assert, caught, 503, 'E_AUTHZ_BACKEND_UNAVAILABLE', `ROJO (openfga.listObjects [${label}] · truncation · respuesta sin \`objects\`): una ListObjects sin cuerpo salió como lista COMPLETA vacía (muda)`)
      }
      return
    }
    const stored: FgaTuple[] = [{ user: `user:${uuidv7()}`, relation: 'viewer', object: `document:${P.type}|${P.uuid}|${uuidv7()}` }]
    const faces: Array<[string, FgaScript]> = [
      ['página vacía con token que no avanza', { respond: (m) => (m === 'read' ? { tuples: [], continuation_token: 'stuck' } : undefined) }],
      ['respuesta sin `tuples`', { respond: (m) => (m === 'read' ? { continuation_token: '' } : undefined) }],
    ]
    for (const [face, script] of faces) {
      for (const [label, target, spy] of fgaTargets(stored, script)) {
        const caught = await catching(() => invoke(target, 'valid'))
        expectError(assert, caught, 503, 'E_AUTHZ_BACKEND_UNAVAILABLE', `ROJO (openfga.${op} [${label}] · truncation · ${face}): una enumeración por Read que no puede ser exhaustiva tiene que LANZAR, no devolver una página corta`)
        assert.notInclude(spy.calls, 'deleteTuples', `openfga.${op} [${label}] · ${face}: con el Read roto no se borra nada`)
        assert.notInclude(spy.calls, 'write', `openfga.${op} [${label}] · ${face}: ni se escribe`)
      }
    }
    return
  }
  if (column === 'denyable') {
    // El driver re-aplica la puerta ANTES de la guarda del modelo (D-31): ni `readAuthorizationModel` ni `write`.
    for (const [variant, what] of NOT_DENYABLE_VARIANTS) {
      for (const [label, target, spy] of fgaTargets()) {
        const caught = await catching(() => invoke(target, variant))
        expectError(assert, caught, 422, NOT_DENYABLE, `openfga.${op} [${label}] · denyable · ${what}`)
        assert.equal(spy.total(), 0, `openfga.${op} [${label}] · denyable · ${what}: CERO llamadas al cliente (${spy.calls.join(', ')})`)
      }
    }
    return
  }
  if (column === 'partition') {
    for (const [label, target, spy] of fgaTargets()) {
      const bad = await catching(() => invoke(target, 'badPartition'))
      expectError(assert, bad, 422, 'E_AUTHZ_INVALID_IDENTITY', `openfga.${op} [${label}] · partición con gramática rota`)
      assert.equal(spy.total(), 0, `openfga.${op} [${label}] · partición rota: CERO llamadas al cliente`)
      for (const [variant, , what] of NON_CANONICAL) {
        const caught = await catching(() => invoke(target, variant))
        if (DASHLESS_PARTITION === 'accepted') {
          assert.isNull(caught, `openfga.${op} [${label}] · ${what}: hoy se ACEPTA (${caught?.message})`)
          assert.isAtLeast(spy.total(), 1, `openfga.${op} [${label}] · ${what}: llegó al cliente`)
        } else {
          expectError(assert, caught, DASHLESS_PARTITION.status, DASHLESS_PARTITION.code, `openfga.${op} [${label}] · ${what}`)
          assert.equal(spy.total(), 0, `openfga.${op} [${label}] · ${what}: CERO llamadas al cliente`)
        }
      }
    }
    return
  }
  if (column === 'model') {
    // Lote «antes de RC» · L11 (decisión del dueño 2026-10-17 (1); injertos 4–6 del juez): la PUERTA del modelo en
    // CADA operación del driver, base y vista. El falso sirve un modelo con UNA deriva: (1) una regla de `document`
    // (el tipo de la operación), (2) las restricciones de `group#member` (se compara en TODA operación) y (3) la
    // condición `not_expired` (la vigencia de toda tupla). Toda operación ⇒ 500 `E_AUTHZ_CONFIG` con CERO llamadas
    // que evalúen o escriban (solo `readAuthorizationModel`); `enumerate*` —el ORIGEN de una migración— pasa SOLO la
    // parte `conditions`: responde con (1)/(2) y es 500 con (3). Un mutante por punto de llamada mata su celda.
    const conditionsOnly = op === 'enumerateRelations' || op === 'enumerateRelationsMany'
    for (const [face, drift, conditions] of MODEL_DRIFTS) {
      const served = { authorization_model: drift() }
      const script: FgaScript = { respond: (m) => (m === 'readAuthorizationModel' ? served : undefined) }
      for (const [label, target, spy] of fgaTargets(undefined, script)) {
        const caught = await catching(() => invoke(target, 'valid'))
        if (conditionsOnly && !conditions) {
          assert.isNull(caught, `openfga.${op} [${label}] · model · ${face}: el ORIGEN de una migración pasa SOLO la parte conditions — con deriva de reglas responde (${caught?.message})`)
          continue
        }
        expectError(assert, caught, 500, 'E_AUTHZ_CONFIG', `ROJO (openfga.${op} [${label}] · model · ${face}): el modelo servido no es el de la config y la operación siguió`)
        assert.deepEqual(
          spy.calls.filter((call) => call !== 'readAuthorizationModel'),
          [],
          `openfga.${op} [${label}] · model · ${face}: CERO llamadas que evalúen o escriban (${spy.calls.join(', ')})`
        )
      }
    }
    return
  }
  assert.fail(`columna sin sonda en openfga: ${column}`)
}

/**
 * **Las tres derivas de la columna `model`** (L11): sobre el modelo que genera la config de la guardia, UNA diferencia
 * en cada parte que compara la puerta. `conditions: true` = la deriva toca `conditions` (la única parte que pasa
 * `enumerate*`).
 */
const MODEL_DRIFTS: Array<[string, () => any, boolean]> = [
  [
    'regla de document#viewer (sin el but not)',
    () => {
      const model = openFgaFactsModel(GUARD_HOLDERS, [], { objectTypes: contractRelationsConfig().objectTypes })
      const document = model.type_definitions.find((t: any) => t.type === 'document')
      document.relations.viewer = document.relations.viewer.difference.base
      return model
    },
    false,
  ],
  [
    'restricciones de group#member (sin with not_expired)',
    () => {
      const model = openFgaFactsModel(GUARD_HOLDERS, [], { objectTypes: contractRelationsConfig().objectTypes })
      const group = model.type_definitions.find((t: any) => t.type === 'group')
      group.metadata.relations.member.directly_related_user_types = group.metadata.relations.member.directly_related_user_types.filter(
        (r: any) => !r.condition
      )
      return model
    },
    false,
  ],
  [
    'condición not_expired (otra expresión)',
    () => {
      const model = openFgaFactsModel(GUARD_HOLDERS, [], { objectTypes: contractRelationsConfig().objectTypes })
      model.conditions.not_expired.expression = 'current_time <= valid_until'
      return model
    },
    true,
  ],
]

/* ── Capa DOUBLE: makeRelationsDriver (D13), base y vista ───────────────── */

function doubleTargets(): Array<[string, RelationsDriver]> {
  const base = makeRelationsDriver({ config: contractRelationsConfig(), capabilities: FULL })
  return [
    ['base', base],
    ['vista withClock', base.withClock!(() => new Date())],
  ]
}

async function probeDouble(assert: any, r: GuardRow, column: GuardColumn, cell: GuardCell): Promise<void> {
  const op = r.operation
  const invoke = (t: any, v: Variant, o?: any) => probeInvoke(op, t, v, o)
  if ('exempt' in cell) {
    assert.equal(cell.probe, 'whitelist')
    assertWhitelistOp(assert, `double.${op}`, op)
    // En el doble no se puede SEMBRAR un tipo no declarado (F-05 lo corta en relate): la enumeración no puede devolverlo.
    for (const [label, target] of doubleTargets()) {
      const seed = await catching(() => target.relate(U, 'assignee', BINDING, P))
      expectError(assert, seed, 422, TYPE_UNKNOWN, `double.${op} [${label}] · sembrar role_binding`)
      const page = (await invoke(target, 'valid')) as { tuples: Array<{ object: { type: string } }> }
      assert.deepEqual(page.tuples.filter((t) => t.object.type === 'role_binding'), [], `double.${op} [${label}]: ningún tipo no declarado`)
    }
    return
  }
  if (!('probe' in cell)) return
  assert.isFunction(INVOKE[op], `no hay forma de invocar double.${op}: añade la entrada en INVOKE`)
  if (column === 'f05') {
    for (const [variant, code] of f05VariantsOf(assert, `double.${op}`, op)) {
      for (const [label, target] of doubleTargets()) {
        const caught = await catching(() => invoke(target, variant))
        expectError(assert, caught, 422, code, `double.${op} [${label}] · F-05 · ${variant} (D13: el doble publicado aplica F-05 por sí mismo)`)
      }
    }
    return
  }
  if (column === 'denyable') {
    // El doble publicado aplica la MISMA puerta: 422 y el deny NO queda escrito (listDenies vacío).
    for (const [variant, what] of NOT_DENYABLE_VARIANTS) {
      for (const [label, target] of doubleTargets()) {
        const caught = await catching(() => invoke(target, variant))
        expectError(assert, caught, 422, NOT_DENYABLE, `double.${op} [${label}] · denyable · ${what}`)
        const left = await target.listDenies!(rel(variant), obj(variant), P)
        assert.lengthOf(left.subjects, 0, `double.${op} [${label}] · denyable · ${what}: el deny NO quedó escrito`)
      }
    }
    return
  }
  if (column === 'partition') {
    // ⚪ 11: el doble también dice qué hace con la partición (D4 lo alcanzará por `scopeKey`).
    for (const [label, target] of doubleTargets()) {
      const bad = await catching(() => invoke(target, 'badPartition'))
      expectError(assert, bad, 422, 'E_AUTHZ_INVALID_IDENTITY', `double.${op} [${label}] · partición con gramática rota`)
      for (const [variant, , what] of NON_CANONICAL) {
        const caught = await catching(() => invoke(target, variant))
        if (DASHLESS_PARTITION === 'accepted') {
          assert.isNull(caught, `double.${op} [${label}] · ${what}: hoy se ACEPTA (${caught?.message})`)
        } else {
          expectError(assert, caught, DASHLESS_PARTITION.status, DASHLESS_PARTITION.code, `double.${op} [${label}] · ${what}`)
        }
      }
    }
    return
  }
  assert.fail(`double.${op}: columna sin sonda en el doble: ${column} (D13: F-05, partición y denyable)`)
}

/* ── G-0 · inventario por reflexión = filas del manifiesto ──────────────── */

const FUNCTION_STATICS = new Set(['length', 'name', 'prototype'])

/**
 * **El inventario ve TODO lo que una instancia expone** (cierre 🟡 3): la cadena de prototipos ENTERA hasta
 * `Object.prototype` (una operación heredada de una clase base no pierde su fila), los campos de instancia que
 * son funciones (`relateFast = async () => …` como campo de clase no está en el prototipo), los símbolos y los
 * estáticos de toda la cadena (`static x` sale como `static x` y, sin fila, nace rojo). Hasta el cierre solo
 * miraba `Object.getOwnPropertyNames(klass.prototype)`.
 */
function isPlainObject(value: unknown): value is Record<string | symbol, unknown> {
  if (value === null || typeof value !== 'object') return false
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

/**
 * **Las operaciones PROPIAS de un objeto** (cierre-2, 🟡 C): funciones, ACCESSORS (`get x()` definido sobre la
 * instancia: se cuenta por nombre, sin evaluarlo) y, recursivo hasta `depth`, los objetos PLANOS (un namespace
 * `admin = { relate }` sale como `admin.relate`). Límite declarado (manifiesto): un valor que es instancia de una
 * CLASE (`client` del SDK de openfga) no se recorre.
 */
function objectOperations(target: object, prefix = '', depth = 3, seen = new Set<object>()): string[] {
  const names: string[] = []
  if (seen.has(target)) return names
  seen.add(target)
  for (const key of [...Object.getOwnPropertyNames(target), ...Object.getOwnPropertySymbols(target)]) {
    const descriptor = Object.getOwnPropertyDescriptor(target, key)
    if (!descriptor) continue
    const name = `${prefix}${String(key)}`
    if (typeof descriptor.get === 'function' || typeof descriptor.set === 'function') names.push(name)
    else if (typeof descriptor.value === 'function') names.push(name)
    else if (depth > 0 && isPlainObject(descriptor.value)) names.push(...objectOperations(descriptor.value, `${name}.`, depth - 1, seen))
  }
  return names
}

function surfaceOperations(klass: Function, instance: object): string[] {
  const names = new Set<string>()
  for (let proto = klass.prototype; proto && proto !== Object.prototype; proto = Object.getPrototypeOf(proto)) {
    for (const n of Object.getOwnPropertyNames(proto)) if (n !== 'constructor') names.add(n)
    for (const s of Object.getOwnPropertySymbols(proto)) names.add(String(s))
  }
  for (const n of objectOperations(instance)) names.add(n)
  for (let k: any = klass; typeof k === 'function' && k !== Function.prototype; k = Object.getPrototypeOf(k)) {
    for (const n of Object.getOwnPropertyNames(k)) if (!FUNCTION_STATICS.has(n)) names.add(`static ${n}`)
  }
  return [...names]
}

/** Un Proxy sirve cualquier nombre sin tenerlo: la reflexión no lo ve, así que la instancia NO puede serlo (🟡 C). */
function assertNotProxy(assert: any, what: string, instance: object): void {
  assert.isFalse(
    utilTypes.isProxy(instance),
    `ROJO (G-0 · 🟡 C): ${what} es un Proxy (devuelto por el constructor o por withClock): puede servir métodos que el inventario por reflexión no ve`
  )
}

/**
 * **La clasificación obligatoria como función PURA** (cierre-2, 🟡 E): las dos listas son disjuntas; toda operación
 * del inventario (menos plataforma, vista, estáticos y símbolos —que G-0 ya juzga—) está en UNA de ellas; y el
 * `kind` de cada fila `write`/`read` de la tabla coincide con la lista.
 */
function classificationViolations(inventory: Record<string, string[]>, writes: readonly string[], reads: readonly string[], table: GuardRow[]): string[] {
  const out: string[] = []
  for (const op of writes) if (reads.includes(op)) out.push(`'${op}' está en PORT_WRITES Y en PORT_READS: una operación es escritura o lectura, no las dos`)
  for (const [where, ops] of Object.entries(inventory)) {
    for (const op of ops) {
      if (op.startsWith('static ') || op.startsWith('Symbol(')) continue
      if ((PLATFORM_OPERATIONS as readonly string[]).includes(op) || (VIEW_OPERATIONS as readonly string[]).includes(op)) continue
      if (!writes.includes(op) && !reads.includes(op)) {
        out.push(
          `${where}.${op}: operación SIN CLASIFICAR — añádela a PORT_WRITES o a PORT_READS de tests/fixtures/guard_manifest.ts ` +
            `(G-R deriva de ahí qué es escritura: sin clasificación una escritura nueva pasaría por lectura, sin freeze, sin puerta trx y sin actor)`
        )
      }
    }
  }
  for (const r of table) {
    if (r.kind !== 'write' && r.kind !== 'read') continue
    const expected = writes.includes(r.operation) ? 'write' : reads.includes(r.operation) ? 'read' : null
    if (expected && r.kind !== expected) out.push(`${r.layer}.${r.operation}: la fila es '${r.kind}' y la clasificación del puerto dice '${expected}'`)
  }
  return out
}

function assertInventory(assert: any, what: string, found: string[], layer: GuardLayer): void {
  const declared = rows(layer).map((r) => r.operation)
  const missing = found.filter((n) => !declared.includes(n))
  const stale = declared.filter((n) => !found.includes(n))
  assert.deepEqual(
    missing,
    [],
    `ROJO (G-0): ${what} tiene operaciones SIN fila en tests/fixtures/guard_manifest.ts — añade una fila '${layer}' con sus seis celdas (y su entrada en INVOKE + F05_VARIANTS del spec, y sus mutantes) para: ${missing.join(', ')}`
  )
  assert.deepEqual(stale, [], `ROJO (G-0): el manifiesto declara filas '${layer}' que ${what} ya no tiene: ${stale.join(', ')}`)
}

/** Lo que el provider construye para `authz.relations`, sobre un driver espía. */
async function providerManager(driver: RelationsDriver): Promise<RelationsManager> {
  return buildRelationsManager({
    default: 'database',
    drivers: {},
    warnOnOptInSecurity: false,
    relations: { config: contractRelationsConfig(), drivers: { database: () => driver } },
  } as any)
}

test.group('GS · G-0 · inventario por reflexión', () => {
  test('RelationsManager: cada método público tiene su fila (cadena de prototipos, campos, accessors y namespaces de instancia, estáticos; y no es un Proxy)', ({ assert }) => {
    const spy = spiedDouble()
    const manager = new RelationsManager(spy.driver, contractRelationsConfig())
    assertNotProxy(assert, 'new RelationsManager(…)', manager)
    assertInventory(assert, 'RelationsManager', surfaceOperations(RelationsManager, manager), 'manager')
  })

  test('DatabaseRelationsDriver: cada método público tiene su fila, y la vista withClock expone EXACTAMENTE la misma superficie (H11)', ({ assert }) => {
    const { driver } = spiedDbDriver()
    assertNotProxy(assert, 'new DatabaseRelationsDriver(…)', driver)
    const ops = surfaceOperations(DatabaseRelationsDriver, driver)
    assertInventory(assert, 'DatabaseRelationsDriver', ops, 'database')
    const view = driver.withClock(() => new Date())
    assert.instanceOf(view, DatabaseRelationsDriver, 'la vista es una instancia de la MISMA clase (no un objeto envoltorio)')
    assertNotProxy(assert, 'DatabaseRelationsDriver.withClock(…)', view)
    assert.sameMembers(surfaceOperations(DatabaseRelationsDriver, view), ops)
    assert.deepEqual({ ...view.capabilities! }, { ...driver.capabilities! })
  })

  test('OpenFgaRelationsDriver: cada método público tiene su fila, y la vista withClock expone EXACTAMENTE la misma superficie (H11)', ({ assert }) => {
    const driver = fgaDriver()
    assertNotProxy(assert, 'new OpenFgaRelationsDriver(…)', driver)
    const ops = surfaceOperations(OpenFgaRelationsDriver, driver)
    assertInventory(assert, 'OpenFgaRelationsDriver', ops, 'openfga')
    const view = driver.withClock(() => new Date())
    assert.instanceOf(view, OpenFgaRelationsDriver, 'la vista es una instancia de la MISMA clase (no un objeto envoltorio)')
    assertNotProxy(assert, 'OpenFgaRelationsDriver.withClock(…)', view)
    assert.sameMembers(surfaceOperations(OpenFgaRelationsDriver, view), ops)
    assert.deepEqual({ ...view.capabilities! }, { ...driver.capabilities! })
  })

  test('makeRelationsDriver (doble publicado, D13): cada operación tiene su fila (funciones, accessors y namespaces), y la vista withClock expone las mismas', ({ assert }) => {
    const [[, base], [, view]] = doubleTargets()
    assertNotProxy(assert, 'makeRelationsDriver(…)', base)
    assertNotProxy(assert, 'makeRelationsDriver(…).withClock(…)', view)
    assertInventory(assert, 'makeRelationsDriver', objectOperations(base), 'double')
    assert.sameMembers(objectOperations(view), objectOperations(base), 'la vista withClock del doble trae las mismas operaciones')
    assert.deepEqual({ ...view.capabilities! }, { ...base.capabilities! })
  })

  test('exports: las cuatro superficies salen por IDENTIDAD; toda OTRA clase con una operación del puerto y toda función con «relation» en el nombre está clasificada con razón', async ({
    assert,
  }) => {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
    const sources: string[] = []
    for (const [subpath, target] of Object.entries<string>(pkg.exports)) {
      const source = target.replace(/^\.\/build\//, '').replace(/\.js$/, '.ts')
      if (source.includes('*')) {
        const dir = source.slice(0, source.indexOf('*'))
        for (const file of readdirSync(new URL(`../${dir}`, import.meta.url))) if (file.endsWith('.ts')) sources.push(`${dir}${file}`)
        continue
      }
      if (subpath === './services/relations') {
        // Exporta la INSTANCIA del servicio (exige `relations.config` para importarse): se juzga por su fuente y
        // por lo que el provider construye (caso «el servicio» y las filas manager, 🟡 6).
        const text = readFileSync(new URL(`../${source}`, import.meta.url), 'utf8')
        assert.include(text, "container.make('authz.relations')", 'services/relations resuelve el singleton del contenedor')
        continue
      }
      sources.push(source)
    }
    assert.isAtLeast(sources.length, 20, `se recorrieron los módulos públicos: ${sources.join(', ')}`)
    // ⚪ 9: las superficies se reconocen por la REFERENCIA importada aquí, no por `.name` (un homónimo no cuela).
    const surfaceByIdentity = new Map<unknown, GuardLayer>([
      [RelationsManager, 'manager'],
      [DatabaseRelationsDriver, 'database'],
      [OpenFgaRelationsDriver, 'openfga'],
      [makeRelationsDriver, 'double'],
    ])
    const foundSurface = new Map<GuardLayer, string>()
    const classes = new Map<string, string>()
    const functions = new Map<string, string>()
    const hunt = (value: unknown, path: string, name: string, seen: Set<unknown>, depth: number) => {
      if (depth >= 6 || value === null || (typeof value !== 'object' && typeof value !== 'function') || seen.has(value)) return
      seen.add(value)
      if (typeof value === 'function') {
        const layer = surfaceByIdentity.get(value)
        if (layer !== undefined) {
          foundSurface.set(layer, path)
        } else {
          const proto = (value as Function).prototype
          const portOps = proto ? Object.getOwnPropertyNames(proto).filter((n) => (PORT_OPERATIONS as readonly string[]).includes(n)) : []
          if (portOps.length > 0) classes.set((value as Function).name || name, path)
          else if (/relation/i.test((value as Function).name || name)) functions.set((value as Function).name || name, path)
        }
      }
      for (const key of Object.getOwnPropertyNames(value)) {
        if (typeof value === 'function' && (key === 'prototype' || key === 'caller' || key === 'arguments' || key === 'length' || key === 'name')) continue
        const descriptor = Object.getOwnPropertyDescriptor(value, key)
        if (descriptor && 'value' in descriptor) hunt(descriptor.value, `${path}.${key}`, key, seen, depth + 1)
      }
    }
    for (const source of sources) {
      const mod: Record<string, unknown> = await import(`../${source}`)
      for (const [name, value] of Object.entries(mod)) hunt(value, `${source}#${name}`, name, new Set(), 0)
    }
    for (const layer of ['manager', 'database', 'openfga', 'double'] as GuardLayer[]) {
      assert.isTrue(foundSurface.has(layer), `la superficie '${layer}' sigue exportada por identidad (${[...foundSurface].map(([l, p]) => `${l}=${p}`).join(', ')})`)
    }
    const unknownClasses = [...classes].filter(([n]) => !(n in NON_SURFACE_CLASSES))
    assert.deepEqual(
      unknownClasses,
      [],
      `ROJO (G-0 · exports): clases exportadas con operaciones del puerto de relaciones que no son una de las cuatro superficies (por identidad) ni están clasificadas como no-superficie: ${unknownClasses.map(([n, p]) => `${n} (${p})`).join(', ')}`
    )
    const unknownFunctions = [...functions].filter(([n]) => !(n in NON_SURFACE_FUNCTIONS))
    assert.deepEqual(
      unknownFunctions,
      [],
      `ROJO (G-0 · exports): funciones exportadas con «relation» en el nombre sin clasificar — o reciben tuplas (fila 'double'/superficie nueva) o van en NON_SURFACE_FUNCTIONS con su razón: ${unknownFunctions.map(([n, p]) => `${n} (${p})`).join(', ')}`
    )
  })

  test('el servicio: lo que el CONTENEDOR sirve como `authz.relations` (AuthzProvider.register → container.make) es EXACTAMENTE un RelationsManager (prototipo exacto, no Proxy, misma superficie), un singleton, y sus filas se sondean sobre él', async ({ assert }) => {
    const spy = spiedDouble()
    const built = await providerManager(spy.driver)
    assert.deepEqual(serviceViolations(built), [], `buildRelationsManager: ${serviceViolations(built).join(' || ')}`)
    // 🟡 B: lo que el usuario recibe es lo que sirve el contenedor, por el closure REAL del provider.
    const config = serviceConfig(spy.driver, {})
    const container = new Container()
    const app = { container, config: { get: (key: string) => (key === 'authorization' ? config : undefined) } }
    new AuthzProvider(app as any).register()
    const served = await container.make('authz.relations')
    assert.deepEqual(serviceViolations(served), [], `ROJO (🟡 B): lo que sirve el contenedor como authz.relations no es la clase que las filas juzgan: ${serviceViolations(served).join(' || ')}`)
    assert.strictEqual(await container.make('authz.relations'), served, 'authz.relations es un singleton del contenedor')
    assert.strictEqual(served.driver(), spy.driver)
    assert.isTrue(
      MANAGER_BUILDS.some(([via]) => via.includes("container.make('authz.relations')")),
      'las filas manager se corren también sobre lo que sirve el contenedor (MANAGER_BUILDS)'
    )
  })
})

/* ── Las celdas: un caso por celda con sonda, por capa ─────────────────── */

const PROBES: Record<GuardLayer, (assert: any, r: GuardRow, column: GuardColumn, cell: GuardCell) => Promise<void>> = {
  manager: probeManager,
  database: probeDatabase,
  openfga: probeOpenFga,
  double: probeDouble,
}

for (const layer of ['manager', 'database', 'openfga', 'double'] as GuardLayer[]) {
  test.group(`GS · celdas · ${layer}`, (group) => {
    group.each.setup(async () => {
      await db.from('authz_relations').delete()
    })
    for (const r of rows(layer)) {
      for (const column of GUARD_COLUMNS) {
        const cell = r.cells[column]
        if ('na' in cell) continue
        test(cellTitle(layer, r.operation, column), async ({ assert }) => {
          await PROBES[layer](assert, r, column, cell)
        }).timeout(TEST_TIMEOUT)
      }
    }
  })
}

/* ── G-R · una lectura no escribe ni notifica (TODOS los métodos, por reflexión) ── */

test.group('GS · G-R · las lecturas no escriben ni notifican', () => {
  for (const r of rows('manager').filter((row) => row.kind === 'read')) {
    test(`G-R · manager.${r.operation}`, async ({ assert }) => {
      for (const [via, build] of MANAGER_BUILDS) {
        const spy = spiedDouble()
        const { manager, events } = await managerOver(build, spy)
        const caught = await catching(() => probeInvoke(r.operation, manager, 'valid'))
        assert.isNull(caught, `manager.${r.operation} [${via}] con entrada válida resuelve (${caught?.message})`)
        assert.isAtLeast(spy.calls(), 1, 'la lectura llegó al driver')
        assert.equal(spy.writes(), 0, `ROJO (G-R): manager.${r.operation} [${via}] está clasificada como LECTURA en el manifiesto y llamó a una escritura del driver`)
        assert.lengthOf(events, 0, `ROJO (G-R): manager.${r.operation} [${via}] está clasificada como LECTURA y notificó un evento`)
      }
    }).timeout(TEST_TIMEOUT)
  }

  // Meta-mutante (🟠 2): se invoca TODO método del manager que sale del inventario por reflexión —no solo
  // PORT_OPERATIONS—, con entrada válida; lo que escribe en el driver o notifica es escritura y tiene que ser
  // EXACTAMENTE el conjunto de filas 'write'. Una operación nueva sin entrada en INVOKE es rojo aquí.
  test('G-R · las escrituras del manifiesto son exactamente las que el manager (todo su inventario) escribe o notifica', async ({ assert }) => {
    const declared = rows('manager').filter((r) => r.kind === 'write').map((r) => r.operation).sort()
    const inventory = surfaceOperations(RelationsManager, new RelationsManager(spiedDouble().driver, contractRelationsConfig()))
    const writing: string[] = []
    for (const op of inventory) {
      if ((PLATFORM_OPERATIONS as readonly string[]).includes(op)) continue
      assert.isFunction(INVOKE[op], `ROJO (G-R): no hay forma de invocar manager.${op} — añade la entrada en INVOKE (una operación que no se invoca no se juzga)`)
      if (!INVOKE[op]) continue
      const spy = spiedDouble()
      const { manager, events } = await managerOver(directBuild, spy)
      await catching(() => probeInvoke(op, manager, 'valid'))
      if (events.length > 0 || spy.writes() > 0) writing.push(op)
    }
    assert.deepEqual(writing.sort(), declared, 'lo que escribe o notifica es escritura; lo que no, lectura')
  }).timeout(TEST_TIMEOUT)

  // 🟡 E: `WRITES` se deriva de PORT_WRITES/PORT_READS; aquí se exige que la clasificación sea COMPLETA (todo el
  // inventario por reflexión de las cuatro capas, sin `static`/símbolos/plataforma/vista) y VERDADERA (el driver
  // `database` ejecuta INSERT/UPDATE/DELETE exactamente en las escrituras; `openfga` llama a write/deleteTuples
  // exactamente en ellas) y que el `kind` de cada fila coincida. Una operación nueva sin clasificar nace roja con su nombre.
  test('G-R · clasificación obligatoria: toda operación del inventario está en PORT_WRITES o PORT_READS, la clasificación coincide con lo que los drivers HACEN y con el kind de cada fila', async ({ assert }) => {
    const inventory: Record<string, string[]> = {
      manager: surfaceOperations(RelationsManager, new RelationsManager(spiedDouble().driver, contractRelationsConfig())),
      database: surfaceOperations(DatabaseRelationsDriver, spiedDbDriver().driver),
      openfga: surfaceOperations(OpenFgaRelationsDriver, fgaDriver()),
      double: objectOperations(doubleTargets()[0][1]),
    }
    const unclassified = classificationViolations(inventory, PORT_WRITES, PORT_READS, GUARD_MANIFEST)
    assert.deepEqual(unclassified, [], `ROJO (🟡 E): ${unclassified.join(' || ')}`)
    // Comportamiento: database (sentencias) y openfga (métodos del cliente), con entrada válida.
    const observed: string[] = []
    const dbDriver = spiedDbDriver().driver
    for (const op of PORT_OPERATIONS) {
      const { queries } = await countQueries(() => catching(() => probeInvoke(op, dbDriver, 'valid')))
      const wrote = queries.some((q) => WRITE_SQL.test(q.sql))
      if (wrote !== WRITES.has(op)) observed.push(`database.${op}: clasificada como ${WRITES.has(op) ? 'ESCRITURA' : 'LECTURA'} y ${wrote ? 'ejecutó INSERT/UPDATE/DELETE' : 'no ejecutó ninguna sentencia de escritura'}`)
    }
    await db.from('authz_relations').delete()
    // Una tupla de OTRO documento: las purgas tienen algo que borrar (el `read` falso devuelve lo almacenado) y
    // `relate` no encuentra la suya ya escrita (re-relate idéntico es no-op sin Write: invariante 6).
    const stored: FgaTuple[] = [{ user: `user:${U.uuid}`, relation: 'viewer', object: `document:${P.type}|${P.uuid}|${uuidv7()}` }]
    for (const op of PORT_OPERATIONS) {
      const [[, target, spy]] = fgaTargets(stored)
      await catching(() => probeInvoke(op, target, 'valid'))
      const wrote = spy.calls.some((m) => FGA_WRITE_METHODS.has(m))
      if (wrote !== WRITES.has(op)) observed.push(`openfga.${op}: clasificada como ${WRITES.has(op) ? 'ESCRITURA' : 'LECTURA'} y ${wrote ? `llamó a ${spy.calls.filter((m) => FGA_WRITE_METHODS.has(m)).join('/')}` : 'no llamó a write/deleteTuples'}`)
    }
    assert.deepEqual(observed, [], 'ROJO (🟡 E): la clasificación PORT_WRITES/PORT_READS no coincide con lo que los drivers hacen')
  }).timeout(TEST_TIMEOUT)

  for (const r of rows('database').filter((row) => row.kind === 'read')) {
    test(`G-R · database.${r.operation}`, async ({ assert }) => {
      for (const [label, target] of dbTargets()) {
        const { result: caught, queries } = await countQueries(() => catching(() => probeInvoke(r.operation, target, 'valid')))
        assert.isNull(caught, `database.${r.operation} [${label}] con entrada válida resuelve (${caught?.message})`)
        const writes = queries.filter((q) => WRITE_SQL.test(q.sql)).map((q) => q.sql)
        assert.deepEqual(writes, [], `ROJO (G-R): database.${r.operation} [${label}] está clasificada como LECTURA y ejecutó sentencias de escritura`)
      }
    }).timeout(TEST_TIMEOUT)
  }

  for (const r of rows('openfga').filter((row) => row.kind === 'read')) {
    test(`G-R · openfga.${r.operation}`, async ({ assert }) => {
      for (const [label, target, spy] of fgaTargets()) {
        await catching(() => probeInvoke(r.operation, target, 'valid'))
        const writes = spy.calls.filter((m) => FGA_WRITE_METHODS.has(m))
        assert.deepEqual(writes, [], `ROJO (G-R): openfga.${r.operation} [${label}] está clasificada como LECTURA y llamó a ${writes.join(', ')}`)
      }
    }).timeout(TEST_TIMEOUT)
  }

  test('G-R · todo método de los drivers (inventario por reflexión) se invoca: ninguno queda fuera de INVOKE', ({ assert }) => {
    const missing: string[] = []
    for (const op of surfaceOperations(DatabaseRelationsDriver, spiedDbDriver().driver)) {
      if (!(VIEW_OPERATIONS as readonly string[]).includes(op) && !INVOKE[op]) missing.push(`database.${op}`)
    }
    for (const op of surfaceOperations(OpenFgaRelationsDriver, fgaDriver())) {
      if (!(VIEW_OPERATIONS as readonly string[]).includes(op) && !INVOKE[op]) missing.push(`openfga.${op}`)
    }
    assert.deepEqual(missing, [], `ROJO (G-R): operaciones de los drivers sin forma de invocarse — añade la entrada en INVOKE: ${missing.join(', ')}`)
  })
})

/* ── G-M · tabla ↔ manifiesto de mutantes, y la matriz cerrada de `na` ──── */

function loadMutants(): GuardMutant[] {
  return JSON.parse(readFileSync(new URL('./fixtures/guard_mutants.json', import.meta.url), 'utf8'))
}

/** Celdas que EXIGEN mutante: las `probe` y las exenciones CON sonda (la razón de la exención es la sonda). */
function cellsNeedingMutant(): string[] {
  const out: string[] = []
  for (const r of GUARD_MANIFEST) {
    for (const column of GUARD_COLUMNS) {
      const cell = r.cells[column]
      if ('probe' in cell) out.push(cellId(r.layer, r.operation, column))
    }
  }
  return out
}

/**
 * **La coherencia del manifiesto como función PURA** (cierre 🟠 2): toda `na` tiene que estar admitida por
 * `NA_MATRIX` para esa (razón, capa, tipo de fila, columna[, operación]); `f05` nunca es `na` salvo en las operaciones
 * SIN tupla, por nombre —`F05_NA_OPERATIONS`: `withClock` y `groupDepthLimit`, doctrina firmada el 2026-10-20 (R1 · D2
 * (a))—, y ese candado va APARTE de la matriz (una regla nueva de `NA_MATRIX` no lo abre: `matrix` es parámetro solo para
 * el caso meta que lo demuestra); `platform` es SOLO `driver()`/`capabilities()` del manager y `view` SOLO `withClock`;
 * una lectura no tiene sondas de escritura; `platform`/`view` no tienen sondas.
 */
/**
 * **R1 · D2 (a): la aridad CERO de `groupDepthLimit` la juzga el COMPILADOR** (injerto del auditor): su `f05: na` se
 * sostiene en que no recibe tupla. Si 2.6 le añadiera un argumento (`groupDepthLimit(partition)`), la celda seguiría verde
 * por NOMBRE; con esto, `npm run typecheck` es rojo en el puerto y en los dos drivers hasta que alguien revise la celda.
 */
type IsZeroArity<F extends (...args: any) => any> = Parameters<F> extends [] ? true : false
const GROUP_DEPTH_LIMIT_ZERO_ARITY: {
  port: IsZeroArity<NonNullable<RelationsDriver['groupDepthLimit']>>
  database: IsZeroArity<DatabaseRelationsDriver['groupDepthLimit']>
  openfga: IsZeroArity<OpenFgaRelationsDriver['groupDepthLimit']>
} = { port: true, database: true, openfga: true }

function manifestViolations(table: GuardRow[], matrix: readonly NaRule[] = NA_MATRIX): string[] {
  const out: string[] = []
  for (const r of table) {
    const where = `${r.layer}.${r.operation}`
    const isPlatformOp = (PLATFORM_OPERATIONS as readonly string[]).includes(r.operation)
    const isViewOp = (VIEW_OPERATIONS as readonly string[]).includes(r.operation)
    if (r.kind === 'platform' && !(r.layer === 'manager' && isPlatformOp)) {
      out.push(`${where}: 'platform' es SOLO para ${PLATFORM_OPERATIONS.join('/')} del manager — una operación que recibe tuplas es 'write' o 'read' y lleva sondas`)
    }
    if (r.kind === 'view' && !isViewOp) out.push(`${where}: 'view' es SOLO para ${VIEW_OPERATIONS.join('/')}`)
    if (isPlatformOp && r.kind !== 'platform') out.push(`${where}: ${r.operation} es 'platform'`)
    if (isViewOp && r.kind !== 'view') out.push(`${where}: ${r.operation} es 'view'`)
    for (const column of GUARD_COLUMNS) {
      const cell = r.cells[column]
      const id = cellId(r.layer, r.operation, column)
      if ('na' in cell) {
        if (!(cell.na in NA_REASONS)) {
          out.push(`${id}: razón 'na' fuera del conjunto cerrado (${String(cell.na)})`)
          continue
        }
        if (column === 'f05' && !(F05_NA_OPERATIONS as readonly string[]).includes(r.operation)) {
          out.push(
            `${id}: 'na: ${cell.na}' en f05 — la columna f05 NUNCA admite na salvo en las operaciones SIN tupla, por nombre ` +
              `(${F05_NA_OPERATIONS.join(' y ')}; doctrina D2 firmada 2026-10-20): o sonda o exención firmada (D6)`
          )
          continue
        }
        const admitted = matrix.some(
          (rule) =>
            rule.reason === cell.na &&
            rule.layers.includes(r.layer) &&
            rule.kinds.includes(r.kind) &&
            rule.columns.includes(column) &&
            (!rule.operations || rule.operations.includes(r.operation)) &&
            (!rule.exceptOperations || !rule.exceptOperations.includes(r.operation))
        )
        if (!admitted) {
          out.push(
            `${id}: 'na: ${cell.na}' NO está admitido por NA_MATRIX para ${r.layer}×${column} (fila '${r.kind}')` +
              (column === 'f05' ? ` — la columna f05 NUNCA admite na salvo en las operaciones SIN tupla, por nombre (${F05_NA_OPERATIONS.join(' y ')}): o sonda o exención firmada (D6)` : '')
          )
        }
        continue
      }
      const probing = cell.probe === true
      if (probing && r.kind === 'read' && ['trx', 'freeze', 'write', 'actor'].includes(column)) out.push(`${id}: una LECTURA no tiene sonda de escritura`)
      if (probing && (r.kind === 'platform' || r.kind === 'view')) out.push(`${id}: una fila '${r.kind}' no recibe tupla y no lleva sonda`)
    }
  }
  return out
}

test.group('GS · G-M · cada celda con sonda tiene ≥ 1 mutante y cada mutante existe en la fuente', () => {
  test('toda celda `probe` (o exención con sonda) aparece en al menos un mutante de guard_mutants.json', ({ assert }) => {
    const mutants = loadMutants()
    const covered = new Set(mutants.flatMap((m) => m.cells ?? []))
    const uncovered = cellsNeedingMutant().filter((id) => !covered.has(id))
    assert.deepEqual(
      uncovered,
      [],
      `ROJO (G-M): celdas con sonda SIN mutante que las mate — añade a tests/fixtures/guard_mutants.json un mutante por celda: ${uncovered.join(', ')}`
    )
  })

  test('cada mutante nombra celdas que existen y tienen sonda, su `find` casa EXACTAMENTE una vez en `file`, y `expectRed` son los títulos canónicos de sus celdas', ({
    assert,
  }) => {
    const mutants = loadMutants()
    const known = new Set(cellsNeedingMutant())
    const ids = new Set<string>()
    for (const m of mutants) {
      assert.isFalse(ids.has(m.id), `mutante duplicado: ${m.id}`)
      ids.add(m.id)
      const cells = m.cells ?? []
      const properties = m.properties ?? []
      assert.isAtLeast(cells.length + properties.length, 1, `${m.id}: sin celdas ni propiedades`)
      assert.isFalse(cells.length > 0 && properties.length > 0, `${m.id}: un mutante mata celdas O propiedades, no las dos`)
      for (const id of cells) assert.isTrue(known.has(id), `${m.id}: la celda '${id}' no existe en el manifiesto o no tiene sonda`)
      for (const id of properties) assert.isTrue(GUARD_PROPERTIES.some((p) => p.id === id), `${m.id}: la propiedad '${id}' no está en GUARD_PROPERTIES`)
      const edits = Array.isArray(m.edits) ? m.edits : [{ find: m.find!, replace: m.replace! }]
      for (const edit of edits) {
        const file = edit.file ?? m.file
        const text = readFileSync(ROOT + file, 'utf8')
        assert.isString(edit.find, `${m.id}: find`)
        const occurrences = text.split(edit.find).length - 1
        assert.equal(occurrences, 1, `ROJO (G-M): el 'find' del mutante ${m.id} casa ${occurrences} veces en ${file} (tiene que casar EXACTAMENTE una): el código cambió y el mutante ya no apunta a la guarda`)
        assert.notEqual(edit.find, edit.replace, `${m.id}: el mutante no cambia nada`)
      }
      const titles = [
        ...cells.map((id) => {
          const [layer, operation, column] = id.split('.') as [GuardLayer, string, GuardColumn]
          return cellTitle(layer, operation, column)
        }),
        ...properties.map((id) => GUARD_PROPERTIES.find((p) => p.id === id)!.title),
      ]
      assert.sameMembers(m.expectRed, titles, `${m.id}: expectRed tiene que ser exactamente los títulos canónicos de sus celdas`)
    }
    assert.isAtLeast(mutants.length, 50, 'hay un manifiesto de mutantes de verdad')
  })

  test('cada propiedad de GUARD_PROPERTIES tiene su lista CERRADA de mutantes en guard_mutants.json (los nombrados existen y apuntan a ella; ninguno más la nombra) — cierre 2 de D1 · ⚪ N2', ({
    assert,
  }) => {
    const mutants = loadMutants()
    for (const property of GUARD_PROPERTIES) {
      assert.isAtLeast(property.mutants.length, 1, `${property.id}: una propiedad sin mutantes no tiene diente`)
      const pointing = mutants.filter((m) => (m.properties ?? []).includes(property.id)).map((m) => m.id)
      assert.sameMembers(
        pointing,
        property.mutants,
        `ROJO (G-M · ${property.id}): los mutantes del corredor que apuntan a la propiedad no son EXACTAMENTE los que declara ` +
          `(un mutante de orden sacado del corredor, o uno nuevo sin declarar): corredor ${JSON.stringify(pointing)} · declarados ${JSON.stringify(property.mutants)}`
      )
    }
  })

  test('el manifiesto es coherente: toda `na` está admitida por la matriz cerrada NA_MATRIX (f05 nunca `na` salvo las operaciones sin tupla withClock/groupDepthLimit; doctrine solo freeze×driver; platform solo driver()/capabilities())', ({
    assert,
  }) => {
    assert.deepEqual(manifestViolations(GUARD_MANIFEST), [])
  })

  test('toda fila con celda f05 en sonda tiene variantes F-05 (una sonda vacía es roja, 🟡 7)', ({ assert }) => {
    const empty = GUARD_MANIFEST.filter((r) => 'probe' in r.cells.f05 && r.cells.f05.probe === true && !(F05_VARIANTS[r.operation]?.length > 0)).map((r) => `${r.layer}.${r.operation}`)
    assert.deepEqual(empty, [], `ROJO (🟡 7): filas con sonda F-05 sin variantes en F05_VARIANTS: ${empty.join(', ')}`)
  })
})

/* ── P · propiedades de un punto de paso (cierre 2 de D1, ⚪ N2; linaje L10 propuesto) ─────────────────── */

/**
 * **`openfga.purge.order`, sin servidor.** La tabla de verdad del 🟠 1 de D1 (y su fila simétrica, 🟡 N1 del cierre 2)
 * se mide contra el servidor en `relations_openfga.spec`; aquí se juzga la MISMA tabla sobre `purgeWrites` —el punto de
 * paso único de `purgeObject`/`purgeSubject`— con un evaluador mínimo del modelo (allow directo o por `group#member`,
 * anidado; deny directo o por `group#member`; el deny gana): para cada fila, en el orden del `Read` del driver (`group`
 * primero, luego el tipo del objeto) y en el inverso, el estado tras CADA prefijo de `Write` no concede (inicial y final
 * no conceden), y una purga que cabe en `RELATIONS_PURGE_WRITE_MAX` es UN `Write`. Así los cinco mutantes de orden van
 * en el corredor publicado (`npm run check:guard-mutants`, job `guard-mutants` en `:memory:` y `sqlite-file`, sin
 * OpenFGA) y no solo «por pieza».
 */
type PurgeTuple = { user: string; relation: string; object: string }

/** ¿`victim` tiene `relation` sobre `object` en `store`? Allow directo o por `group:*#member` (cierre transitivo), menos deny. */
function simulatedCheck(store: readonly PurgeTuple[], victim: string, relation: string, object: string): boolean {
  const reach = new Set([victim])
  for (let grew = true; grew; ) {
    grew = false
    for (const t of store) {
      const userset = `${t.object}#member`
      if (t.relation === 'member' && t.object.startsWith('group:') && reach.has(t.user) && !reach.has(userset)) {
        reach.add(userset)
        grew = true
      }
    }
  }
  const allowed = store.some((t) => t.object === object && t.relation === relation && reach.has(t.user))
  const denied = store.some((t) => t.object === object && t.relation === `denied_${relation}` && reach.has(t.user))
  return allowed && !denied
}

interface PurgeRow {
  label: string
  store: PurgeTuple[]
  /** El sujeto que se purga: `purgeSubject` lee las tuplas cuyo `user` es él. */
  subject: string
  victim: string
}

/** Las filas de la tabla de verdad (mismas que el grupo «lote D · cierre 1 de D1 · 🟠 1» de `relations_openfga.spec`). */
function purgeRows(): PurgeRow[] {
  const V = 'document:unit|p|v'
  const U = 'user:u'
  const W = 'user:w'
  const filler = (subject: string, n: number): PurgeTuple[] =>
    Array.from({ length: n }, (_, i) => ({ user: subject, relation: 'viewer', object: `document:unit|p|f${String(i).padStart(3, '0')}` }))
  const gm = (id: string) => `group:unit|p|${id}#member`
  const grp = (id: string) => `group:unit|p|${id}`
  const rows: PurgeRow[] = []
  for (const n of [0, 100]) {
    const fit = n === 0 ? 'cabe' : 'no cabe'
    rows.push({
      label: `directo × ${fit}`,
      subject: U,
      victim: U,
      store: [{ user: U, relation: 'viewer', object: V }, { user: U, relation: 'denied_viewer', object: V }, ...filler(U, n)],
    })
    rows.push({
      label: `por grupo × ${fit}`,
      subject: U,
      victim: U,
      store: [
        { user: U, relation: 'member', object: grp('g') },
        { user: gm('g'), relation: 'denied_viewer', object: V },
        ...filler(U, n),
        { user: U, relation: 'viewer', object: V },
      ],
    })
    rows.push({
      label: `anidado (userset g#member) × ${fit}`,
      subject: gm('g'),
      victim: W,
      store: [
        { user: W, relation: 'member', object: grp('g') },
        { user: gm('g'), relation: 'member', object: grp('h') },
        { user: gm('h'), relation: 'denied_viewer', object: V },
        ...filler(gm('g'), n),
        { user: gm('g'), relation: 'viewer', object: V },
      ],
    })
    rows.push({
      label: `allow por grupo × deny directo (holder) × ${fit}`,
      subject: U,
      victim: U,
      store: [
        { user: U, relation: 'member', object: grp('ga') },
        { user: gm('ga'), relation: 'viewer', object: V },
        { user: U, relation: 'denied_viewer', object: V },
        ...filler(U, n),
      ],
    })
    rows.push({
      label: `allow por grupo × deny directo (userset g#member) × ${fit}`,
      subject: gm('g'),
      victim: W,
      store: [
        { user: W, relation: 'member', object: grp('g') },
        { user: gm('g'), relation: 'member', object: grp('h') },
        { user: gm('h'), relation: 'viewer', object: V },
        { user: gm('g'), relation: 'denied_viewer', object: V },
        ...filler(gm('g'), n),
      ],
    })
  }
  // Allow Y deny por grupo, 99 allows: las dos membresías (g_deny ordena antes que g_allow) no caben con el último lote
  // de allows ⇒ el mutante «troceado contiguo» las separa.
  rows.push({
    label: 'allow Y deny por grupo × 99 allows',
    subject: U,
    victim: U,
    store: [
      { user: U, relation: 'member', object: grp('a-deny') },
      { user: U, relation: 'member', object: grp('b-allow') },
      { user: gm('a-deny'), relation: 'denied_viewer', object: V },
      { user: gm('b-allow'), relation: 'viewer', object: V },
      ...filler(U, 99),
    ],
  })
  return rows
}

test.group('GS · P · propiedades de un punto de paso (cierre 2 de D1 · ⚪ N2, linaje L10 propuesto)', () => {
  const property = GUARD_PROPERTIES.find((p) => p.id === 'openfga.purge.order')!

  test(property.title, ({ assert }) => {
    const violations: string[] = []
    for (const r of purgeRows()) {
      const V = 'document:unit|p|v'
      const own = r.store.filter((t) => t.user === r.subject)
      // El orden del `Read` del driver: el tipo `group` primero y luego el del objeto; y el inverso.
      const asRead = [...own.filter((t) => t.object.startsWith('group:')), ...own.filter((t) => !t.object.startsWith('group:'))]
      for (const [order, keys] of [['orden del Read', asRead], ['orden inverso', [...asRead].reverse()]] as const) {
        const batches = purgeWrites(keys)
        if (own.length <= 100 && batches.length !== 1) {
          violations.push(`${r.label} · ${order}: cabe en un Write (${own.length} tuplas) y salió en ${batches.length}`)
        }
        if (batches.flat().length !== own.length) violations.push(`${r.label} · ${order}: los Write no borran exactamente lo leído`)
        const removed = new Set<PurgeTuple>()
        for (let k = 0; k <= batches.length; k++) {
          const state = r.store.filter((t) => !removed.has(t))
          if (simulatedCheck(state, r.victim, 'viewer', V)) {
            violations.push(
              `${r.label} · ${order} · tras ${k} de ${batches.length} Write: CONCEDE (lotes [${batches.map((b) => b.length).join(', ')}]; ` +
                `aplicado: ${batches
                  .slice(0, k)
                  .map((b) => b.filter((t) => t.object.startsWith('group:') || t.relation.startsWith('denied_')).map((t) => `${t.object}#${t.relation}@${t.user}`).join(' ') || `${b.length} allows`)
                  .join(' | ')})`
            )
          }
          if (k < batches.length) for (const t of batches[k]) removed.add(t)
        }
      }
    }
    assert.deepEqual(violations, [], `ROJO (${property.id}): un estado intermedio de la purga concede, o una purga que cabe no es UN Write — ${violations.join(' ;; ')}`)
  })
})

/**
 * **`relations.reconcile.order`** (lote D · D2; S4/S5; cierre 1 de D2 · 🟠 1): la pasada de `reconcileRelations` sobre
 * dos dobles en memoria, cortada por un espía tras CADA escritura posible (k = 0…n), con el origen enumerado en SU orden
 * y en el INVERSO (el 🟠 1: el orden de la pasada no puede depender de cuál enumera primero el origen — `database` lo
 * hace por uuid v7, o sea por orden de creación). El orden lo decide el punto de paso ÚNICO `relationWriteOrder` /
 * `relationDeleteOrder` (`src/relations/tuple_order.ts`, compartido con `purgeWrites`). Filas: deny directo, corte de
 * camino, deny por grupo, deny ANIDADO, membresía portadora antes que la de un grupo con un allow que el destino ya
 * tenía, y la poda (allow + deny sobrantes; membresía portadora al final). En toda fila ni el estado inicial ni el final
 * del destino conceden a la víctima: ningún estado intermedio puede concederle. Sin servidor (job `guard-mutants`).
 */
test.group('GS · P · relations.reconcile.order (lote D · D2, linaje L10)', () => {
  const property = GUARD_PROPERTIES.find((p) => p.id === 'relations.reconcile.order')!
  const caps: RelationsDriverCapabilities = { ...FULL, relationDenies: true }
  const mk = () => makeRelationsDriver({ config: contractRelationsConfig(), capabilities: caps })
  const writesOf = ['relate', 'unrelate', 'deny', 'removeDeny']
  function cutAfter(driver: RelationsDriver, k: number): RelationsDriver {
    let n = 0
    return new Proxy(driver as any, {
      get(target, prop) {
        const value = Reflect.get(target, prop, target)
        if (typeof prop === 'string' && writesOf.includes(prop) && typeof value === 'function') {
          return async (...args: any[]) => {
            if (n >= k) throw new AuthorizationBackendError('doble', 'reconcile', new Error('corte inyectado'))
            n++
            return value.apply(target, args)
          }
        }
        return typeof value === 'function' ? value.bind(target) : value
      },
    }) as RelationsDriver
  }
  /** El origen enumerado al REVÉS (cada página invertida; el doble da una sola página): el otro orden de enumeración. */
  function reversedEnumeration(driver: RelationsDriver): RelationsDriver {
    return new Proxy(driver as any, {
      get(target, prop) {
        const value = Reflect.get(target, prop, target)
        if ((prop === 'enumerateRelations' || prop === 'enumerateRelationsMany') && typeof value === 'function') {
          return async (...args: any[]) => {
            const page = await value.apply(target, args)
            return { ...page, tuples: [...page.tuples].reverse() }
          }
        }
        return typeof value === 'function' ? value.bind(target) : value
      },
    }) as RelationsDriver
  }
  test(property.title, async ({ assert }) => {
    const violations: string[] = []
    const p: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const u: SubjectRef = { type: 'user', uuid: uuidv7() }
    const d = { type: 'document', id: uuidv7() }
    const keep = { type: 'document', id: uuidv7() }
    // Grupos con ids en orden CONOCIDO (uuid v7 crece): `gFirst` < `gSecond`. Las filas de la portadora colocan el
    // grupo con el allow PRIMERO en ese orden, para que un orden «solo por objeto» se equivoque.
    const gFirst = { type: 'group', id: uuidv7() }
    const gSecond = { type: 'group', id: uuidv7() }
    const h = { type: 'group', id: uuidv7() }
    const member = (g: { type: string; id: string }) => ({ object: g, relation: 'member' })
    type Row = {
      label: string
      source: (x: RelationsDriver) => Promise<void>
      dest: (x: RelationsDriver) => Promise<void>
      prune: boolean
      victim: [string, typeof d]
      cuts?: true
      /** Cierre 3 de D2: lo que el destino ENUMERA de más sin que conecte nada (un deny vencido escrito a mano). */
      extra?: () => any[]
      /** Cierre 4 de D2 · 🟡 horizonte: un instante POSTERIOR en el que cada prefijo (y el final) también se comprueba. */
      horizon?: Date
      /** Cierre 5 de D2 (opción A): la PARTICIÓN se niega — la pasada no escribe NADA (y el destino niega igual). */
      refused?: true
      /**
       * Cierre 5 de D2 (`c4h.plan.shortening-not-passed` al corredor): la fila solo se juzga en el HORIZONTE — en `now` el
       * estado final (el origen) SÍ concede; lo vigilado es el instante en que vence la caducidad NUEVA.
       */
      horizonOnly?: true
    }
    /** El destino que además enumera `extra()` (sin escribirlo: no conecta nada, como una tupla vencida). */
    const withExtra = (driver: RelationsDriver, extra?: () => any[]): RelationsDriver =>
      !extra
        ? driver
        : (new Proxy(driver as any, {
            get(target, prop) {
              const value = Reflect.get(target, prop, target)
              if (prop === 'enumerateRelations' && typeof value === 'function') {
                return async (...args: any[]) => {
                  const page = await value.apply(target, args)
                  return { ...page, tuples: [...page.tuples, ...extra()] }
                }
              }
              return typeof value === 'function' ? value.bind(target) : value
            },
          }) as RelationsDriver)
    // Cierre 3 de D2 (🟠 C2-1 / 🟡 C2-2): instante ya VENCIDO para las filas de vigencia, y un tercer grupo.
    const past = new Date(Date.now() - 3_600_000)
    const soon = new Date(Date.now() + 3_600_000)
    const k3 = { type: 'group', id: uuidv7() }
    const rows: Row[] = [
      { label: 'deny directo (allow + deny del mismo hecho)', prune: false, victim: ['viewer', d], dest: async () => {},
        source: async (x) => { await x.relate(u, 'viewer', d, p); await x.deny!(u, 'viewer', d, p) } },
      { label: 'corte de camino (owner, deny en editor)', prune: false, victim: ['owner', d], dest: async () => {},
        source: async (x) => { await x.relate(u, 'owner', d, p); await x.deny!(u, 'editor', d, p) } },
      { label: 'deny por grupo', prune: false, victim: ['viewer', d], dest: async () => {},
        source: async (x) => { await x.relate(u, 'viewer', d, p); await x.relate(u, 'member', gFirst, p); await x.deny!(member(gFirst), 'viewer', d, p) } },
      { label: 'deny anidado (U ∈ h ⊂ g, deny en g#member)', prune: false, victim: ['viewer', d], dest: async () => {},
        source: async (x) => {
          await x.relate(u, 'viewer', d, p)
          await x.relate(member(h), 'member', gFirst, p)
          await x.relate(u, 'member', h, p)
          await x.deny!(member(gFirst), 'viewer', d, p)
        } },
      { label: 'portadora antes que la membresía de un grupo cuyo allow el destino YA tenía', prune: false, victim: ['viewer', d],
        dest: async (x) => { await x.relate(member(gFirst), 'viewer', d, p) },
        source: async (x) => {
          await x.relate(member(gFirst), 'viewer', d, p)
          await x.relate(u, 'member', gFirst, p)
          await x.relate(u, 'member', gSecond, p)
          await x.deny!(member(gSecond), 'viewer', d, p)
        } },
      { label: 'portadora ANIDADA (U ∈ h ⊂ g, deny en g#member) antes que la membresía de un grupo cuyo allow el destino YA tenía', prune: false, victim: ['viewer', d],
        dest: async (x) => { await x.relate(member(gFirst), 'viewer', d, p) },
        source: async (x) => {
          await x.relate(member(gFirst), 'viewer', d, p)
          await x.relate(u, 'member', gFirst, p)
          await x.relate(u, 'member', h, p)
          await x.relate(member(h), 'member', gSecond, p)
          await x.deny!(member(gSecond), 'viewer', d, p)
        } },
      { label: 'poda de un allow + deny sobrantes', prune: true, victim: ['viewer', d],
        source: async (x) => { await x.relate(u, 'viewer', keep, p) },
        dest: async (x) => { await x.relate(u, 'viewer', keep, p); await x.relate(u, 'viewer', d, p); await x.deny!(u, 'viewer', d, p) } },
      // Cierre 2 de D2 · 🟡 N3 (C2 del auditor): el ex-miembro compone con un allow NUEVO — hasta el cierre 2 TODAS las
      // escrituras iban antes que TODA la poda y, cortada tras la 1.ª, U concedía sobre d.
      { label: 'N3 · el ex-miembro (U ∈ g sobra) no compone con el allow nuevo de g (--prune)', prune: true, victim: ['viewer', d],
        dest: async (x) => { await x.relate(u, 'member', gFirst, p) },
        source: async (x) => { await x.relate(member(gFirst), 'viewer', d, p) } },
      // Cierre 2 de D2 · 🟡 N3: la composición ANIDADA — U ∈ h entra y h ⊂ g sale; g concede d.
      { label: 'N3 · composición anidada: U ∈ h entra y h ⊂ g sale (--prune)', prune: true, victim: ['viewer', d],
        dest: async (x) => { await x.relate(member(h), 'member', gFirst, p); await x.relate(member(gFirst), 'viewer', d, p) },
        source: async (x) => { await x.relate(u, 'member', h, p); await x.relate(member(gFirst), 'viewer', d, p) } },
      // Cierre 2 de D2 · 🟡 N2: el OTRO grupo solo transporta un deny (no es mixto): gFirst concede d y deniega keep; h
      // solo deniega d. U entra en los dos: la membresía de h (deny sobre d) antes que la de gFirst (allow sobre d).
      { label: 'N2 · la membresía del grupo que solo DENIEGA va antes que la del grupo mixto (allow aquí, deny allí)', prune: false, victim: ['viewer', d],
        dest: async (x) => { await x.relate(member(gFirst), 'viewer', d, p); await x.deny!(member(gFirst), 'viewer', keep, p); await x.deny!(member(h), 'viewer', d, p) },
        source: async (x) => {
          await x.relate(member(gFirst), 'viewer', d, p)
          await x.deny!(member(gFirst), 'viewer', keep, p)
          await x.deny!(member(h), 'viewer', d, p)
          await x.relate(u, 'member', gFirst, p)
          await x.relate(u, 'member', h, p)
        } },
      // Cierre 2 de D2 · 🟡 N3: en UNA secuencia, el allow sobrante (fase 2) se borra ANTES que la membresía que
      // transporta su deny (fase 3).
      { label: 'poda: el allow sobrante se borra ANTES que la membresía que transporta su deny', prune: true, victim: ['viewer', d],
        source: async (x) => { await x.deny!(member(gFirst), 'viewer', d, p) },
        dest: async (x) => { await x.relate(u, 'viewer', d, p); await x.relate(u, 'member', gFirst, p); await x.deny!(member(gFirst), 'viewer', d, p) } },
      { label: 'poda: la membresía portadora se borra la ÚLTIMA', prune: true, victim: ['viewer', d],
        source: async (x) => { await x.relate(member(gSecond), 'viewer', d, p); await x.deny!(member(gFirst), 'viewer', d, p) },
        dest: async (x) => {
          await x.relate(member(gSecond), 'viewer', d, p)
          await x.deny!(member(gFirst), 'viewer', d, p)
          await x.relate(u, 'member', gFirst, p)
          await x.relate(u, 'member', gSecond, p)
        } },
      // Cierre 3 de D2 · 🟠 C2-1: la membresía PORTADORA está VENCIDA en el destino y viva en el origen, y el allow es
      // nuevo. Hasta el cierre 3 el plan la tomaba por viva: `renewal-unsafe` (no se escribía) con el allow escrito ⇒ el
      // destino concedía para siempre (doble sin atomicRenewal); en un destino atómico, la «renovación» iba a la fase 4,
      // detrás del allow (R5).
      { label: 'C2-1 · portadora VENCIDA en el destino: su reescritura es una escritura (fase 3), no una renovación', prune: false, victim: ['viewer', d],
        dest: async (x) => { await x.relate(u, 'member', h, p, { expiresAt: past }); await x.deny!(member(h), 'viewer', d, p) },
        source: async (x) => { await x.relate(u, 'member', h, p); await x.relate(u, 'viewer', d, p); await x.deny!(member(h), 'viewer', d, p) } },
      // Cierre 3 de D2 · 🟡 C2-2 (R7 del auditor): una arista VENCIDA solo en el destino (gFirst ⊂ k3, k3 deniega d) no
      // corta el allow de gFirst para el auto-corte: U entra en h (deniega d) ANTES que en gFirst (concede d).
      { label: 'C2-2 · una arista VENCIDA del destino no cuenta para el auto-corte (con la config del destino)', prune: false, victim: ['viewer', d], cuts: true,
        dest: async (x) => {
          await x.relate(member(gFirst), 'viewer', d, p)
          await x.deny!(member(k3), 'viewer', d, p)
          await x.deny!(member(h), 'viewer', d, p)
          await x.relate(member(gFirst), 'member', k3, p, { expiresAt: past })
        },
        source: async (x) => {
          await x.relate(member(gFirst), 'viewer', d, p)
          await x.deny!(member(k3), 'viewer', d, p)
          await x.deny!(member(h), 'viewer', d, p)
          await x.relate(u, 'member', gFirst, p)
          await x.relate(u, 'member', h, p)
        } },
      // Cierre 3 de D2 · 🟡 C2-2 (medido por la fuerza bruta con vigencia): una sobrante VENCIDA que se poda (h ⊂ k3, k3
      // deniega d) no entra en el orden — dentro, el grafo unión la tomaba por un deny que «ya niega» a h y U entraba en
      // h antes de que h ⊂ gFirst (que concede d) saliera.
      { label: 'C2-2 · una sobrante VENCIDA se poda antes y fuera del orden (--prune)', prune: true, victim: ['viewer', d],
        dest: async (x) => {
          await x.relate(member(h), 'member', gFirst, p)
          await x.relate(member(gFirst), 'viewer', d, p)
          await x.deny!(member(k3), 'viewer', d, p)
          await x.relate(member(h), 'member', k3, p, { expiresAt: past })
        },
        source: async (x) => {
          await x.relate(u, 'member', h, p)
          await x.relate(member(gFirst), 'viewer', d, p)
          await x.deny!(member(k3), 'viewer', d, p)
        } },
      // Cierre 3 de D2 · 🟡 C2-2 (el contraejemplo de la fuerza bruta con vigencia): un deny VENCIDO del destino (escrito a
      // mano con condición, M5) que se poda no entra en el orden — dentro, el grafo unión lo tomaba por un deny que «ya
      // niega» a h, y U entraba en h antes de que h ⊂ gFirst (que concede d) saliera.
      { label: 'C2-2 · un deny VENCIDO que se poda va antes y FUERA del orden (--prune, con la config del destino)', prune: true, victim: ['viewer', d], cuts: true,
        extra: () => [{ subject: member(h), relation: 'viewer', object: d, partition: p, kind: 'deny', expiresAt: past }],
        dest: async (x) => { await x.relate(member(h), 'member', gFirst, p); await x.relate(member(gFirst), 'viewer', d, p) },
        source: async (x) => { await x.relate(u, 'member', h, p); await x.relate(member(gFirst), 'viewer', d, p) } },
      // Cierre 5 de D2 (C3 ya no usa el auto-corte, así que las dos filas C2-2 de arriba dejaron de matar a
      // `rec.apply.expired-deletes-in-order`): un deny VENCIDO del grupo que CONCEDE, sobrante y podado, dentro del orden
      // cortaría (auto-corte) el allow de ese grupo y C1 dejaría entrar a U en gFirst antes que en h (que deniega d).
      { label: 'C2-2 · un deny VENCIDO del grupo que concede, podado, no corta su allow en el orden (--prune, con la config del destino)', prune: true, victim: ['viewer', d], cuts: true,
        extra: () => [{ subject: member(gFirst), relation: 'viewer', object: d, partition: p, kind: 'deny', expiresAt: past }],
        dest: async (x) => { await x.relate(member(gFirst), 'viewer', d, p); await x.deny!(member(h), 'viewer', d, p) },
        source: async (x) => {
          await x.relate(member(gFirst), 'viewer', d, p)
          await x.deny!(member(h), 'viewer', d, p)
          await x.relate(u, 'member', gFirst, p)
          await x.relate(u, 'member', h, p)
        } },
      // Cierre 4 de D2 · 🟠 C3-1 → cierre 5 (opción A): la portadora está VIVA en el destino con una caducidad MÁS CORTA
      // que la del origen (renewal-unsafe en el doble sin atomicRenewal) y el allow es nuevo: hasta el cierre 4 el allow se
      // escribía y, al vencer la caducidad vieja, el destino concedía. Desde el cierre 5 la PARTICIÓN se niega: cero
      // escrituras, y el destino niega en `now` y en el HORIZONTE (reloj del doble).
      { label: 'C3-1 · portadora viva que vence ANTES que en el origen: la PARTICIÓN se niega, cero escrituras (horizonte)', prune: false, victim: ['viewer', d], horizon: new Date(soon.getTime() + 1_000), refused: true,
        dest: async (x) => { await x.relate(u, 'member', h, p, { expiresAt: soon }); await x.deny!(member(h), 'viewer', d, p) },
        source: async (x) => {
          await x.relate(u, 'member', h, p, { expiresAt: new Date(Date.now() + 86_400_000) })
          await x.relate(u, 'viewer', d, p)
          await x.relate(u, 'viewer', keep, p)
          await x.deny!(member(h), 'viewer', d, p)
        } },
      // Cierre 4 de D2 · 🟡 C3-2 → cierre 5 (opción A): un deny CONDICIONAL vencido del destino (escrito a mano) que el
      // origen tiene: el doble sin atomicRenewal no puede rehacerlo (deny-conditional, en el plan) y la PARTICIÓN se niega.
      // Cierre 4 de D2 · 🟡 horizonte (al corredor en el cierre 5): una renovación que ACORTA un allow va con los borrados,
      // ANTES de que salga la membresía que transporta su deny; en el instante en que vence la caducidad NUEVA ni el inicial
      // (la membresía lo deniega) ni el origen (el allow ya venció) conceden.
      { label: 'horizonte · una renovación que ACORTA un allow va ANTES de que salga la membresía portadora (--prune)', prune: true, victim: ['viewer', d], horizon: new Date(Date.now() + 1_801_000), horizonOnly: true,
        dest: async (x) => {
          await x.deny!(member(h), 'viewer', d, p)
          await x.relate(u, 'viewer', d, p, { expiresAt: soon })
          await x.relate(u, 'member', h, p, { expiresAt: soon })
        },
        source: async (x) => {
          await x.deny!(member(h), 'viewer', d, p)
          await x.relate(u, 'viewer', d, p, { expiresAt: new Date(Date.now() + 1_800_000) })
        } },
      { label: 'C3-2 · deny condicional VENCIDO que el origen tiene: la PARTICIÓN se niega, cero escrituras', prune: false, victim: ['viewer', d], refused: true,
        extra: () => [{ subject: u, relation: 'viewer', object: d, partition: p, kind: 'deny', expiresAt: past }],
        dest: async () => {},
        source: async (x) => { await x.relate(u, 'viewer', d, p); await x.relate(u, 'viewer', keep, p); await x.deny!(u, 'viewer', d, p) } },
    ]
    const toConfig = contractRelationsConfig()
    for (const r of rows) {
      const base = mk()
      await r.source(base)
      for (const [order, from] of [['orden de enumeración del origen', base], ['orden INVERSO', reversedEnumeration(base)]] as const) {
        // Cuántas escrituras hace la pasada completa: una corrida sin corte.
        const probe = mk()
        await r.dest(probe)
        if (!r.horizonOnly && (await probe.check(u, r.victim[0], r.victim[1], p))) violations.push(`${r.label}: el estado INICIAL concede (la fila está mal construida)`)
        let total = 0
        await reconcileRelations({ from, to: new Proxy(withExtra(probe, r.extra) as any, { get(t, prop) { const v = Reflect.get(t, prop, t); return typeof prop === 'string' && writesOf.includes(prop) && typeof v === 'function' ? async (...a: any[]) => { total++; return v.apply(t, a) } : typeof v === 'function' ? v.bind(t) : v } }), partition: p, prune: r.prune, toConfig: r.cuts ? toConfig : undefined })
        if (!r.horizonOnly && (await probe.check(u, r.victim[0], r.victim[1], p))) violations.push(`${r.label}: el estado FINAL concede (la fila está mal construida)`)
        if (r.refused && total !== 0) violations.push(`${r.label}: la partición NEGADA escribe ${total} vez/veces (opción A: cero escrituras)`)
        if (!r.refused && total === 0) violations.push(`${r.label}: la pasada no escribe nada (la fila está mal construida)`)
        for (let k = 0; k <= total; k++) {
          const to = mk()
          await r.dest(to)
          await reconcileRelations({ from, to: cutAfter(withExtra(to, r.extra), k), partition: p, prune: r.prune, toConfig: r.cuts ? toConfig : undefined }).catch(() => {})
          if (!r.horizonOnly && (await to.check(u, r.victim[0], r.victim[1], p))) violations.push(`${r.label} · ${order} · tras ${k} de ${total} escrituras: CONCEDE`)
          const later = r.horizon
          if (later && (await to.withClock!(() => later).check(u, r.victim[0], r.victim[1], p))) {
            violations.push(`${r.label} · ${order} · tras ${k} de ${total} escrituras: CONCEDE en el horizonte (${later.toISOString()})`)
          }
        }
      }
    }
    assert.deepEqual(violations, [], `ROJO (${property.id}): un estado intermedio del reconcile concede lo que ni el estado inicial ni el final concedían — ${violations.join(' ;; ')}`)
  })
})

/**
 * **`relations.order.exhaustive`** (cierre 2 de D2 · 🟡 N3; linaje L10 PROMOVIDO): la garantía del orden DEMOSTRADA por
 * fuerza bruta, no con tablas a mano. `tests/helpers/order_bruteforce.ts` recorre TODOS los pares (inicial, final) de
 * `E1-reduced` —1 usuario, 2 grupos con 1 nivel de anidamiento, 2 objetos, `viewer` con deny; 8 tuplas, con `--prune` y
 * sin él— y CADA prefijo del orden de `relationTransitionOrder`: un par sin ciclo en el grafo de precedencias no concede
 * fuera de inicial ∪ final ni a un denegado en los dos. Las cifras del residuo están fijadas (un cambio de orden las mueve
 * y pone rojo el caso). Los universos completos, en `tests/relations_order_exhaustive.spec.ts`. Sin servidor.
 */
test.group('GS · P · relations.order.exhaustive (cierre 2 de D2 · 🟡 N3, linaje L10)', () => {
  const property = GUARD_PROPERTIES.find((p) => p.id === 'relations.order.exhaustive')!
  test(property.title, ({ assert }) => {
    const r = bruteForce('E1-reduced', packageOrder(ORDER_CUTS))
    assert.equal(r.pairs, 131_072)
    assert.equal(r.malformed, 0, `ROJO (${property.id}): el orden no es una permutación del diff o no llega al estado final`)
    assert.equal(r.unsafeWithoutResidue, 0, `ROJO (${property.id}): un par SIN residuo concede en un prefijo — ${r.examples.join(' ;; ')}`)
    // Cierre 5 de D2: el oráculo cuenta los objetos `group:` (D4-2) y C3 cuenta la membresía como concesión; C4 con la
    // exclusión de C2. Cifras re-medidas (antes 1 140 / 210 / 88).
    assert.deepEqual(
      { residuePairs: r.residuePairs, unsafe: r.unsafe, inherent: r.inherent },
      { residuePairs: 1044, unsafe: 204, inherent: 88 },
      `ROJO (${property.id}): las cifras del residuo cambiaron — re-mídelas y reescribe README/CHANGELOG si el orden cambió a propósito`
    )
    // Cierre 3 de D2 · 🟡 C2-2: la VIGENCIA en el universo (el plan la deriva por `liveInDestination`). Muestra declarada.
    for (const atomic of [true, false]) {
      const v = bruteForceVigencia('E1-reduced', packageOrder(ORDER_CUTS), { atomic, sample: 50_000 })
      const label = atomic ? 'atómico' : 'dos Write'
      assert.equal(v.malformed, 0, `ROJO (${property.id}) · vigencia · ${label}: el estado alcanzado no es el final — ${v.examples.join(' ;; ')}`)
      assert.equal(v.unsafeWithoutResidue, 0, `ROJO (${property.id}) · vigencia · ${label}: un par SIN residuo concede — ${v.examples.join(' ;; ')}`)
      // Cierre 4 de D2 · 🟡 horizonte; cierre 5 (opción A): ocho estados, el horizonte (`now`, +30 min, +1 h), la
      // partición NEGADA (`renewal-unsafe` / `deny-conditional`) como ÚNICA exclusión; cifras POR MODO.
      assert.deepEqual(
        { residuePairs: v.residuePairs, unsafe: v.unsafe, inherent: v.inherent, renewalUnsafe: v.renewalUnsafe, denyConditional: v.denyConditional, refused: v.refused },
        atomic
          ? { residuePairs: 2506, unsafe: 306, inherent: 80, renewalUnsafe: 0, denyConditional: 0, refused: 0 }
          : { residuePairs: 187, unsafe: 50, inherent: 24, renewalUnsafe: 59_798, denyConditional: 74_725, refused: 76_389 },
        `ROJO (${property.id}) · vigencia · ${label}: las cifras cambiaron`
      )
    }
    // Cierre 5 de D2 · los contraejemplos LITERALES (tester del panel «óptimo»): mutantes que la muestra no ve y que hasta
    // aquí solo morían por cifras.
    //  - C4 (U2, --prune): U2 sale de g (que le niega Y) y entra en h (que también se lo niega); sin C4, sale antes.
    const c4 = walkPair('U2', packageOrder(ORDER_CUTS), pick('U2', 'g@u2', 'g@h#member', 'y@u2', 'x@g#member', '¬y@g#member'), pick('U2', 'h@u2', 'y@u2', 'x@g#member', '¬y@h#member'))
    assert.isNull(c4.bad, `ROJO (${property.id}) · literal C4 (U2): concede tras ${c4.bad} — [${c4.steps.join(' ')}]`)
    //  - una RENOVACIÓN que acorta (b ⊂ c) es una arista que CAMBIA (E3, 8 tuplas, --prune, destino atómico).
    const e3 = walkVigencia(
      'E3',
      packageOrder(ORDER_CUTS),
      ['a@u1:absent/same', 'b@u1:live/absent', 'b@a#member:live/absent', 'c@b#member:live/shorter', 'x@b#member:live/same', 'y@c#member:live/same', '¬y@b#member:absent/same', '¬x@c#member:live/same'],
      { prune: true, atomic: true }
    )
    assert.isTrue(e3.bad === null && !e3.finalBad, `ROJO (${property.id}) · literal de las renovaciones (E3): concede tras ${e3.bad} — [${e3.steps.join(' ')}]`)
    //  - C3 cuenta la MEMBRESÍA como concesión (D4-2): +U∈h antes de -h⊂g haría a U miembro de g, que ni el inicial ni el final.
    const c3 = walkPair('E1-reduced', packageOrder(ORDER_CUTS), pick('E1-reduced', 'g@h#member'), pick('E1-reduced', 'h@u1'))
    assert.isNull(c3.bad, `ROJO (${property.id}) · literal C3 (membresía): concede tras ${c3.bad} — [${c3.steps.join(' ')}]`)
  }).timeout(60_000)
})

/**
 * **`openfga.roles.purgeScope.order`** (lote D · D2, addendum; linaje L10 en ROLES): `purgeScope` del driver de roles
 * (`facts`) sobre un cliente FGA en MEMORIA (sin servidor), cortada por el cliente tras CADA `deleteTuples` (k = 0…n).
 * El store: un rol vinculado en el scope (estructura `role_binding#role` + `scope#binding`), 150 asignaciones (hechos
 * `assignee`, dos lotes) y 150 denies del scope (dos lotes), entre ellos la VÍCTIMA: asignada Y denegada — no concede
 * al inicio ni al final. El oráculo es (c2r) reducido al scope: concede ⇔ assignee ∧ role ∧ binding ∧ ¬denied.
 */
test.group('GS · P · openfga.roles.purgeScope.order (lote D · D2, linaje L10)', (group) => {
  const property = GUARD_PROPERTIES.find((p) => p.id === 'openfga.roles.purgeScope.order')!
  const scopeType = 'gsorder'
  const roleUuid = uuidv7()
  group.setup(async () => {
    const now = new Date()
    await db.table('authz_roles').insert({ uuid: roleUuid, slug: 'gs-order', name: 'gs-order', scope_type: scopeType, rank: 1, owner_scope_key: 'global', created_at: now, updated_at: now })
    return async () => {
      await db.from('authz_roles').where('uuid', roleUuid).delete()
    }
  })
  test(property.title, async ({ assert }) => {
    const scope = { type: scopeType, uuid: uuidv7() }
    const key = `${scopeType}|${scope.uuid}`
    const rb = `role_binding:${key}|${roleUuid}`
    const scopeObject = `scope:${key}`
    const victim = `user:${uuidv7()}`
    type T = { user: string; relation: string; object: string }
    const initial = (): T[] => [
      { user: `role:${roleUuid}`, relation: 'role', object: rb },
      { user: rb, relation: 'binding', object: scopeObject },
      { user: victim, relation: 'assignee', object: rb },
      { user: victim, relation: 'denied_docs_read', object: scopeObject },
      ...Array.from({ length: 149 }, (_, i) => ({ user: `user:a${i}`, relation: 'assignee', object: rb })),
      ...Array.from({ length: 149 }, (_, i) => ({ user: `user:d${i}`, relation: 'denied_docs_read', object: scopeObject })),
    ]
    const grants = (store: T[]) => {
      const has = (t: T) => store.some((x) => x.user === t.user && x.relation === t.relation && x.object === t.object)
      return (
        has({ user: victim, relation: 'assignee', object: rb }) &&
        has({ user: `role:${roleUuid}`, relation: 'role', object: rb }) &&
        has({ user: rb, relation: 'binding', object: scopeObject }) &&
        !has({ user: victim, relation: 'denied_docs_read', object: scopeObject })
      )
    }
    const run = async (
      cutAfter: number | undefined,
      seed: () => T[] = initial,
      hooks: { raceBeforeDelete?: (nth: number) => T[]; failRead?: (filter: any) => boolean } = {}
    ) => {
      let store = seed()
      let calls = 0
      const driver: any = new OpenFgaAuthorizationDriver({ apiUrl: 'http://127.0.0.1:1', storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV', modelId: TEST_MODEL_ID, holderTypes: { users: 'user' }, acceptScopeDriftRisk: true, logger: { warn: () => {} } } as any)
      driver.client = {
        // L11: la puerta lee el modelo fijado UNA vez; el falso sirve el que genera la config.
        readAuthorizationModel: async () => ({ authorization_model: generatedModel({ users: 'user' }, ['docs:read']) }),
        read: async (filter: any) => {
          if (hooks.failRead?.(filter)) throw new AuthorizationBackendError('openfga', 'read', new Error('fallo inyectado'))
          return {
            tuples: store.filter((t) => t.object === filter.object && (!filter.relation || t.relation === filter.relation)).map((k) => ({ key: k })),
            continuation_token: '',
          }
        },
        deleteTuples: async (keys: T[]) => {
          if (cutAfter !== undefined && calls >= cutAfter) throw new AuthorizationBackendError('openfga', 'deleteTuples', new Error('corte inyectado'))
          // Un `grant` concurrente que aterriza JUSTO antes de este Write (después de las lecturas previas).
          store = [...store, ...(hooks.raceBeforeDelete?.(calls) ?? [])]
          calls++
          store = store.filter((t) => !keys.some((k) => k.user === t.user && k.relation === t.relation && k.object === t.object))
        },
      }
      let partial = false
      const outcome = await driver.purgeScope(scope).then(
        () => 'ok',
        (e: any) => {
          partial = isPartialWrite(e)
          return String(e?.code)
        }
      )
      return { store, calls, outcome, partial }
    }
    const full = await run(undefined)
    const violations: string[] = []
    if (full.outcome !== 'ok') violations.push(`la purga entera no terminó: ${full.outcome}`)
    if (grants(initial())) violations.push('la fila está mal construida: el estado inicial concede')
    if (grants(full.store)) violations.push('el estado FINAL concede')
    for (let k = 0; k < full.calls; k++) {
      const cut = await run(k)
      if (grants(cut.store)) violations.push(`tras ${k} de ${full.calls} Write: CONCEDE`)
      // Cierre 4 de D2 · ⚪ C3-4 (invariante 13): cortada DESPUÉS de borrar (k ≥ 1: la estructura existe y el 1.er Write
      // la borró), el error va marcado parcial; cortada en el 1.º, no.
      if (cut.partial !== k >= 1) violations.push(`tras ${k} de ${full.calls} Write: marca parcial ${cut.partial} (esperada ${k >= 1})`)
    }
    // Cierre 5 de D2 · ⚪ D4-5: un scope SIN estructura (roles del catálogo sin bindings aquí: el 1.er Write, la
    // estructura a ciegas, no borra NADA) y con denies: cortada en el 2.º Write, NO hay escritura hecha ⇒ sin marca parcial.
    const bare = (): T[] => Array.from({ length: 150 }, (_, i) => ({ user: `user:d${i}`, relation: 'denied_docs_read', object: scopeObject }))
    const bareCut = await run(1, bare)
    if (bareCut.outcome === 'ok') violations.push('la fila D4-5 está mal construida: la purga sin estructura terminó')
    if (bareCut.partial) violations.push('D4-5: la purga sin estructura cortada en el 2.º Write sale marcada parcial (contaba claves pedidas, no borradas)')
    // Cierre 6 de D2 · ⚪ D5-4: un `grant` concurrente escribe sus TRES tuplas en el scope sin estructura ENTRE la lectura
    // previa y el borrado a ciegas de la fase 1 (que se lleva su `#role` y su `#binding` sin contarlos), y la siguiente
    // request —la lectura de la fase 2, o su `deleteTuples`— falla: el error tiene que ir marcado PARCIAL (se borraron
    // aristas que cambiaban una respuesta). Sobre-notificar, nunca sub-.
    const racer = `user:${uuidv7()}`
    const race = (nth: number): T[] =>
      nth === 0
        ? [
            { user: `role:${roleUuid}`, relation: 'role', object: rb },
            { user: rb, relation: 'binding', object: scopeObject },
            { user: racer, relation: 'assignee', object: rb },
          ]
        : []
    const raceRead = await run(undefined, bare, { raceBeforeDelete: race, failRead: (f) => f.object === rb })
    if (raceRead.outcome === 'ok') violations.push('la fila D5-4 (lectura) está mal construida: la purga terminó')
    if (!raceRead.partial) violations.push('D5-4: un grant concurrente borrado a ciegas por la fase 1 y la lectura de la fase 2 que falla ⇒ el error sale SIN marca parcial (sub-notifica)')
    const raceWrite = await run(1, bare, { raceBeforeDelete: race })
    if (raceWrite.outcome === 'ok') violations.push('la fila D5-4 (escritura) está mal construida: la purga terminó')
    if (!raceWrite.partial) violations.push('D5-4: un grant concurrente borrado a ciegas por la fase 1 y el Write de la fase 2 que falla ⇒ el error sale SIN marca parcial (sub-notifica)')
    assert.isAbove(full.calls, 3, 'la purga son varios Write (si no, no hay estados intermedios que juzgar)')
    assert.deepEqual(violations, [], `ROJO (${property.id}): ${violations.join(' ;; ')}`)
  })
})

/**
 * **`openfga.roles.moved.order`** (lote «antes de RC» · F4; decisión del dueño (6b-estudio), opción E; linaje L10 en el
 * ÁRBOL de roles): `scopes.moved` —y su gemelo, el `attached` de un hijo que el árbol ya conoce (es un move)— del driver
 * de roles en `facts`, sobre un cliente FGA en MEMORIA cortado tras CADA `Write` (k = 0…n), con el INTÉRPRETE del modelo
 * generado como oráculo (`tests/helpers/fga_interpreter.ts`). El universo: un rol LOCAL de la org A asignado en la unit C
 * y en sus 149 hijas (150 `scope#binding`: dos lotes del barrido), con la VÍCTIMA (asignada en C y en la última hija)
 * denegada en A. Dos sentidos: SALIR del owner (C de A a B: el prefijo «arista y después barrido» concedía saltándose el
 * deny, 🟠 del auditor del estudio, 15,9 % medido) y ENTRAR (C de B a A, con los bindings barridos: escribirlos antes de
 * la arista concedería bajo B). Se juzga: (1) ningún estado cortado concede lo que no concedían el inicial ni el final;
 * (2) el comprobador del intérprete sobre los `Write` EFECTIVOS no encuentra ningún `prefix` (queda el `torn` declarado:
 * dos escrituras en un `Check`) y su CONTROL POSITIVO —los mismos `Write` en el orden de antes de F4— sí; (3) cortado tras
 * ≥ 1 `Write` el error va marcado PARCIAL y antes no (invariante 13); (4) el reintento desde cada corte (el relay)
 * converge al mismo final sin estados que concedan de más —el corte tras la arista entra por el atajo idempotente, que
 * barre—; (5) un `grant` del rol local que aterriza ENTRE el barrido previo y la arista no deja nada concediendo fuera del
 * owner (el barrido de después es COMPLETO: borra y escribe).
 */
test.group('GS · P · openfga.roles.moved.order (lote «antes de RC» · F4, linaje L10)', () => {
  const property = GUARD_PROPERTIES.find((p) => p.id === 'openfga.roles.moved.order')!
  // Cierre de F4 (tester del panel de carreras, `loteC-carreras-tester.md` punto 1): el doble lanza los conflictos con la
  // FORMA del SDK medida en R3 (`tests/fixtures/fga_errors/`), no `Error` a secas — si no, `isTreeWriteRace`/
  // `isDuplicateWrite` nunca reconocen la carrera y `reparent` lanza donde en producción relee y re-aplica.
  const sdkFixture = (id: string) => loadFgaFixtures().find((f) => f.id === id)!
  test(property.title, async ({ assert }) => {
    type T = { user: string; relation: string; object: string }
    const holders = { users: 'user' }
    const model = compileModel(generatedModel(holders, ['docs:read']))
    const at = { current_time: new Date().toISOString() }
    const key = (s: { type: string; uuid: string | null }) => (s.type === 'app' ? 'app' : `${s.type}|${s.uuid}`)
    const orgA = { type: 'organization', uuid: uuidv7() }
    const orgB = { type: 'organization', uuid: uuidv7() }
    // Cierre de F4 (🟡-2 del tester): dos departamentos DENTRO del owner, para mover C sin salir de A.
    const deptA1 = { type: 'department', uuid: uuidv7() }
    const deptA2 = { type: 'department', uuid: uuidv7() }
    const unitC = { type: 'unit', uuid: uuidv7() }
    const kids = Array.from({ length: 149 }, () => ({ type: 'unit', uuid: uuidv7() }))
    const role = { uuid: uuidv7(), slug: 'gs-lead', scopeType: 'unit', owner: key(orgA), rank: 10 }
    const view = { localRoles: () => [role], roleByUuid: (uuid: string) => (uuid === role.uuid ? role : null) }
    const victim = 'user:victim'
    const racer = 'user:racer'
    const assignments: Array<[string, string]> = [
      [victim, key(unitC)],
      [victim, key(kids[148])],
      ['user:plain', key(unitC)],
      ...kids.slice(0, 148).map((kid, i): [string, string] => [`user:p${i}`, key(kid)]),
    ]
    const requests = [...assignments, [racer, key(unitC)] as [string, string]].map(([user, scope]) => ({
      user,
      relation: 'can_docs_read',
      object: factsScopeObject(scope),
      context: at,
    }))
    const grants = (store: T[]) => {
      const state = new TupleStore(store)
      return requests.map((r) => checkTuples(model, state, r).verdict === 'T')
    }
    const same = (a: T, b: T) => a.user === b.user && a.relation === b.relation && a.object === b.object
    /** El store de partida: C bajo `from`, sus hijas bajo C; `swept` = sin `scope#binding` (fuera del owner, ya barrido). */
    const seed = (from: { type: string; uuid: string }, swept: boolean): T[] => {
      const scopes = [unitC, ...kids]
      return [
        ...factsRootTuples(holders),
        ...factsCatalogTuples([{ uuid: role.uuid, permissions: ['docs:read'] }] as any, holders),
        factsParentTuple(key(orgA), 'app'),
        factsParentTuple(key(orgB), 'app'),
        factsParentTuple(key(deptA1), key(orgA)),
        factsParentTuple(key(deptA2), key(orgA)),
        factsParentTuple(key(unitC), key(from)),
        ...kids.map((kid) => factsParentTuple(key(kid), key(unitC))),
        ...scopes.flatMap((s) => factsBindingTuples(key(s), role.uuid).filter((t) => !swept || t.relation !== 'binding')),
        ...assignments.map(([user, scope]) => ({ user, relation: 'assignee', object: factsBindingObject(scope, role.uuid) })),
        factsDenyTuple(key(orgA), 'docs:read', victim),
      ]
    }
    /** El `grant` concurrente del rol local en C (sus tres tuplas), que aterriza JUSTO antes del `Write` de la arista. */
    const raceTuples: T[] = [
      ...factsBindingTuples(key(unitC), role.uuid),
      { user: racer, relation: 'assignee', object: factsBindingObject(key(unitC), role.uuid) },
    ]
    const run = async (
      to: { type: string; uuid: string },
      start: T[],
      options: {
        op?: 'onScopeMoved' | 'onScopeAttached'
        cutAfter?: number
        race?: boolean
        /** El árbol del CONSUMIDOR, si no es el de siempre (C bajo `to`, las hijas bajo C): el caso del ciclo del store. */
        consumer?: Array<[{ type: string; uuid: string }, { type: string; uuid: string | null }]>
        /** Cierre de F4 (tester del panel de carreras, punto 1): el PRIMER `Write` de la arista choca con otro escritor. */
        edgeRaceOnce?: boolean
      } = {}
    ) => {
      let edgeRaced = false
      const tree = memoryScopeTree()
      await tree.attach(orgA, APP_SCOPE)
      await tree.attach(orgB, APP_SCOPE)
      await tree.attach(deptA1, orgA)
      await tree.attach(deptA2, orgA)
      if (options.consumer) for (const [child, parent] of options.consumer) await tree.attach(child as any, parent as any)
      else {
        await tree.attach(unitC, to)
        for (const kid of kids) await tree.attach(kid, unitC)
      }
      const driver: any = new OpenFgaAuthorizationDriver({
        apiUrl: 'http://127.0.0.1:1',
        storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
        modelId: TEST_MODEL_ID,
        holderTypes: holders,
        resolveChain: resolveChainFrom(tree),
        catalog: { view: async () => view },
        acceptScopeDriftRisk: true,
        logger: { warn: () => {} },
      } as any)
      // Sublote «asentar» (lote C, paso 1): el doble FIEL compartido (`tests/helpers/fga_memory_client.ts`) instalado DENTRO
      // del cliente del SDK que el driver envuelve — los errores pasan por el MISMO `guardBackendErrors`/`classifyFgaFailure`
      // que en producción, `onDuplicateWrites`/`onMissingDeletes` se honran POR SEPARADO y el corte es un 503 con la forma
      // del SDK (antes: un `AuthorizationBackendError` a mano saltándose el clasificador).
      const fga = new FgaMemoryStore({ model: generatedModel(holders, ['docs:read']), initial: start })
      const raceWriter = fga.client('racer')
      const applied = () => fga.trace.filter((e) => e.actor === 'mover' && e.kind === 'write' && e.result === 'ok').length
      const isEdge = (body: any) => (body?.writes ?? []).some((t: T) => t.relation === 'parent')
      installMemoryClient(
        driver,
        fga.client('mover', {
          onIo: async (event) => {
            // (5) El `grant` concurrente aterriza JUSTO antes del `Write` de la arista (sus tres tuplas, como otro proceso).
            if (options.race && event.kind === 'write' && isEdge(event.body)) {
              await raceWriter.write({ writes: raceTuples, deletes: [] }, { conflict: { onDuplicateWrites: 'ignore' } })
            }
          },
          fault: (event) => {
            if (event.kind !== 'write') return undefined
            if (options.cutAfter !== undefined && applied() >= options.cutAfter) return { error: sdkError('fake-503-unavailable') }
            // El servidor rechaza el `Write` entero (nada se aplica) con la forma MEDIDA del SDK: el borrado de la arista
            // vieja que otro escritor ya se llevó.
            if (options.edgeRaceOnce && isEdge(event.body) && !edgeRaced) {
              edgeRaced = true
              return { error: sdkError('real-delete-absent') }
            }
            return undefined
          },
        })
      )
      let partial = false
      const outcome = await driver[options.op ?? 'onScopeMoved'](unitC, to).then(
        () => 'ok',
        (e: any) => {
          partial = isPartialWrite(e)
          return String(e?.code ?? e?.message)
        }
      )
      const steps: WriteStep[] = fga.trace
        .filter((e) => e.actor === 'mover' && e.kind === 'write' && e.result === 'ok')
        .map((e) => ({ writes: e.writes ?? [], deletes: e.deletes ?? [] }))
      return { store: fga.tuples() as T[], calls: steps.length, steps, outcome, partial }
    }
    const violations: string[] = []
    const scenarios = [
      { name: 'SALIR del owner (A → B)', from: orgA, to: orgB, swept: false, op: 'onScopeMoved' as const },
      { name: 'SALIR del owner por attached de un hijo existente (A → B)', from: orgA, to: orgB, swept: false, op: 'onScopeAttached' as const },
      { name: 'ENTRAR en el owner (B → A)', from: orgB, to: orgA, swept: true, op: 'onScopeMoved' as const },
      // Cierre de F4 (🟡-4 del tester): la cuarta combinación dirección × operación.
      { name: 'ENTRAR en el owner por attached de un hijo existente (B → A)', from: orgB, to: orgA, swept: true, op: 'onScopeAttached' as const },
      // Cierre de F4 (🟡-2 del tester): mover DENTRO del owner (C de A1 a A2, los dos bajo A). Invariante 18: «un local cuyo
      // owner sigue siendo ancestro no se toca» ⇒ el barrido previo no borra NADA (0 Write antes de la arista) y ningún
      // corte PIERDE lo que conceden los dos extremos (mata «el previo borra de más», X1: `chain: [childKey]`).
      { name: 'MOVER DENTRO del owner (A1 → A2)', from: deptA1, to: deptA2, swept: false, op: 'onScopeMoved' as const, inside: true },
    ] as Array<{ name: string; from: { type: string; uuid: string }; to: { type: string; uuid: string }; swept: boolean; op: 'onScopeMoved' | 'onScopeAttached'; inside?: boolean }>
    for (const s of scenarios) {
      const initial = seed(s.from, s.swept)
      const full = await run(s.to, initial, { op: s.op })
      if (full.outcome !== 'ok') {
        violations.push(`${s.name}: el move entero no terminó: ${full.outcome}`)
        continue
      }
      const before = grants(initial)
      const after = grants(full.store)
      const allowed = before.map((b, i) => b || after[i])
      const excess = (store: T[]) =>
        grants(store)
          .map((g, i) => (g && !allowed[i] ? `${requests[i].user}@${requests[i].object}` : null))
          .filter((x): x is string => x !== null)
      // Las filas están bien construidas: la víctima no concede ni al principio ni al final.
      if (before[0] || after[0]) violations.push(`${s.name}: fila mal construida (la víctima concede en un extremo)`)
      if (s.swept ? !after[2] : !before[2]) violations.push(`${s.name}: fila mal construida (el rol local no concede dentro del owner)`)
      if (s.inside && !(before[2] && after[2])) violations.push(`${s.name}: fila mal construida (dentro del owner el rol local concede en los dos extremos)`)
      /** Lo que conceden LOS DOS extremos: dentro del owner, ningún corte lo pierde (el previo no borra lo que sigue visible). */
      const lost = (store: T[]) =>
        grants(store)
          .map((g, i) => (!g && before[i] && after[i] ? `${requests[i].user}@${requests[i].object}` : null))
          .filter((x): x is string => x !== null)
      // (2) El oráculo sobre los `Write` efectivos: ningún PREFIJO; y el control positivo con el orden de antes de F4.
      const edgeAt = full.steps.findIndex((st) => (st.writes ?? []).some((t) => t.relation === 'parent'))
      const others = full.steps.filter((_, i) => i !== edgeAt)
      const found = impossibleTrues(model, new TupleStore(initial), full.steps, requests)
      const prefixes = found.filter((f) => f.kind === 'prefix')
      if (prefixes.length) violations.push(`${s.name}: el intérprete encuentra PREFIJOS que conceden: ${prefixes.map((f) => `${f.request.user}@${f.request.object} tras ${f.prefixes.join(',')}`).slice(0, 3).join('; ')}`)
      if (s.inside && edgeAt !== 0) violations.push(`${s.name}: el barrido previo escribió ${edgeAt} Write antes de la arista (dentro del owner no hay nada que borrar)`)
      const legacy = s.swept ? [...others, full.steps[edgeAt]] : [full.steps[edgeAt], ...others]
      const control = impossibleTrues(model, new TupleStore(initial), legacy, requests)
      if (!s.inside && !control.some((f) => f.kind === 'prefix' && f.request.user === victim)) {
        violations.push(`${s.name}: CONTROL POSITIVO fallido — el orden de antes de F4 (${s.swept ? 'escrituras antes de la arista' : 'arista y después barrido'}) tendría que dar un prefijo que concede a la víctima`)
      }
      // (1) + (3) + (4) Cortado tras cada `Write`, y el reintento desde el corte.
      for (let k = 0; k < full.calls; k++) {
        const cut = await run(s.to, initial, { op: s.op, cutAfter: k })
        if (cut.outcome === 'ok') violations.push(`${s.name}: el corte ${k} no cortó`)
        const extra = excess(cut.store)
        if (extra.length) violations.push(`${s.name}: tras ${k} de ${full.calls} Write CONCEDE: ${extra.slice(0, 3).join(', ')}`)
        if (s.inside) {
          const gone = lost(cut.store)
          if (gone.length) violations.push(`${s.name}: tras ${k} de ${full.calls} Write PIERDE lo que conceden los dos extremos: ${gone.slice(0, 3).join(', ')}`)
        }
        if (cut.partial !== k >= 1) violations.push(`${s.name}: tras ${k} de ${full.calls} Write: marca parcial ${cut.partial} (esperada ${k >= 1})`)
        const retry = await run(s.to, cut.store, { op: s.op })
        if (retry.outcome !== 'ok') violations.push(`${s.name}: el reintento tras ${k} no terminó: ${retry.outcome}`)
        const retried = grants(retry.store)
        if (retried.some((g, i) => g !== after[i])) violations.push(`${s.name}: el reintento tras ${k} de ${full.calls} Write NO converge al final`)
        // Cierre de F4 (🟡-6 del tester): converge también en TUPLAS, no solo en veredictos (una tupla sobrante que hoy no
        // concede a ningún pedido sería deriva del store).
        const tupleId = (t: T) => `${t.user}#${t.relation}@${t.object}`
        const fullIds = new Set(full.store.map(tupleId))
        const retryIds = new Set(retry.store.map(tupleId))
        const diff = [...[...fullIds].filter((id) => !retryIds.has(id)).map((id) => `-${id}`), ...[...retryIds].filter((id) => !fullIds.has(id)).map((id) => `+${id}`)]
        if (diff.length) violations.push(`${s.name}: el reintento tras ${k} de ${full.calls} Write deja OTRAS tuplas que el move entero: ${diff.slice(0, 3).join(', ')}`)
        let state = new TupleStore(cut.store)
        for (const [j, step] of retry.steps.entries()) {
          state = state.apply(step)
          const bad = grants(state.tuples() as T[]).some((g, i) => g && !allowed[i])
          if (bad) violations.push(`${s.name}: el reintento tras ${k} concede de más tras su Write ${j + 1}`)
        }
      }
      // (5) La carrera con un `grant` entre el barrido previo y la arista (solo al SALIR: fuera del owner no concede).
      if (!s.swept && !s.inside) {
        const raced = await run(s.to, initial, { op: s.op, race: true })
        const final = grants(raced.store)
        if (raced.outcome !== 'ok') violations.push(`${s.name}: el move con carrera no terminó: ${raced.outcome}`)
        if (final[requests.length - 1]) violations.push(`${s.name}: un grant que aterriza entre el barrido previo y la arista CONCEDE fuera del owner al final (el barrido de después no borra)`)
        if (final[0]) violations.push(`${s.name}: con la carrera la víctima CONCEDE al final`)
      }
      // Cierre de F4 (tester del panel de carreras, punto 1): con la forma del SDK, un choque en el `Write` de la arista
      // (otro escritor se llevó la arista vieja entre la lectura y el `Write`) es CARRERA: `reparent` relee, vuelve a barrer
      // y re-aplica, y acaba en el MISMO store que el move sin choque — no lanza.
      {
        const raced = await run(s.to, initial, { op: s.op, edgeRaceOnce: true })
        if (raced.outcome !== 'ok') violations.push(`${s.name}: un choque de carrera en la arista (forma del SDK) no se relee: ${raced.outcome}`)
        const tupleId = (t: T) => `${t.user}#${t.relation}@${t.object}`
        if (raced.store.map(tupleId).sort().join('\n') !== full.store.map(tupleId).sort().join('\n')) {
          violations.push(`${s.name}: tras releer el choque de la arista el store NO es el del move sin choque`)
        }
      }
      // F-7 (coste fijado). Desde el lote C (L13) el barrido de después es el SETTLE, que relee el store y escribe solo la
      // DIFERENCIA (hasta F4 reescribía el barrido entero con `Ignore`): SALIR = 2 lotes de borrado previo + la arista (el
      // settle ve el subárbol coherente: 0); ENTRAR = la arista + 2 lotes de altas (el previo no tiene nada que borrar);
      // DENTRO = solo la arista. Cierre de F4 (🟡-1 del tester): va a `violations` y no a un `assert` dentro del bucle,
      // para que lo que el corredor registre sea el ORÁCULO y no la cuenta.
      const expectedCalls = s.inside ? 1 : 3
      if (full.calls !== expectedCalls) violations.push(`${s.name}: F-7 — ${full.calls} Write del move con 150 bindings locales (esperados ${expectedCalls})`)
    }
    // Cierre de F4 (🟡-3 del tester): el barrido previo va DESPUÉS del anti-ciclos del store (3b-8 · A5). El store tiene la
    // primera hija BAJO C y el consumidor —desincronizado, una outbox aplicada en desorden— la tiene bajo B y mueve C debajo
    // de ella: legal para el consumidor, ciclo REAL en el store ⇒ 422 `E_AUTHZ_SCOPE_CYCLE` con CERO `Write`, sin marca
    // parcial y el store intacto. Los bindings de A en el subárbol están ahí aunque C cuelgue de B (deriva: un `grant` con
    // la cadena vieja, hallazgo 2 del auditor de F4), así que un barrido previo ANTES del anti-ciclos los borraría (X2).
    {
      const initial = seed(orgB, false)
      const cyc = await run(kids[0], initial, {
        consumer: [[kids[0], orgB], [unitC, kids[0]], ...kids.slice(1).map((kid): [typeof kid, typeof unitC] => [kid, unitC])],
      })
      if (cyc.outcome !== 'E_AUTHZ_SCOPE_CYCLE') violations.push(`CICLO del store: el move no es 422 E_AUTHZ_SCOPE_CYCLE (${cyc.outcome})`)
      if (cyc.calls !== 0) violations.push(`CICLO del store: el 422 dejó ${cyc.calls} Write (el barrido previo corrió ANTES del anti-ciclos)`)
      if (cyc.partial) violations.push('CICLO del store: el 422 va marcado PARCIAL')
      const tupleId = (t: T) => `${t.user}#${t.relation}@${t.object}`
      if (cyc.store.map(tupleId).sort().join('\n') !== initial.map(tupleId).sort().join('\n')) violations.push('CICLO del store: el 422 cambió el store')
    }
    assert.deepEqual(violations, [], `ROJO (${property.id}): ${violations.join(' ;; ')}`)
  }).timeout(120_000)
})

/**
 * **`openfga.roles.reconcile.order`** (cierre de F4, 🟡-5 del tester; linaje L10, el GEMELO de mantenimiento de `moved`):
 * la pasada de MANTENIMIENTO (`reconcile` con el propio store como origen) que repara un `moved` perdido aplica TODOS los
 * borrados —la arista vieja y las `scope#binding` que el invariante 18 prohíbe— antes que TODAS las escrituras. Sin
 * servidor: cliente FGA en memoria que registra cada `Write` efectivo, el INTÉRPRETE del modelo como oráculo. El universo
 * fuerza ≥ 2 lotes de borrados con la arista vieja en el lote 1 y el binding de la víctima en el lote 2 (el orden de
 * `readEveryTuple` lo decide el doble): con las fases invertidas —escrituras primero— el estado tras el lote 1 deja la
 * unit SOLO bajo B con el binding de A visible y concede a la víctima (prefijo). Con UN solo lote ese mutante sobrevivía
 * (el estado intermedio con DOS padres hereda el deny del viejo), que es lo que decía mal la letra del informe de F4.
 */
test.group('GS · P · openfga.roles.reconcile.order (cierre de F4, linaje L10)', () => {
  const property = GUARD_PROPERTIES.find((p) => p.id === 'openfga.roles.reconcile.order')!
  test(property.title, async ({ assert }) => {
    type T = { user: string; relation: string; object: string }
    const slug = 'gsrec:read'
    const holders = { users: 'user' }
    const model = compileModel(generatedModel(holders, [slug]))
    const at = { current_time: new Date().toISOString() }
    const key = (s: { type: string; uuid: string | null }) => (s.type === 'app' ? 'app' : `${s.type}|${s.uuid}`)
    const orgA = { type: 'organization', uuid: uuidv7() }
    const orgB = { type: 'organization', uuid: uuidv7() }
    const unitC = { type: 'unit', uuid: uuidv7() }
    const kids = Array.from({ length: 149 }, () => ({ type: 'unit', uuid: uuidv7() }))
    const permissionUuid = uuidv7()
    const role = { uuid: uuidv7(), slug: 'gsrec-lead', scopeType: 'unit', owner: key(orgA), rank: 10 }
    const view = {
      permissionSlugs: [slug],
      permission: (s: string) => (s === slug ? { uuid: permissionUuid, assignableAt: null } : null),
      localRoles: () => [role],
      roleByUuid: (uuid: string) => (uuid === role.uuid ? role : null),
    }
    const victim = 'user:victim'
    const assignments: Array<[string, string]> = [
      [victim, key(unitC)],
      [victim, key(kids[148])],
      ['user:plain', key(unitC)],
      ...kids.slice(0, 148).map((kid, i): [string, string] => [`user:p${i}`, key(kid)]),
    ]
    const requests = assignments.map(([user, scope]) => ({ user, relation: `can_${slug.replace(':', '_')}`, object: factsScopeObject(scope), context: at }))
    const grants = (store: T[]) => {
      const state = new TupleStore(store)
      return requests.map((r) => checkTuples(model, state, r).verdict === 'T')
    }
    const same = (a: T, b: T) => a.user === b.user && a.relation === b.relation && a.object === b.object
    // El store: el `moved` C: A → B se PERDIÓ (aparcado). Orden de `Read` = orden de los borrados: la arista vieja primero,
    // las `scope#binding` de las hijas p0..p147 después y las de la VÍCTIMA (C y la última hija) al final (lote 2).
    const victimBindings = new Set([key(unitC), key(kids[148])])
    const allScopes = [unitC, ...kids]
    const bindingEdges = allScopes.map((s) => factsBindingTuples(key(s), role.uuid).find((t) => t.relation !== 'role')!)
    const initial: T[] = [
      factsParentTuple(key(unitC), key(orgA)),
      ...bindingEdges.filter((t) => !victimBindings.has(t.object.slice('scope:'.length))),
      ...bindingEdges.filter((t) => victimBindings.has(t.object.slice('scope:'.length))),
      ...factsRootTuples(holders),
      ...factsCatalogTuples([{ uuid: role.uuid, permissions: [slug] }] as any, holders),
      factsParentTuple(key(orgA), 'app'),
      factsParentTuple(key(orgB), 'app'),
      ...kids.map((kid) => factsParentTuple(key(kid), key(unitC))),
      ...allScopes.flatMap((s) => factsBindingTuples(key(s), role.uuid).filter((t) => t.relation === 'role')),
      ...assignments.map(([user, scope]) => ({ user, relation: 'assignee', object: factsBindingObject(scope, role.uuid) })),
      factsDenyTuple(key(orgA), slug, victim),
    ]
    // El árbol del CONSUMIDOR (el que manda en el reconcile): C ya cuelga de B.
    const edges = [
      { child: orgA, parent: APP_SCOPE },
      { child: orgB, parent: APP_SCOPE },
      { child: unitC, parent: orgB },
      ...kids.map((kid) => ({ child: kid, parent: unitC })),
    ]
    const tree = memoryScopeTree()
    for (const e of edges) await tree.attach(e.child as any, e.parent as any)

    // La proyección del catálogo la lee el reconcile de SQL: el rol y su permiso, filas propias que se borran al final.
    const now = new Date()
    await db.table('authz_permissions').insert({ uuid: permissionUuid, slug, created_at: now, updated_at: now })
    await db.table('authz_roles').insert({ uuid: role.uuid, slug: role.slug, name: role.slug, scope_type: 'unit', rank: 10, owner_scope_key: role.owner, created_at: now, updated_at: now })
    await db.table('authz_role_permissions').insert({ uuid: uuidv7(), role_uuid: role.uuid, permission_uuid: permissionUuid, created_at: now })
    try {
      const run = async (cutAfter?: number) => {
        let store = initial.map((t) => ({ ...t }))
        let calls = 0
        const steps: WriteStep[] = []
        const driver: any = new OpenFgaAuthorizationDriver({
          apiUrl: 'http://127.0.0.1:1',
          storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
          modelId: TEST_MODEL_ID,
          holderTypes: holders,
          resolveChain: resolveChainFrom(tree),
          catalog: { view: async () => view },
          acceptScopeDriftRisk: true,
          logger: { warn: () => {} },
        } as any)
        const matches = (filter: any) => (t: T) =>
          (!filter.object || (filter.object.endsWith(':') ? t.object.startsWith(filter.object) : t.object === filter.object)) &&
          (!filter.relation || t.relation === filter.relation) &&
          (!filter.user || t.user === filter.user)
        const apply = (writes: T[], deletes: T[]) => {
          if (cutAfter !== undefined && calls >= cutAfter) throw new AuthorizationBackendError('openfga', 'write', new Error('corte inyectado'))
          calls++
          const effective = {
            deletes: deletes.filter((t) => store.some((x) => same(x, t))).map((t) => ({ user: t.user, relation: t.relation, object: t.object })),
            writes: writes.filter((t) => !store.some((x) => same(x, t))).map((t) => ({ user: t.user, relation: t.relation, object: t.object })),
          }
          store = [...store.filter((x) => !effective.deletes.some((d) => same(d, x))), ...effective.writes]
          steps.push(effective)
          return {}
        }
        driver.client = {
          readAuthorizationModel: async () => ({ authorization_model: generatedModel(holders, [slug]) }),
          read: async (filter: any = {}, readOptions: any = {}) => {
            const all = store.filter(matches(filter ?? {}))
            const from = Number(readOptions?.continuationToken || 0)
            const size = readOptions?.pageSize ?? 100
            const page = all.slice(from, from + size)
            return { tuples: page.map((k) => ({ key: k })), continuation_token: from + size < all.length ? String(from + size) : '' }
          },
          write: async (body: any) => apply(body.writes ?? [], body.deletes ?? []),
          writeTuples: async (writes: T[]) => apply(writes, []),
          deleteTuples: async (deletes: T[]) => apply([], deletes),
        }
        const source = {
          enumerateEdges: async ({ limit, after }: { limit: number; after?: string }) => {
            const from = Number(after ?? 0)
            return { edges: edges.slice(from, from + limit), cursor: from + limit < edges.length ? String(from + limit) : undefined }
          },
          resolveChain: resolveChainFrom(tree),
          factsOrigin: { name: 'openfga', authzTables: false, self: true },
          facts: (page: any) => driver.enumerateFacts(page),
        }
        const outcome = await driver.reconcile(source, {}).then(
          (r: any) => r,
          (e: any) => `${e?.code ?? ''} ${e?.message ?? e}`
        )
        return { store, calls, steps, outcome }
      }
      const violations: string[] = []
      const full = await run()
      if (typeof full.outcome === 'string') {
        assert.fail(`ROJO (${property.id}): la pasada de mantenimiento no terminó: ${full.outcome}`)
      }
      const before = grants(initial)
      const after = grants(full.store)
      const allowed = before.map((b, i) => b || after[i])
      if (before[0] || before[1] || after[0] || after[1]) violations.push('fila mal construida: la víctima concede en un extremo')
      if (!before[2] || after[2]) violations.push('fila mal construida: el rol local concede DENTRO del owner y no fuera')
      // El universo es el que el hallazgo exige: ≥ 2 lotes de borrados y la arista vieja en el PRIMERO.
      const oldEdge = factsParentTuple(key(unitC), key(orgA))
      const deleteSteps = full.steps.filter((st) => st.deletes?.length)
      const writeSteps = full.steps.filter((st) => st.writes?.length)
      if (deleteSteps.length < 2) violations.push(`fila mal construida: ${deleteSteps.length} lote(s) de borrados (hacen falta ≥ 2)`)
      if (!deleteSteps[0]?.deletes?.some((t: T) => same(t, oldEdge))) violations.push('fila mal construida: la arista vieja no va en el PRIMER lote de borrados')
      // (2) Ningún PREFIJO concede según el intérprete; y el CONTROL POSITIVO: los mismos `Write` con las escrituras
      // primero (el mutante «escrituras primero») sí dan un prefijo que concede a la víctima.
      const found = impossibleTrues(model, new TupleStore(initial), full.steps, requests)
      const prefixes = found.filter((f) => f.kind === 'prefix')
      if (prefixes.length) violations.push(`el intérprete encuentra PREFIJOS que conceden: ${prefixes.map((f) => `${f.request.user}@${f.request.object} tras ${f.prefixes.join(',')}`).slice(0, 3).join('; ')}`)
      const control = impossibleTrues(model, new TupleStore(initial), [...writeSteps, ...deleteSteps], requests)
      if (!control.some((f) => f.kind === 'prefix' && f.request.user === victim)) {
        violations.push('CONTROL POSITIVO fallido — con las escrituras primero el lote 1 de borrados tendría que dejar un prefijo que concede a la víctima')
      }
      // (1) Cortada tras cada `Write`, ningún estado concede fuera de inicial ∪ final; y repetida converge.
      for (let k = 0; k < full.calls; k++) {
        const cut = await run(k)
        if (typeof cut.outcome !== 'string') violations.push(`el corte ${k} no cortó`)
        const extra = grants(cut.store)
          .map((g, i) => (g && !allowed[i] ? `${requests[i].user}@${requests[i].object}` : null))
          .filter((x): x is string => x !== null)
        if (extra.length) violations.push(`tras ${k} de ${full.calls} Write CONCEDE: ${extra.slice(0, 3).join(', ')}`)
      }
      assert.deepEqual(violations, [], `ROJO (${property.id}): ${violations.join(' ;; ')}`)
    } finally {
      await db.from('authz_role_permissions').where('role_uuid', role.uuid).delete()
      await db.from('authz_roles').where('uuid', role.uuid).delete()
      await db.from('authz_permissions').where('uuid', permissionUuid).delete()
    }
  }).timeout(120_000)
})

/* ── L11 · lote «antes de RC»: cuatro propiedades (sustituyen a `openfga.model.drift`, cierre 5 de D2) ──────────────── */

/** El modelo de la config de la guardia, tal como lo genera el paquete (con o sin los permisos de roles). */
function guardModel(permissions: readonly string[] = []): any {
  return openFgaFactsModel(GUARD_HOLDERS, permissions, { objectTypes: contractRelationsConfig().objectTypes })
}

/** El modelo con el RUIDO de proto3 y el ORDEN con que lo devuelve OpenFGA v1.19.0 (medido en `:8090`). */
function servedShape(model: any): any {
  const noisy = (node: any): any => {
    if (Array.isArray(node)) return [...node].reverse().map(noisy)
    if (node === null || typeof node !== 'object') return node
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(node).reverse()) out[key] = noisy(node[key])
    if ('computedUserset' in out) (out.computedUserset as any).object = ''
    if ('directly_related_user_types' in out) {
      out.module = ''
      out.source_info = null
      for (const r of out.directly_related_user_types as any[]) if (r.condition === undefined) r.condition = ''
    }
    if ('type_name' in out) out.generic_types = []
    return out
  }
  const copy = noisy(JSON.parse(JSON.stringify(model)))
  copy.id = '01ARZ3NDEKTSV4RRFFQ69G5FAW'
  for (const definition of copy.type_definitions) if (definition.metadata === undefined) definition.metadata = null
  for (const condition of Object.values<any>(copy.conditions)) condition.metadata = null
  return copy
}

/** Un driver de relaciones de la guardia con el cliente falso sirviendo `served` (y el resto como `fakeFgaClient`). */
function gateDriver(served: unknown, config = contractRelationsConfig(), script: FgaScript = {}) {
  const driver = new OpenFgaRelationsDriver(config, {
    apiUrl: 'http://127.0.0.1:9',
    storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
    modelId: '01ARZ3NDEKTSV4RRFFQ69G5FAW',
    holderTypes: GUARD_HOLDERS,
    timeoutMs: 1000,
    listObjectsDeadlineMs: 1000,
    logger: { warn: () => {} },
  })
  const spy = fakeFgaClient(driver, [], {
    ...script,
    respond: (method, nth) =>
      script.respond?.(method, nth) ?? (method === 'readAuthorizationModel' ? { authorization_model: served } : undefined),
  })
  return { driver, spy }
}

const pathsOf = (served: unknown, slice: 'roles' | 'relations' | 'all' = 'relations') =>
  factsModelDifferences(served, {
    holderTypes: GUARD_HOLDERS,
    relations: slice === 'roles' ? undefined : { objectTypes: contractRelationsConfig().objectTypes },
    slice,
  }).differences.map((d) => d.path)

/**
 * **`openfga.model.equal`** (L11): la función pura sobre el modelo de la config de la guardia —normalizaciones neutras y
 * una mutación por operador— y la puerta del driver de relaciones con el cliente falso —la deriva NOMBRADA, `group` en
 * toda operación, un tipo ajeno fuera, D8 por tipo entero, el memo (C13)—. Sin servidor; el anclaje contra `:8090` es C1.
 */
test.group('GS · P · openfga.model.equal (lote «antes de RC» · L11)', () => {
  const property = GUARD_PROPERTIES.find((p) => p.id === 'openfga.model.equal')!
  test(property.title, async ({ assert }) => {
    const red = (what: string) => `ROJO (${property.id}): ${what}`
    // 1 · Lo que genera la config, y el mismo con la forma del servidor (ruido de proto3, otro orden): IGUAL.
    assert.deepEqual(pathsOf(guardModel()), [], red('el modelo de la config no es igual a sí mismo'))
    assert.deepEqual(pathsOf(servedShape(guardModel())), [], red('el ruido de proto3 / el orden del servidor cuentan como deriva'))
    assert.deepEqual(pathsOf(servedShape(guardModel(['docs:read'])), 'roles'), [], red('roles: el ruido de proto3 cuenta como deriva'))
    // 2 · Una mutación por operador ⇒ AL MENOS su ruta (C6).
    const mutate = (edit: (model: any) => void, slice: 'roles' | 'relations' = 'relations') => {
      const model = guardModel(['docs:read'])
      edit(model)
      return pathsOf(model, slice)
    }
    const type = (model: any, name: string) => model.type_definitions.find((t: any) => t.type === name)
    const cases: Array<[string, string[], string]> = [
      ['C6-1 literal: `with inverted` en denied_viewer + la condición', mutate((m) => {
        // La MISMA restricción con OTRA condición (no una de más): un canonicalizador que quite `condition` no la ve.
        const restriction = type(m, 'document').metadata.relations.denied_viewer.directly_related_user_types.find((r: any) => r.type === 'group' && r.condition)
        restriction.condition = 'inverted'
        m.conditions.inverted = { name: 'inverted', expression: 'current_time >= valid_until', parameters: { current_time: { type_name: 'TYPE_NAME_TIMESTAMP' }, valid_until: { type_name: 'TYPE_NAME_TIMESTAMP' } } }
      }), 'document#denied_viewer (restricciones de tipo)'],
      ['condición de más', mutate((m) => { m.conditions.inverted = { name: 'inverted', expression: 'true', parameters: {} } }), 'conditions.inverted (condición de más)'],
      ['condición distinta', mutate((m) => { m.conditions.not_expired.expression = 'current_time <= valid_until' }), 'conditions.not_expired (distinta)'],
      ['regla distinta (mismo nombre)', mutate((m) => { type(m, 'document').relations.viewer = type(m, 'document').relations.viewer.difference.base }), 'document#viewer (regla)'],
      ['relación de más (D-L11-3)', mutate((m) => { type(m, 'document').relations.admin = { this: {} } }), 'document#admin (relación de más)'],
      ['relación que falta', mutate((m) => { delete type(m, 'document').relations.owner }), 'document#owner (falta)'],
      ['`this: {}` ⇒ `{}`', mutate((m) => { type(m, 'group').relations.member = {} }), 'group#member (regla)'],
      ['difference con base/subtract intercambiados', mutate((m) => {
        const d = type(m, 'document').relations.viewer.difference
        type(m, 'document').relations.viewer.difference = { base: d.subtract, subtract: d.base }
      }), 'document#viewer (regla)'],
      ['restricción duplicada', mutate((m) => {
        const r = type(m, 'group').metadata.relations.member.directly_related_user_types
        r.push(r[0])
      }), 'group#member (restricciones de tipo)'],
      ['restricción sin `with not_expired`', mutate((m) => {
        const r = type(m, 'group').metadata.relations.member
        r.directly_related_user_types = r.directly_related_user_types.filter((x: any) => !x.condition)
      }), 'group#member (restricciones de tipo)'],
      ['schema_version', mutate((m) => { m.schema_version = '1.2' }), 'schema_version ("1.2")'],
      ['módulo NO vacío (modelo modular: falso positivo previsto y FIJADO)', mutate((m) => { type(m, 'document').metadata.module = 'docs' }), 'document.metadata.module'],
      ['tipo de la config ausente', mutate((m) => { m.type_definitions = m.type_definitions.filter((t: any) => t.type !== 'note') }), 'note (tipo ausente del modelo)'],
      ['roles · wildcard quitado de role#permits', mutate((m) => {
        const r = type(m, 'role').metadata.relations.permits_docs_read
        r.directly_related_user_types = r.directly_related_user_types.map((x: any) => ({ type: x.type }))
      }, 'roles'), 'role#permits_docs_read (restricciones de tipo)'],
      ['roles · can_<P> sin `but not denied_<P>`', mutate((m) => {
        type(m, 'scope').relations.can_docs_read = { intersection: { child: [{ computedUserset: { relation: 'docs_read' } }, { computedUserset: { relation: 'rooted' } }] } }
      }, 'roles'), 'scope#can_docs_read (regla)'],
    ]
    for (const [what, paths, expected] of cases) assert.include(paths, expected, red(`${what} no se ve (${JSON.stringify(paths)})`))
    // 3 · D8 por TIPO ENTERO: la forma con deny COMPLETA en un tipo sin opt-in (note) es legítima; MEZCLADA, no.
    const d8 = () => openFgaFactsModel(GUARD_HOLDERS, [], {
      objectTypes: contractRelationsConfig().objectTypes.map((t: any) => (t.type === 'note' ? { ...t, deny: 'write' } : t)),
    }) as any
    assert.deepEqual(pathsOf(d8()), [], red('la forma con deny ENTERA en un tipo sin opt-in (D8) cuenta como deriva'))
    const mixed = d8()
    type(mixed, 'note').relations.denied_editor = { this: {} }
    assert.include(pathsOf(mixed), 'note#denied_editor (regla)', red('D8 con denied_editor sin el cierre del corte de camino pasa (D5-2)'))
    // 4 · La puerta del driver: la deriva NOMBRADA, cero llamadas; `group` en toda operación; un tipo AJENO fuera (C7).
    const narrowed = guardModel()
    type(narrowed, 'note').relations.viewer = { this: {} }
    const noteDrift = gateDriver(narrowed)
    const caught = await noteDrift.driver.check(U, 'viewer', NOTE, P).then(() => null, (e: any) => e)
    assert.equal(caught?.code, 'E_AUTHZ_CONFIG', red('la puerta no se negó con una regla de note distinta'))
    assert.include(String(caught?.message), 'note#viewer (regla)')
    assert.deepEqual(noteDrift.spy.calls, ['readAuthorizationModel'], red('la puerta llamó al servidor para evaluar'))
    // 4a · POR TIPO, la otra mitad de la firma (1) (injerto 5; cierre de L11, 🟠-1 del tester): la MISMA deriva en `note`
    // NO tumba una operación de `document` — `check`, `checkMany` y `decideMany` llegan al servidor.
    const byType = gateDriver(narrowed)
    const onDoc = await byType.driver.check(U, 'viewer', DOC, P).then((v) => v, (e: any) => e)
    assert.strictEqual(onDoc, false, red(`una deriva en note tumbó un check de document: la puerta mira el slice entero (${onDoc?.message})`))
    const manyDoc = await byType.driver.checkMany(U, 'viewer', [DOC], P).then((v) => v, (e: any) => e)
    assert.notEqual(manyDoc?.code, 'E_AUTHZ_CONFIG', red(`checkMany de document se negó por una deriva en note (${manyDoc?.message})`))
    const decideDoc = await byType.driver.decideMany(U, 'viewer', [DOC], P).then((v) => v, (e: any) => e)
    assert.notEqual(decideDoc?.code, 'E_AUTHZ_CONFIG', red(`decideMany de document se negó por una deriva en note (${decideDoc?.message})`))
    assert.includeMembers(byType.spy.calls, ['check', 'batchCheck'], red('las operaciones de document no llegaron al servidor'))
    // 4b · Los HOLDERS, siempre relevantes (desviación 2 a; cierre de L11, 🟡-2 / X2): son el tipo del SUJETO de toda
    // operación — una relación de más en `user` tumba un check de `document`.
    const holderDrift = guardModel()
    type(holderDrift, 'user').relations = { nickname: { this: {} } }
    const viaHolder = await gateDriver(holderDrift).driver.check(U, 'viewer', DOC, P).then(() => null, (e: any) => e)
    assert.equal(viaHolder?.code, 'E_AUTHZ_CONFIG', red('una relación de más en el holder user no se ve en un check de document'))
    assert.include(String(viaHolder?.message), 'user#nickname (relación de más)')
    const groupDrift = guardModel()
    type(groupDrift, 'group').relations.member = { union: { child: [{ this: {} }, { computedUserset: { relation: 'owner' } }] } }
    const viaGroup = await gateDriver(groupDrift).driver.check(U, 'viewer', NOTE, P).then(() => null, (e: any) => e)
    assert.include(String(viaGroup?.message), 'group#member', red('la deriva de group#member no se ve en un check de note'))
    // Y al revés: una operación sobre `group` (una membresía) compara TODOS los tipos de la config —su renovación lee los
    // denied_* de los tipos con deny—.
    const onGroup = await gateDriver(narrowed).driver.relate(U, 'member', GROUP, P).then(() => null, (e: any) => e)
    assert.include(String(onGroup?.message), 'note#viewer (regla)', red('una membresía de group no compara los tipos de la config'))
    const foreign = guardModel()
    foreign.type_definitions.push({ type: 'invoice', relations: { reader: { this: {} } }, metadata: { relations: { reader: { directly_related_user_types: [{ type: 'user' }] } } } })
    assert.isFalse(await gateDriver(foreign).driver.check(U, 'viewer', NOTE, P), 'un tipo AJENO a la config no cuenta (límite declarado, C7)')
    assert.isFalse(await gateDriver(d8()).driver.check(U, 'editor', NOTE, P), red('D8 legítimo: la puerta se negó'))
    // 4c · `decideMany` usa la FORMA del modelo comparado (`denyForm`, D8 por tipo entero), observable SIN servidor (cierre
    // de L11, 🟡-5 / X11): `note` plain ⇒ ningún `denied_*` en el batchCheck; con la forma con deny ENTERA, sí.
    const deniedChecks = async (served: unknown): Promise<string[]> => {
      const gate = gateDriver(served)
      const inner = (gate.driver as any).client
      const ids: string[] = []
      ;(gate.driver as any).client = new Proxy({}, {
        get: (_t, prop) => async (...args: any[]) => {
          if (prop === 'batchCheck') {
            for (const c of args[0]?.checks ?? []) ids.push(`${c.correlationId}:${c.relation}`)
            throw new Error('fin de la sonda (solo importa lo que se pidió)')
          }
          return inner[prop](...args)
        },
      })
      await gate.driver.decideMany(U, 'viewer', [NOTE], P).catch(() => undefined)
      return ids
    }
    const plainAsked = await deniedChecks(guardModel())
    assert.deepEqual(plainAsked.filter((id) => id.startsWith('d')), [], red(`decideMany preguntó denied_* a un tipo en forma plain (${plainAsked.join(', ')})`))
    assert.include(plainAsked, 'a0:viewer', 'y sí la relación pedida')
    const d8Asked = await deniedChecks(d8())
    assert.include(d8Asked, 'd0-0:denied_owner', red(`decideMany no preguntó el deny con la forma D8 entera (${d8Asked.join(', ')})`))
    // 5 · El memo (C13): un 503 NO se memoriza; una diferencia SÍ; base y vista comparten UNA lectura.
    const flaky = gateDriver(guardModel(), contractRelationsConfig(), {
      failOn: (method, nth) => (method === 'readAuthorizationModel' && nth === 1 ? new Error('FGA caído (transitorio)') : undefined),
    })
    const first = await flaky.driver.check(U, 'viewer', NOTE, P).then(() => null, (e: any) => e)
    assert.equal(first?.status, 503, 'la primera lectura falla: 503')
    assert.isFalse(await flaky.driver.check(U, 'viewer', NOTE, P), red('C13 a: el 503 se memorizó (el driver no relee)'))
    assert.equal(flaky.spy.calls.filter((c) => c === 'readAuthorizationModel').length, 2, 'relee tras el fallo')
    const memoDiff = gateDriver(narrowed)
    await memoDiff.driver.check(U, 'viewer', NOTE, P).catch(() => undefined)
    const again = await (memoDiff.driver.withClock(() => new Date()) as OpenFgaRelationsDriver).check(U, 'viewer', NOTE, P).then(() => null, (e: any) => e)
    assert.equal(again?.code, 'E_AUTHZ_CONFIG', 'la vista ve la MISMA diferencia')
    assert.equal(memoDiff.spy.calls.filter((c) => c === 'readAuthorizationModel').length, 1, 'C13 b/c: UNA lectura (diferencia memorizada, vista compartida)')
  })
})

/**
 * **`fga.tuple.expiry`** (L11): la función y su TABLA de consumidores, sin servidor (cliente falso de cada driver y el
 * doble para el plan del reconcile). Las cifras de M-b (F0) fijan el oráculo: `ns(now) < trunc9(ns(s))`.
 */
test.group('GS · P · fga.tuple.expiry (lote «antes de RC» · L11)', (group) => {
  const property = GUARD_PROPERTIES.find((p) => p.id === 'fga.tuple.expiry')!
  const roleUuid = uuidv7()
  group.setup(async () => {
    const now = new Date()
    await db.table('authz_roles').insert({ uuid: roleUuid, slug: 'gs-l11', name: 'gs-l11', scope_type: 'unit', rank: 1, owner_scope_key: 'global', created_at: now, updated_at: now })
    return async () => {
      await db.from('authz_roles').where('uuid', roleUuid).delete()
    }
  })
  test(property.title, async ({ assert }) => {
    const red = (what: string) => `ROJO (${property.id}): ${what}`
    const ne = (valid_until: unknown, extra: Record<string, unknown> = {}) => ({ name: 'not_expired', context: { valid_until, ...extra } })
    const kind = (condition: unknown) => fgaTupleExpiry(condition).kind
    assert.equal(kind(null), 'none')
    assert.equal(kind({ name: 'inverted', context: { valid_until: '2001-01-01T00:00:00Z' } }), 'foreign', red('una condición ajena se lee como not_expired'))
    assert.equal(kind(ne('2001-01-01T00:00:00Z', { current_time: '2000-01-01T00:00:00Z' })), 'foreign', red('un current_time congelado en la tupla pasa (H2)'))
    assert.equal(kind({ name: 'not_expired', context: {} }), 'unparseable')
    for (const raw of ['2030-06-15T10:20:30,999001Z', '2030-06-15T10:20:30.999+25:00', 'garbage']) {
      assert.notEqual(kind(ne(raw)), 'none', red(`'${raw}' se lee como PERMANENTE`))
    }
    const at = (raw: string) => (fgaTupleExpiry(ne(raw)) as { at: Date }).at.getTime()
    const now = Date.parse('2030-06-15T10:20:30.999Z')
    assert.isAbove(at('2030-06-15T10:20:30.999000001Z'), now, red('C6-2: .999000001 con now .999 tiene que estar VIVA (floor la da por vencida)'))
    assert.equal(at('2030-06-15T10:20:30.999Z'), now, '.999 exacto: vencida en now (estricta)')
    assert.equal(at('2030-06-16T10:20:30.999+24:00'), now, '+24:00 se interpreta (F0 · M-b)')
    // Consumidores · relaciones (cliente falso).
    const partitionKey = `unit|${P.uuid}`
    const objectId = `document:${partitionKey}|${DOC.id}`
    const user = `user:${U.uuid}`
    const foreignTuple = { user, relation: 'viewer', object: objectId, condition: { name: 'inverted', context: { valid_until: '2001-01-01T00:00:00Z' } } }
    const withTuples = (tuples: any[]) => gateDriver(guardModel(), contractRelationsConfig(), { respond: (m) => (m === 'read' ? { tuples: tuples.map((key) => ({ key })), continuation_token: '' } : undefined) })
    const relating = withTuples([foreignTuple])
    const renewal = await relating.driver.relate(U, 'viewer', DOC, P, { expiresAt: null }).then(() => null, (e: any) => e)
    assert.equal(renewal?.code, 'E_AUTHZ_RENEWAL_UNSAFE', red('relate sobre una clave con condición ajena no es 409'))
    assert.notInclude(relating.spy.calls, 'write', red('relate escribió sobre una clave con condición ajena'))
    assert.deepEqual((await withTuples([foreignTuple]).driver.listSubjects('viewer', DOC, P)).subjects, [], red('listSubjects lista una condición ajena'))
    const deniedForeign = { ...foreignTuple, relation: 'denied_viewer' }
    assert.deepEqual((await withTuples([deniedForeign]).driver.listDenies('viewer', DOC, P)).subjects, [], red('listDenies lista una condición ajena'))
    const swept = await withTuples([foreignTuple]).driver.enumerateRelations(P)
    assert.isString(swept.tuples[0]?.invalidCondition, red('enumerateRelations no marca la condición ajena'))
    // Cierre de L11 (⚪ A3.3): un lector que NO conozca `invalidCondition` no la toma por PERMANENTE (`expiresAt: null`).
    assert.instanceOf(swept.tuples[0]?.expiresAt, Date, red('enumerateRelations emite la condición ajena con expiresAt null (= permanente para un lector que no conozca la marca)'))
    assert.isAtMost((swept.tuples[0]!.expiresAt as Date).getTime(), Date.now(), 'se lee VENCIDA')
    // #carriedDeny: la membresía de g (con caducidad vigente) y un deny de g con condición ajena ⇒ la renovación es 409.
    const g = `group:${partitionKey}|${GROUP.id}`
    const later = new Date(Date.now() + 3_600_000).toISOString()
    const carrier = gateDriver(guardModel(), contractRelationsConfig(), {
      respond: (m, nth) => {
        if (m !== 'read') return undefined
        if (nth === 1) return { tuples: [{ key: { user, relation: 'member', object: g, condition: ne(later) } }], continuation_token: '' }
        if (nth === 2) return { tuples: [{ key: { user: `${g}#member`, relation: 'denied_viewer', object: objectId, condition: { name: 'inverted', context: {} } } }], continuation_token: '' }
        return { tuples: [], continuation_token: '' }
      },
    })
    const carried = await carrier.driver.relate(U, 'member', GROUP, P, { expiresAt: null }).then(() => null, (e: any) => e)
    assert.equal(carried?.code, 'E_AUTHZ_RENEWAL_UNSAFE', red('un deny con condición ajena no cuenta como VIVO en la portadora'))
    // GEMELO en roles (cierre de L11, 🟡-3 del tester; «viva donde niega», paridad con #carriedDeny): el deny de roles con
    // una condición ajena cuenta VIVO en `deniedScopeKeys` (lo que decide `listScopes`): lista de menos, nunca de más.
    const denyReader: any = new OpenFgaAuthorizationDriver({ apiUrl: 'http://127.0.0.1:1', storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV', modelId: TEST_MODEL_ID, holderTypes: { users: 'user' }, acceptScopeDriftRisk: true, logger: { warn: () => {} } } as any)
    denyReader.catalog = { view: async () => ({ permissionSlug: () => 'docs:read' }) }
    denyReader.client = {
      read: async () => ({ tuples: [{ key: { user, relation: 'denied_docs_read', object: `scope:${partitionKey}`, condition: ne('2001-01-01T00:00:00Z', { current_time: '2000-01-01T00:00:00Z' }) } }], continuation_token: '' }),
    }
    const deniedKeys: Set<string> = await denyReader.deniedScopeKeys({ type: 'users', uuid: U.uuid }, uuidv7())
    assert.isTrue(deniedKeys.has(partitionKey), red('roles: un deny con condición ajena NO cuenta vivo en listScopes (gemelo de #carriedDeny)'))
    // Consumidores · roles (cliente falso: grant, listSubjects, enumerateFacts).
    const roles: any = new OpenFgaAuthorizationDriver({
      apiUrl: 'http://127.0.0.1:1',
      storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      modelId: TEST_MODEL_ID,
      holderTypes: { users: 'user' },
      resolveChain: async (s: ScopeRef) => (s.type === 'app' ? [s] : s.uuid === P.uuid ? [P, { type: 'app', uuid: null }] : null),
      acceptScopeDriftRisk: true,
      logger: { warn: () => {} },
    } as any)
    const writes: string[] = []
    const roleTuples = [{ key: { user, relation: 'assignee', object: `role_binding:app|${uuidv7()}`, condition: { name: 'inverted', context: {} } } }]
    roles.client = {
      readAuthorizationModel: async () => ({ authorization_model: generatedModel({ users: 'user' }, ['docs:read']) }),
      read: async () => ({ tuples: roleTuples, continuation_token: '' }),
      write: async () => void writes.push('write'),
      writeTuples: async () => void writes.push('writeTuples'),
      deleteTuples: async () => void writes.push('deleteTuples'),
    }
    // Cierre de L11 (🟡 A2(a) / 🟠-2 del tester, clase 3b-2j): `countRoleAssignments` CUENTA el `assignee` con condición
    // ajena (puede estar vivo en el servidor): contarlo de menos es `stillGranting: false` sobre un rol que concede.
    assert.deepEqual(await roles.countRoleAssignments([uuidv7()]), [1], red('countRoleAssignments no cuenta una asignación con condición ajena («no lo sé» degradado a «no concede»)'))
    const page = await roles.enumerateFacts({ limit: 10 })
    assert.deepEqual(page.facts, [], red('enumerateFacts migra una asignación con condición ajena'))
    assert.isTrue(page.skipped.some((s: any) => s.reason === 'invalid-condition'), red('enumerateFacts no la cuenta'))
    const listed = await (roles as any).readAllTuples({ object: roleTuples[0].key.object })
    assert.deepEqual(listed, [], red('las enumeraciones de roles listan una condición ajena'))
    // grant sobre una asignación que YA existe con condición ajena ⇒ 409, cero escrituras (el rol lo declara el catálogo).
    roleTuples[0].key.object = `role_binding:unit|${P.uuid}|${roleUuid}`
    const granted = await roles.grant({ type: 'users', uuid: U.uuid }, 'gs-l11', P).then(() => null, (e: any) => e)
    assert.equal(granted?.code, 'E_AUTHZ_RENEWAL_UNSAFE', red(`grant sobre una asignación con condición ajena no es 409 (${granted?.code} ${granted?.message})`))
    assert.deepEqual(writes, [], red('grant escribió sobre una asignación con condición ajena'))
    // Cierre de L11 (🟡-8 del tester, X13): la rama de CARRERA de `grant` — la asignación no estaba, el write choca y la
    // RELECTURA la encuentra con una condición ajena (otro escritor) ⇒ el mismo 409, sin reescribir encima.
    const racing: any = new OpenFgaAuthorizationDriver({
      apiUrl: 'http://127.0.0.1:1',
      storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
      modelId: TEST_MODEL_ID,
      holderTypes: { users: 'user' },
      resolveChain: async (s: ScopeRef) => (s.type === 'app' ? [s] : s.uuid === P.uuid ? [P, { type: 'app', uuid: null }] : null),
      acceptScopeDriftRisk: true,
      logger: { warn: () => {} },
    } as any)
    const raceWrites: string[] = []
    let raceReads = 0
    racing.client = {
      readAuthorizationModel: async () => ({ authorization_model: generatedModel({ users: 'user' }, ['docs:read']) }),
      read: async () => (++raceReads === 1 ? { tuples: [], continuation_token: '' } : { tuples: [roleTuples[0]], continuation_token: '' }),
      write: async () => void raceWrites.push('write'),
      writeTuples: async () => {
        raceWrites.push('writeTuples')
        throw Object.assign(new Error('Aborted'), { statusCode: 409 })
      },
      deleteTuples: async () => void raceWrites.push('deleteTuples'),
    }
    const raced = await racing.grant({ type: 'users', uuid: U.uuid }, 'gs-l11', P).then(() => null, (e: any) => e)
    assert.equal(raced?.code, 'E_AUTHZ_RENEWAL_UNSAFE', red(`grant en carrera con una asignación ajena no es 409 (${raced?.code} ${raced?.message})`))
    assert.deepEqual(raceWrites, ['writeTuples'], red(`grant en carrera reescribió sobre la asignación ajena (${raceWrites.join(', ')})`))
    // Consumidor · el DESTINO del reconcile de roles (`readEveryTuple`): la asignación con condición ajena es intocable —ni
    // `extra-fact` que `--prune` borre, ni una caducidad que «actualizar»—, y se cuenta `invalid-condition` (deriva).
    const dest: any = new OpenFgaAuthorizationDriver({ apiUrl: 'http://127.0.0.1:1', storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV', modelId: TEST_MODEL_ID, holderTypes: { users: 'user' }, acceptScopeDriftRisk: true, logger: { warn: () => {} } } as any)
    dest.client = { ...roles.client }
    const pass = await dest.reconcile({ enumerateEdges: async () => ({ edges: [] }), resolveChain: async (s: ScopeRef) => (s.type === 'app' ? [s] : null) }, { dryRun: true, prune: true })
    assert.equal(pass.phases.facts.deleted, 0, red('el reconcile de roles poda una asignación del destino con condición ajena'))
    assert.isTrue(pass.details.some((skip: any) => skip.reason === 'invalid-condition'), red('el reconcile de roles no cuenta la condición ajena del destino'))
    // Cierre de L11 (⚪ A2(b) del auditor, gemelo del plan de relaciones): un DENY que el origen quiere y el destino tiene con
    // una condición ajena NIEGA la pasada que escribe (el servidor puede ignorarlo y los grants alrededor concederían).
    const blocking: any = new OpenFgaAuthorizationDriver({ apiUrl: 'http://127.0.0.1:1', storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV', modelId: TEST_MODEL_ID, holderTypes: { users: 'user' }, acceptScopeDriftRisk: true, logger: { warn: () => {} } } as any)
    const blockingWrites: string[] = []
    blocking.client = {
      readAuthorizationModel: async () => ({ authorization_model: generatedModel({ users: 'user' }, ['docs:read']) }),
      read: async () => ({ tuples: [{ key: { user, relation: 'denied_docs_read', object: 'scope:app', condition: { name: 'inverted', context: {} } } }], continuation_token: '' }),
      write: async () => void blockingWrites.push('write'),
      writeTuples: async () => void blockingWrites.push('writeTuples'),
      deleteTuples: async () => void blockingWrites.push('deleteTuples'),
    }
    const denySource = {
      enumerateEdges: async () => ({ edges: [] }),
      resolveChain: async (s: ScopeRef) => (s.type === 'app' ? [s] : null),
      factsOrigin: { name: 'gs-origen', authzTables: false },
      facts: async () => ({ facts: [{ kind: 'deny', holder: { type: 'users', uuid: U.uuid }, scope: { type: 'app', uuid: null }, permission: 'docs:read', detail: 'deny del origen' }], skipped: [] }),
    }
    const blockedPass = await blocking.reconcile(denySource, { prune: false }).then(() => null, (e: any) => e)
    assert.equal(blockedPass?.code, 'E_AUTHZ_DENY_MIGRATION_REFUSED', red(`el reconcile de roles escribe alrededor de un deny bloqueado por una condición ajena (${blockedPass?.code} ${blockedPass?.message})`))
    assert.deepEqual(blockingWrites, [], red('el reconcile de roles escribió con un deny bloqueado'))
    const blockedDry = await blocking.reconcile(denySource, { dryRun: true, prune: false })
    assert.isTrue(blockedDry.details.some((skip: any) => skip.reason === 'invalid-condition'), '--dry-run la lista (deriva)')
    // Cierre-2 de L11 (🟡 C1 del auditor): en la pasada de MANTENIMIENTO (origen = el propio store) ese mismo deny ajeno NO
    // bloquea: `enumerateFacts` lo MARCA, la pasada corre (rehace lo derivado), no escribe ni borra esa clave y la reporta.
    const maintWrites: any[] = []
    const maint: any = new OpenFgaAuthorizationDriver({ apiUrl: 'http://127.0.0.1:1', storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV', modelId: TEST_MODEL_ID, holderTypes: { users: 'user' }, acceptScopeDriftRisk: true, logger: { warn: () => {} } } as any)
    maint.client = {
      ...blocking.client,
      write: async (body: any) => void maintWrites.push(body),
      writeTuples: async (body: any) => void maintWrites.push({ writes: body }),
      deleteTuples: async (body: any) => void maintWrites.push({ deletes: body }),
    }
    maint.catalog = { view: async () => ({ permissionSlugs: ['docs:read'], permissionSlug: () => null }) }
    const selfPage = await maint.enumerateFacts({ limit: 10 })
    assert.isString(selfPage.facts[0]?.invalidCondition, red('enumerateFacts emite un deny con condición ajena como deny LIMPIO'))
    const selfSource = {
      enumerateEdges: async () => ({ edges: [] }),
      resolveChain: async (s: ScopeRef) => (s.type === 'app' ? [s] : null),
      factsOrigin: { name: 'openfga', authzTables: false, self: true },
      facts: async () => selfPage,
    }
    const deniedId = `${user}#denied_docs_read@scope:app`
    for (const prune of [false, true]) {
      const selfPass = await maint.reconcile(selfSource, { prune }).then((r: any) => r, (e: any) => e)
      assert.notEqual(selfPass?.code, 'E_AUTHZ_DENY_MIGRATION_REFUSED', red(`la pasada de MANTENIMIENTO se auto-bloquea con un deny ajeno del propio store (prune=${prune})`))
      assert.isUndefined(selfPass?.code, `la pasada corre (${selfPass?.code} ${selfPass?.message})`)
      assert.isAbove(selfPass.phases.root.written, 0, 'rehace lo DERIVADO (el marcador de raíz)')
      assert.equal(selfPass.skipped['invalid-condition'], 1, 'el deny ajeno se REPORTA una vez (deriva)')
      const touched = maintWrites.flatMap((b: any) => [...(b.writes ?? []), ...(b.deletes ?? [])]).map((t: any) => `${t.user}#${t.relation}@${t.object}`)
      assert.notInclude(touched, deniedId, red('la pasada de mantenimiento escribió o borró el deny ajeno'))
      maintWrites.length = 0
    }
    // Consumidores · el PLAN del reconcile (doble con la marca inyectada en el origen y en el destino).
    const inject = (driver: RelationsDriver, ids: Set<string>) =>
      new Proxy(driver as any, {
        get(target, prop) {
          if (prop === 'enumerateRelations') {
            return async (...args: any[]) => {
              const out = await target.enumerateRelations(...args)
              return { ...out, tuples: out.tuples.map((t: any) => (ids.has(t.object.id) ? { ...t, expiresAt: new Date(0), invalidCondition: 'foreign: inverted' } : t)) }
            }
          }
          const value = Reflect.get(target, prop, target)
          return typeof value === 'function' ? value.bind(target) : value
        },
      }) as RelationsDriver
    const from = makeRelationsDriver({ config: contractRelationsConfig(), capabilities: FULL })
    const to = makeRelationsDriver({ config: contractRelationsConfig(), capabilities: FULL })
    const a = { type: 'document', id: uuidv7() }
    const b = { type: 'document', id: uuidv7() }
    await from.relate(U, 'viewer', a, P)
    await to.relate(U, 'viewer', b, P)
    const report = await reconcileRelations({ from: inject(from, new Set([a.id])), to: inject(to, new Set([b.id])), partition: P, prune: true, dryRun: true })
    assert.equal(report.written, 0, red('el plan migra (como permanente) una tupla del origen con condición ajena'))
    assert.equal(report.deleted, 0, red('el plan poda una tupla del destino con condición ajena'))
    assert.sameMembers(report.details!.map((d) => `${d.side}:${d.reason}`), ['origen:invalid-condition', 'destino:invalid-condition'])
    // Cierre de L11 (🟡 A2): una MEMBRESÍA con condición ajena en una partición con un deny NIEGA la partición.
    const cp = { type: 'unit', uuid: uuidv7() }
    const cg = { type: 'group', id: uuidv7() }
    const cfrom = makeRelationsDriver({ config: contractRelationsConfig(), capabilities: FULL })
    await cfrom.relate(U, 'viewer', a, cp)
    await cfrom.deny!({ object: cg, relation: 'member' }, 'viewer', a, cp)
    await cfrom.relate(U, 'member', cg, cp)
    const carrierReport = await reconcileRelations({ from: inject(cfrom, new Set([cg.id])), to: makeRelationsDriver({ config: contractRelationsConfig(), capabilities: FULL }), partition: cp, dryRun: true })
    assert.deepEqual(carrierReport.partitionsRefused?.flatMap((r) => r.causes.map((c) => c.reason)), ['invalid-condition'], red('el plan salta como allow una membresía ajena que puede transportar un deny (A2)'))
  })
})

/**
 * **`openfga.provision.reread`** (L11 · C12): `openfga:provision` por el KERNEL contra un servidor HTTP falso que publica y
 * relee; la relectura devuelve lo publicado o lo publicado MUTADO. Las dos ramas (store nuevo y `--store-id`).
 */
test.group('GS · P · openfga.provision.reread (lote «antes de RC» · L11)', () => {
  const property = GUARD_PROPERTIES.find((p) => p.id === 'openfga.provision.reread')!
  test(property.title, async ({ assert }) => {
    const red = (what: string) => `ROJO (${property.id}): ${what}`
    const fake = await provisionFake()
    try {
      const config = {
        holderTypes: { users: 'user' },
        catalogs: [async () => ({ permissions: [{ slug: 'docs:read' }] })],
        openfga: { url: fake.url },
      }
      for (const branch of [[], [`--store-id=${fake.storeId}`]] as string[][]) {
        // Cierre de L11 (🟡-1 del tester): además de la condición (global), una deriva SOLO de roles (`scope#can_*`: la
        // relectura compara el modelo ENTERO, no el slice de relaciones — X18) y un tipo DE MÁS (X17).
        for (const mutated of [false, 'condition', 'roles', 'extra-type'] as const) {
          fake.mutate = mutated
          const run = await (await aceFor(OpenFgaProvision, { authorization: config })).exec(branch)
          const logs = run.logs.join('\n')
          const label = `${branch.length ? '--store-id' : 'store nuevo'} · relectura ${mutated ? `MUTADA (${mutated})` : 'igual'}`
          if (!mutated) {
            assert.equal(run.exitCode ?? 0, 0, `${label}: ${logs}`)
            assert.include(logs, 'OPENFGA_MODEL_ID=', label)
            // Punto 7 de CLAUDE.md: la rama «relectura igual» tiene su línea con prefijo ESTABLE.
            assert.include(logs, 'provision RELECTURA OK:', red(`${label}: la rama de éxito no dice que releyó`))
            assert.notInclude(logs, 'provision RELECTURA FALLIDA:', label)
            continue
          }
          assert.notInclude(logs, 'provision RELECTURA OK:', red(`${label}: dice OK con la relectura distinta`))
          assert.equal(run.exitCode, 1, red(`${label}: la relectura distinta no da exit 1 — ${logs}`))
          assert.include(logs, 'provision RELECTURA FALLIDA:', label)
          assert.include(logs, 'NO lo fijes', label)
          assert.notInclude(logs, 'OPENFGA_MODEL_ID=', red(`${label}: imprime el id que NO hay que fijar`))
        }
      }
    } finally {
      await fake.close()
    }
  }).timeout(TEST_TIMEOUT)
})

/** Un OpenFGA HTTP mínimo para `provision`: crea stores, publica modelos y los relee (opcionalmente MUTADOS). */
async function provisionFake() {
  const state = {
    url: '',
    storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
    mutate: false as false | 'condition' | 'roles' | 'extra-type',
    models: new Map<string, any>(),
    close: async () => {},
  }
  let n = 0
  const server = http.createServer((req, res) => {
    let body = ''
    req.on('data', (chunk) => (body += chunk))
    req.on('end', () => {
      const send = (status: number, data: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json' })
        res.end(JSON.stringify(data))
      }
      const path = req.url?.split('?')[0] ?? ''
      if (req.method === 'POST' && path === '/stores') return send(201, { id: state.storeId, name: 'gs' })
      const models = `/stores/${state.storeId}/authorization-models`
      if (req.method === 'GET' && path === models) return send(200, { authorization_models: [], continuation_token: '' })
      if (req.method === 'POST' && path === models) {
        const id = `01ARZ3NDEKTSV4RRFFQ69G5F${String(n++).padStart(2, '0')}`
        state.models.set(id, { id, ...JSON.parse(body || '{}') })
        return send(201, { authorization_model_id: id })
      }
      if (req.method === 'GET' && path.startsWith(`${models}/`)) {
        const model = JSON.parse(JSON.stringify(state.models.get(path.slice(models.length + 1)) ?? null))
        if (model && state.mutate === 'condition') model.conditions.not_expired.expression = 'current_time <= valid_until'
        if (model && state.mutate === 'roles') {
          const scope = model.type_definitions.find((t: any) => t.type === 'scope')
          scope.relations.can_docs_read = { intersection: { child: [{ computedUserset: { relation: 'docs_read' } }, { computedUserset: { relation: 'rooted' } }] } }
        }
        if (model && state.mutate === 'extra-type') {
          model.type_definitions.push({ type: 'invoice', relations: { reader: { this: {} } }, metadata: { relations: { reader: { directly_related_user_types: [{ type: 'user' }] } } } })
        }
        return model ? send(200, { authorization_model: model }) : send(400, { code: 'authorization_model_not_found' })
      }
      if (req.method === 'POST' && path === `/stores/${state.storeId}/read`) return send(200, { tuples: [], continuation_token: '' })
      return send(400, { code: 'validation_error', message: `fake: ${req.method} ${path}` })
    })
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  state.url = `http://127.0.0.1:${(server.address() as any).port}`
  state.close = () => new Promise((resolve) => server.close(() => resolve()))
  return state
}

/**
 * **`openfga.roles.model.equal`** (L11; injerto 6 del juez: roles por REFLEXIÓN, no como capa): TODO método del prototipo
 * de `OpenFgaAuthorizationDriver` está clasificado —llega al store (con su invocación), vista, o ayudante privado—; uno
 * nuevo sin clasificar nace rojo con su nombre. Cada método que llega al store, sobre la base y sobre las dos vistas por
 * prototipo, da 500 `E_AUTHZ_CONFIG` con un modelo con deriva en `scope` y CERO llamadas que no sean la lectura del
 * modelo (memo compartido); `enumerateFacts` responde con esa deriva (solo pasa la parte `conditions`) y da 500 con una
 * deriva de condiciones.
 */
const ROLES_STORE_METHODS: Record<string, (d: any) => Promise<unknown>> = {
  authorize: (d) => d.authorize({ type: 'users', uuid: uuidv7() }, 'docs:read', P),
  authorizeMany: (d) => d.authorizeMany({ type: 'users', uuid: uuidv7() }, 'docs:read', [P]),
  grant: (d) => d.grant({ type: 'users', uuid: uuidv7() }, 'admin', P),
  revoke: (d) => d.revoke({ type: 'users', uuid: uuidv7() }, 'admin', P),
  hasRole: (d) => d.hasRole({ type: 'users', uuid: uuidv7() }, 'admin', P),
  deny: (d) => d.deny({ type: 'users', uuid: uuidv7() }, 'docs:read', P),
  removeDeny: (d) => d.removeDeny({ type: 'users', uuid: uuidv7() }, 'docs:read', P),
  listSubjects: (d) => d.listSubjects('admin', P),
  listRoles: (d) => d.listRoles({ type: 'users', uuid: uuidv7() }, P),
  rolesInChain: (d) => d.rolesInChain({ type: 'users', uuid: uuidv7() }, [P]),
  listRoleScopes: (d) => d.listRoleScopes({ type: 'users', uuid: uuidv7() }, 'unit'),
  listScopes: (d) => d.listScopes({ type: 'users', uuid: uuidv7() }, 'docs:read'),
  listDenies: (d) => d.listDenies({ type: 'users', uuid: uuidv7() }, P),
  onScopeAttached: (d) => d.onScopeAttached({ type: 'unit', uuid: uuidv7() }, { type: 'app', uuid: null }),
  onScopeMoved: (d) => d.onScopeMoved({ type: 'unit', uuid: uuidv7() }, { type: 'app', uuid: null }),
  onScopeDetached: (d) => d.onScopeDetached({ type: 'unit', uuid: uuidv7() }),
  purgeScope: (d) => d.purgeScope({ type: 'unit', uuid: uuidv7() }),
  catalogProjection: (d) => d.catalogProjection().project({ roles: [], permissions: [] }),
  purgeRole: (d) => d.purgeRole(uuidv7()),
  countRoleAssignments: (d) => d.countRoleAssignments([uuidv7()]),
  projectCatalogRole: (d) => d.projectCatalogRole(uuidv7()),
  reconcile: (d) => d.reconcile({}, {}),
}
/** Vistas (se re-corre la tabla sobre ellas) y lo que no llega al store, con su razón. */
const ROLES_NOT_STORE: Record<string, string> = {
  constructor: 'construye (modelId obligatorio: C14)',
  capabilities: 'getter: declara, no llama',
  withChainResolver: 'VISTA por prototipo: la tabla se re-corre sobre ella',
  withClock: 'VISTA por prototipo: la tabla se re-corre sobre ella',
  enumerateFacts: 'ORIGEN de una migración: solo la parte conditions (sonda propia abajo)',
}
const ROLES_PRIVATE_HELPERS = [
  'chain', 'knownScope', 'canonicalOrSelf', 'canonicalTargets', 'checkContext', 'modelGate', 'assertModel', 'fgaSubject', 'batchCheckAll',
  'findPermission', 'declaredRole', 'factsAuthorize', 'factsAuthorizeMany', 'rejectTransaction', 'writeAssignment', 'replaceAssignment',
  'readAssignment', 'denyTuple', 'listBindings', 'deniedScopeKeys', 'factsDenies', 'parseBindings', 'warn', 'assertOneParent', 'assertEdge',
  'reparent', 'sweepLocalRoleBindings', 'sweepRoleVisibility', 'classifyBindingEdge', 'applyBindingSweep', 'storeChain', 'ensureFactsRoot',
  'projectCatalog', 'modelPermissions', 'readSourceTree', 'readSourceFacts', 'readOriginFacts', 'wantAssignment', 'wantDeny', 'eachRow',
  'readEveryTuple', 'applyReconcileWrites', 'tuplesOrThrow', 'readAllTuples', 'sql', 'withSourceSnapshot',
  // Lote C · L13 (settle) y hallazgo 3 TREE: ayudantes de los métodos que escriben (todos detrás de su `assertModel`).
  'writeCatalog', 'writeCatalogKnowing', 'checkForWrite', 'decideRoleVisibility', 'writeBindingEdges', 'settleRoleVisibility', 'settleRounds',
  'writeGrant', 'localBindingsBelow', 'settleSubtree', 'projectRolePermits', 'readForWrite',
]

test.group('GS · P · openfga.roles.model.equal (lote «antes de RC» · L11)', () => {
  const property = GUARD_PROPERTIES.find((p) => p.id === 'openfga.roles.model.equal')!
  test(property.title, async ({ assert }) => {
    const red = (what: string) => `ROJO (${property.id}): ${what}`
    const inventory = Object.getOwnPropertyNames(OpenFgaAuthorizationDriver.prototype)
    const classified = new Set([...Object.keys(ROLES_STORE_METHODS), ...Object.keys(ROLES_NOT_STORE), ...ROLES_PRIVATE_HELPERS])
    assert.deepEqual(inventory.filter((name) => !classified.has(name)), [], red('método del driver de roles SIN clasificar (¿llega al store? añádelo a ROLES_STORE_METHODS con su invocación)'))
    assert.deepEqual([...classified].filter((name) => !inventory.includes(name)), [], 'la clasificación no inventa métodos')
    const drifted = generatedModel({ users: 'user' }, ['docs:read'])
    drifted.type_definitions.find((t: any) => t.type === 'scope').relations.can_docs_read = {
      intersection: { child: [{ computedUserset: { relation: 'docs_read' } }, { computedUserset: { relation: 'rooted' } }] },
    }
    const conditionsDrift = generatedModel({ users: 'user' }, ['docs:read'])
    conditionsDrift.conditions.not_expired.expression = 'current_time <= valid_until'
    const make = (served: unknown, failFirst: boolean | (() => Error) = false) => {
      const calls: string[] = []
      // El resolutor conoce la raíz y NADA más (desde el cierre de L11 la puerta va ANTES de `assertEdge` en `attached`/`moved`).
      const resolveChain = async (s: ScopeRef) => (s.type === 'app' ? [s] : null)
      const driver: any = new OpenFgaAuthorizationDriver({ apiUrl: 'http://127.0.0.1:1', storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV', modelId: TEST_MODEL_ID, holderTypes: { users: 'user' }, resolveChain, acceptScopeDriftRisk: true, logger: { warn: () => {} } } as any)
      let reads = 0
      driver.client = new Proxy({}, {
        get(_t, prop) {
          if (typeof prop !== 'string') return undefined
          return async () => {
            calls.push(prop)
            if (prop === 'readAuthorizationModel') {
              reads++
              if (failFirst && reads === 1) {
                throw typeof failFirst === 'function' ? failFirst() : new AuthorizationBackendError('openfga', 'readAuthorizationModel', new Error('FGA caído'))
              }
              return { authorization_model: served }
            }
            return prop === 'read' ? { tuples: [], continuation_token: '' } : {}
          }
        },
      })
      return { driver, calls }
    }
    const { driver, calls } = make(drifted)
    const targets: Array<[string, any]> = [
      ['base', driver],
      ['vista withChainResolver', driver.withChainResolver(async (s: ScopeRef) => (s.type === 'app' ? [s] : null))],
      ['vista withClock', driver.withClock(() => new Date())],
    ]
    for (const [label, target] of targets) {
      for (const [method, invoke] of Object.entries(ROLES_STORE_METHODS)) {
        const caught = await invoke(target).then(() => null, (e: any) => e)
        assert.equal(caught?.code, 'E_AUTHZ_CONFIG', red(`${method} [${label}]: llegó al store con un modelo con deriva en scope (${caught?.code} ${caught?.message})`))
        assert.include(String(caught?.message), 'scope#can_docs_read (regla)', `${method} [${label}]`)
        // Cierre de L11 (🟠 A1 = H1): el 500 de la puerta es un fallo del DESPLIEGUE ⇒ transitorio para el relay.
        assert.isTrue(caught?.deploymentFailure === true, red(`${method} [${label}]: el 500 de la puerta no va marcado como fallo de despliegue (el relay lo contaría como intento y aparcaría el moved)`))
      }
    }
    assert.deepEqual([...new Set(calls)], ['readAuthorizationModel'], red(`algún método llamó al store además de leer el modelo: ${calls.join(', ')}`))
    assert.equal(calls.length, 1, 'UNA lectura del modelo entre la base y las dos vistas (memo compartido, H11 b)')
    // enumerateFacts: con la deriva de REGLAS responde (origen de una migración); con la de CONDICIONES, 500.
    const origin = make(drifted)
    const facts = await origin.driver.enumerateFacts({ limit: 10 }).then((page: any) => page, (e: any) => e)
    assert.notInstanceOf(facts, Error, `enumerateFacts pasa solo la parte conditions: ${facts?.message}`)
    const conditions = await make(conditionsDrift).driver.enumerateFacts({ limit: 10 }).then(() => null, (e: any) => e)
    assert.equal(conditions?.code, 'E_AUTHZ_CONFIG', red('enumerateFacts con la condición not_expired distinta no se niega'))
    // C13 a (roles): un 503 al leer el modelo NO se memoriza.
    const flaky = make(generatedModel({ users: 'user' }, ['docs:read']), true)
    const first = await flaky.driver.listRoleScopes({ type: 'users', uuid: uuidv7() }, 'unit').then(() => null, (e: any) => e)
    assert.equal(first?.status, 503)
    const second = await flaky.driver.listRoleScopes({ type: 'users', uuid: uuidv7() }, 'unit').then((v: any) => v, (e: any) => e)
    assert.notInstanceOf(second, Error, red(`C13 a: el 503 se memorizó (${second?.message})`))
    // Cierre de L11 (🟡-6 del tester): «comparación hecha ⇒ memo», «fallo al LEER el modelo ⇒ no memo», sea de la clase
    // que sea — con R3 un 401/403 o un modelo inexistente serán un 500 de despliegue al LEER y no pueden quedarse
    // memorizados (un token rotado se recuperaría solo reiniciando). Se simula con un 500 de configuración en la lectura.
    const readConfig = make(generatedModel({ users: 'user' }, ['docs:read']), () => new AuthorizationConfigError('401 al leer el modelo (simulado: R3 lo clasificará como despliegue)'))
    const configFirst = await readConfig.driver.listRoleScopes({ type: 'users', uuid: uuidv7() }, 'unit').then(() => null, (e: any) => e)
    assert.equal(configFirst?.code, 'E_AUTHZ_CONFIG')
    const configSecond = await readConfig.driver.listRoleScopes({ type: 'users', uuid: uuidv7() }, 'unit').then((v: any) => v, (e: any) => e)
    assert.notInstanceOf(configSecond, Error, red(`un 500 al LEER el modelo se memorizó (${configSecond?.message})`))
    assert.equal(readConfig.calls.filter((c) => c === 'readAuthorizationModel').length, 2, 'relee tras el fallo de lectura')
    // Y la otra cara (X6 del tester): el 500 del GENERADOR sí sale de una comparación hecha (determinista con ese modelo,
    // H11 d) y SE memoriza — una sola lectura para dos operaciones; su error es de despliegue (transitorio para el relay).
    const ungenerable = generatedModel({ users: 'user' }, ['docs:read'])
    ungenerable.type_definitions.find((t: any) => t.type === 'role').relations.permits_parent = { this: {} }
    const generator = make(ungenerable)
    for (let i = 0; i < 2; i++) {
      const caught = await generator.driver.listRoleScopes({ type: 'users', uuid: uuidv7() }, 'unit').then(() => null, (e: any) => e)
      assert.equal(caught?.code, 'E_AUTHZ_CONFIG', `el generador que no puede generar es 500 (${caught?.message})`)
      assert.isTrue(caught?.deploymentFailure === true, red('el 500 del generador no va marcado como fallo de DESPLIEGUE (el relay lo aparcaría)'))
    }
    assert.equal(generator.calls.filter((c) => c === 'readAuthorizationModel').length, 1, red('el 500 del generador (comparación hecha) no se memorizó'))
  })
})

/* ── R3 · fga.errors.classify ── */

/** El cuerpo de una función de nivel superior (`function NAME(` … su llave de cierre) en el texto de un fichero. */
function functionBody(source: string, name: string): string {
  const start = source.search(new RegExp(`\\nexport function ${name}\\b|\\nfunction ${name}\\b`))
  if (start < 0) return ''
  const open = source.indexOf('{', source.indexOf(')', start))
  let depth = 0
  for (let i = open; i < source.length; i++) {
    if (source[i] === '{') depth++
    else if (source[i] === '}' && --depth === 0) return source.slice(start, i + 1)
  }
  return source.slice(start)
}

/** El bloque `{ … }` que empieza en la primera llave a partir de `start` (un método de clase). */
function blockFrom(source: string, start: number): string {
  if (start < 0) return ''
  const open = source.indexOf('{', source.indexOf(')', start))
  let depth = 0
  for (let i = open; i < source.length; i++) {
    if (source[i] === '{') depth++
    else if (source[i] === '}' && --depth === 0) return source.slice(start, i + 1)
  }
  return source.slice(start)
}

/**
 * La primera LECTURA del mensaje de un error en `code` (sin comentarios), o `null` (cierre de R3, 🟡-1 / ⚪ R3-A6): por
 * propiedad, por índice, por desestructuración o volcando el error a texto. Asignar `.message` (la letra) no cuenta.
 */
function messageReads(code: string): string | null {
  const stripped = code.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1')
  const patterns = [
    /\.message\b(?!\s*=(?!=))/,
    /\bapiErrorMessage\b/,
    /\bresponseData\b/,
    /\bstatusText\b/,
    /\[\s*['"`]message['"`]\s*\]/,
    /\{[^{}]*\bmessage\b[^{}]*\}\s*=[^=>]/,
    /\bString\((?!prop\))/, // `String(prop)` es el NOMBRE del método del cliente (guardBackendErrors), no un error
    /\bJSON\.stringify\(/,
  ]
  for (const pattern of patterns) {
    const match = stripped.match(pattern)
    if (match) return match[0]
  }
  return null
}

/** Las funciones de nivel superior que aplican una expresión regular al MENSAJE de un error (`/…/.test(… message …)`). */
function messageRegexReaders(source: string): string[] {
  const found = new Set<string>()
  const pattern = /\/[^/\n]+\/[gimsuy]*\.test\(([^)\n]*)\)/g
  for (const match of source.matchAll(pattern)) {
    if (!/message|Message/.test(match[1])) continue
    const before = source.slice(0, match.index)
    const owners = [...before.matchAll(/\n(?:export )?(?:async )?function (\w+)/g)]
    found.add(owners.length ? owners[owners.length - 1][1] : '<nivel superior>')
  }
  return [...found].sort()
}

test.group('GS · P · fga.errors.classify (lote «antes de RC» · R3)', () => {
  const property = GUARD_PROPERTIES.find((p) => p.id === 'fga.errors.classify')!
  test(property.title, async ({ assert }) => {
    const red = (what: string) => `ROJO (${property.id}): ${what}`
    const fixtures = loadFgaFixtures()
    assert.lengthOf(fixtures, 41, 'las 41 formas de F0 · M-d, versionadas')
    const throwing = throwingFgaFixtures()
    assert.deepEqual(throwing.map((f) => f.id).sort(), Object.keys(FGA_FIXTURE_CLASS).sort(), 'cada fixture que lanza tiene su clase en la tabla')

    // (1) La tabla de verdad PURA: la forma reconstruida es la medida, y la clase no se mueve con el mensaje.
    for (const fixture of throwing) {
      const expected = FGA_FIXTURE_CLASS[fixture.id]
      const error = fgaErrorFromFixture(fixture)
      assertFixtureShape(assert, fixture, error)
      assert.equal(classifyFgaFailure(error).kind, expected, red(`${fixture.id}: clase`))
      for (const poisoned of POISONED_MESSAGES) {
        assert.equal(classifyFgaFailure(fgaErrorFromFixture(fixture, poisoned)).kind, expected, red(`${fixture.id}: la clase cambió con el mensaje «${poisoned}» (se clasifica por el mensaje)`))
      }
    }
    // El `FgaError` sin respuesta es timeout para `isTimeoutLike` (el timeout de axios llega sin `code`: F0 · M-d nota 1).
    for (const id of ['real-client-timeout', 'fake-client-timeout-slow-server', 'net-connection-refused']) {
      assert.isTrue(isTimeoutLike(fgaErrorFromFixture(fixtures.find((f) => f.id === id)!)), red(`${id}: isTimeoutLike no reconoce el FgaError sin respuesta`))
    }

    // (1b) Cierre de R3 (⚪-6 del tester): las dos ramas sin fixture que se CONSERVAN, cada una con su caso. La validación
    // del cliente SIN red (`FgaRequiredParamError`: el SDK la lanza antes de llamar, sin `statusCode`) es despliegue; y
    // un error por ítem cuya clave no es una cadena (el enum como número, una forma nueva) cae a TRANSITORIO —fail-closed
    // ruidoso, 503—, nunca a despliegue ni a `false`.
    assert.equal(classifyFgaFailure(new (FgaRequiredParamError as any)('check', 'storeId')).kind, 'deployment', red('FgaRequiredParamError (validación del cliente, sin red) no es despliegue'))
    for (const item of [{ internal_error: 1 }, { input_error: 2 }, { input_error: null, internal_error: undefined }]) {
      assert.equal(classifyFgaFailure(item).kind, 'transient', red(`el error por ítem ${JSON.stringify(item)} (clave no string) no cae a transitorio`))
    }

    // (2) El error PÚBLICO de cada clase (lo que ve el llamante y lo que lee el relay), con la causa conservada.
    for (const fixture of throwing) {
      const kind = FGA_FIXTURE_CLASS[fixture.id]
      const cause = fgaErrorFromFixture(fixture)
      const pub: any = fgaFailureError('openfga', 'check', cause, { timeoutMs: 1000 })
      const want = FGA_PUBLIC_ERROR[kind]
      assert.equal(pub.status, want.status, red(`${fixture.id} (${kind}): status ${pub.status} ${pub.code}`))
      assert.equal(pub.code, want.code, red(`${fixture.id} (${kind}): code`))
      assert.strictEqual(pub.cause, cause, `${fixture.id}: la causa del SDK viaja en cause`)
      // La regla del relay es la del MANAGER (`isTransientRelayFailure`, punto de paso único): la carrera que escapa es 409
      // para el llamante y transitoria para el relay (cierre de R3, 🟠 R3-A1).
      assert.equal(isTransientRelayFailure(pub), want.relayTransient, red(`${fixture.id} (${kind}): transitorio para el relay`))
      if (kind === 'deployment') assert.include(pub.message, 'No es transitorio', `${fixture.id}: la letra`)
      if (kind === 'resolution-limit') assert.include(pub.message, 'Limits', `${fixture.id}: la letra apunta a «Limits»`)
      if (kind === 'race') assert.isTrue(isDuplicateWrite(pub) || /delete/.test(fixture.id), red(`${fixture.id}: la carrera ya no llega a isDuplicateWrite por la causa`))
    }

    // (2b) Cierre de R3 (🟡 R3-A2; invariante 13): en una ESCRITURA, el 504 y `deadline_exceeded` son TIMEOUT
    // (indeterminados); el resto de clases no se mueve por ser escritura, y en una lectura el 504 sigue transitorio.
    for (const fixture of throwing) {
      const kind = FGA_FIXTURE_CLASS[fixture.id]
      const error: any = fgaErrorFromFixture(fixture)
      const writeKind = error.statusCode === 504 || error.apiErrorCode === 'deadline_exceeded' ? 'timeout' : kind
      assert.equal(classifyFgaFailure(error, { write: true }).kind, writeKind, red(`${fixture.id}: clase en una ESCRITURA`))
      for (const poisoned of POISONED_MESSAGES) {
        assert.equal(classifyFgaFailure(fgaErrorFromFixture(fixture, poisoned), { write: true }).kind, writeKind, red(`${fixture.id}: la clase de ESCRITURA cambió con el mensaje «${poisoned}»`))
      }
      const pub: any = fgaFailureError('openfga', 'write', error, { timeoutMs: 1000, write: true })
      assert.equal(pub.code, FGA_PUBLIC_ERROR[writeKind].code, red(`${fixture.id}: código en una ESCRITURA`))
      if (writeKind === 'timeout' && kind !== 'timeout') {
        assert.instanceOf(pub, AuthorizationBackendTimeoutError, red(`${fixture.id}: el 504 de una escritura no es AuthorizationBackendTimeoutError (no habría indeterminate)`))
        assert.include(pub.message, 'INDETERMINADA', `${fixture.id}: la letra no dice «no respondió en N ms»`)
      }
    }

    // (3) El error POR ÍTEM de batchCheck: la MISMA clase que la excepción, en alignBatchResults (respuesta desordenada).
    for (const [id, items] of Object.entries(FGA_ITEM_CLASS)) {
      const fixture = fixtures.find((f) => f.id === id)!
      const results: any[] = fixture.response.result
      for (const [correlationId, kind] of Object.entries(items)) {
        const result = results.find((r) => r.correlationId === correlationId)
        assert.equal(classifyFgaFailure(result.error).kind, kind, red(`${id}#${correlationId}: clase del ítem`))
        const ok = results.find((r) => !r.error)
        const checks = [ok.request, result.request].map((r: any) => ({ ...r }))
        // El servidor no devuelve en orden (nota 2 de M-d): el fallido primero en la respuesta, segundo en la petición.
        const caught: any = (() => {
          try {
            alignBatchResults('openfga-relations', 'checkMany', checks as any, [result, ok])
            return null
          } catch (error) {
            return error
          }
        })()
        const want = FGA_PUBLIC_ERROR[kind]
        assert.equal(caught?.status, want.status, red(`${id}#${correlationId} (${kind}) por alignBatchResults: ${caught?.code}`))
        assert.equal(caught?.code, want.code, red(`${id}#${correlationId} (${kind}) por alignBatchResults`))
        assert.include(String(caught?.message), 'checkMany', `${id}#${correlationId}: nombra la operación`)
      }
    }

    // (4) Los otros DOS puntos de paso, con el cliente que lanza la forma medida: guardBackendErrors (roles) y #guard
    // (relaciones). El mismo error público que la tabla.
    for (const fixture of throwing) {
      const kind = FGA_FIXTURE_CLASS[fixture.id]
      const want = FGA_PUBLIC_ERROR[kind]
      const roles: any = new OpenFgaAuthorizationDriver({ apiUrl: 'http://127.0.0.1:9', storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV', modelId: TEST_MODEL_ID, holderTypes: { users: 'user' }, acceptScopeDriftRisk: true, logger: { warn: () => {} } } as any)
      roles.client.check = async () => {
        throw fgaErrorFromFixture(fixture)
      }
      const viaRoles: any = await roles.client.check({}).then(() => null, (e: any) => e)
      assert.equal(viaRoles?.code, want.code, red(`guardBackendErrors · ${fixture.id} (${kind}): ${viaRoles?.code} ${viaRoles?.message}`))
      assert.equal(isDeploymentFailure(viaRoles), kind === 'deployment' || kind === 'unknown-4xx', red(`guardBackendErrors · ${fixture.id}: marca de despliegue`))
      // Y por un método que ESCRIBE (`write`): el 504 / `deadline_exceeded` sale TIMEOUT (cierre de R3, 🟡 R3-A2).
      const writeKind = fixture.error!.statusCode === 504 || fixture.error!.apiErrorCode === 'deadline_exceeded' ? 'timeout' : kind
      roles.client.write = async () => {
        throw fgaErrorFromFixture(fixture)
      }
      const viaRolesWrite: any = await roles.client.write({}).then(() => null, (e: any) => e)
      assert.equal(viaRolesWrite?.code, FGA_PUBLIC_ERROR[writeKind].code, red(`guardBackendErrors · write · ${fixture.id} (${writeKind}): ${viaRolesWrite?.code}`))
      const writer = fgaDriver()
      fakeFgaClient(writer, [], { failOn: (method) => (method === 'write' ? fgaErrorFromFixture(fixture) : undefined) })
      const viaRelationsWrite: any = await writer.unrelate(U, 'viewer', DOC, P).then(() => null, (e: any) => e)
      assert.equal(viaRelationsWrite?.code, FGA_PUBLIC_ERROR[writeKind].code, red(`#guard · unrelate · ${fixture.id} (${writeKind}): ${viaRelationsWrite?.code} ${viaRelationsWrite?.message}`))
      const relations = fgaDriver()
      fakeFgaClient(relations, [], { failOn: (method) => (method === 'check' ? fgaErrorFromFixture(fixture) : undefined) })
      const viaRelations: any = await relations.check(U, 'viewer', DOC, P).then(() => null, (e: any) => e)
      assert.equal(viaRelations?.code, want.code, red(`#guard · ${fixture.id} (${kind}): ${viaRelations?.code} ${viaRelations?.message}`))
      assert.equal(isDeploymentFailure(viaRelations), kind === 'deployment' || kind === 'unknown-4xx', red(`#guard · ${fixture.id}: marca de despliegue`))
    }

    // (4b) Lote «antes de RC» · F4 (⚪ RC-1 del auditor de R3; punto 6): en RELACIONES la marca `write` es POR LLAMADA
    // (`#guard(op, fn, true)`), así que se ENUMERA por reflexión sobre la fuente —toda llamada a `#guard` cuyo cuerpo
    // escribe (`client.write`/`writeTuples`/`deleteTuples`) lleva `true`— y CADA sitio tiene su sonda de comportamiento:
    // un 504 de esa escritura sale 503 E_AUTHZ_BACKEND_TIMEOUT (indeterminada). Un sitio nuevo sin sonda ⇒ rojo (la
    // cuenta no casa). En roles la marca es estructural (por nombre de método, `guardBackendErrors`): no aplica.
    {
      const source = readFileSync(`${ROOT}src/drivers/openfga_relations_driver.ts`, 'utf8')
      const writeSites: string[] = []
      for (let at = source.indexOf('this.#guard('); at !== -1; at = source.indexOf('this.#guard(', at + 1)) {
        let depth = 0
        let end = at + 'this.#guard'.length
        for (; end < source.length; end++) {
          if (source[end] === '(') depth++
          else if (source[end] === ')' && --depth === 0) break
        }
        const call = source.slice(at, end + 1)
        if (/client\.(write|writeTuples|deleteTuples)\(/.test(call)) writeSites.push(call.replace(/\s+/g, ' '))
      }
      for (const call of writeSites) assert.match(call, /,\s*true\s*\)$/, red(`#guard que ESCRIBE sin la marca write: ${call}`))
      const fixture504 = throwing.find((f) => f.error!.statusCode === 504)!
      const served = { authorization_model: openFgaFactsModel(GUARD_HOLDERS, [], { objectTypes: contractRelationsConfig().objectTypes }) }
      /** Un driver de relaciones con un cliente que sirve `existing` en toda lectura y lanza el 504 en la `nth` llamada a `method`. */
      const probe = (existing: FgaTuple[], failAt?: { method: string; nth: number }) => {
        const driver = fgaDriver()
        const counts = new Map<string, number>()
        const written: any[] = []
        ;(driver as any).client = new Proxy(
          {},
          {
            get(_target, prop) {
              if (typeof prop !== 'string') return undefined
              return async (...args: any[]) => {
                const nth = (counts.get(prop) ?? 0) + 1
                counts.set(prop, nth)
                if (prop === 'readAuthorizationModel') return served
                if (prop === 'read') return { tuples: existing.map((key) => ({ key })), continuation_token: '' }
                if (failAt && prop === failAt.method && nth === failAt.nth) throw fgaErrorFromFixture(fixture504)
                if (prop === 'write') written.push(args[0])
                return {}
              }
            },
          }
        )
        return { driver, written }
      }
      // La tupla tal como la escribe el driver (con caducidad), para la renovación y la purga.
      const capture = probe([])
      await capture.driver.relate(U, 'viewer', DOC, P, { expiresAt: new Date(Date.now() + 3_600_000) })
      const stored: any = capture.written[0].writes[0]
      const later = { expiresAt: new Date(Date.now() + 7_200_000) }
      const sites: Array<[string, FgaTuple[], { method: string; nth: number }, (d: OpenFgaRelationsDriver) => Promise<unknown>]> = [
        ['relate (alta)', [], { method: 'write', nth: 1 }, (d) => d.relate(U, 'viewer', DOC, P)],
        ['relate (renovación: delete)', [stored], { method: 'write', nth: 1 }, (d) => d.relate(U, 'viewer', DOC, P, later)],
        ['relate (renovación: write)', [stored], { method: 'write', nth: 2 }, (d) => d.relate(U, 'viewer', DOC, P, later)],
        ['unrelate', [stored], { method: 'write', nth: 1 }, (d) => d.unrelate(U, 'viewer', DOC, P)],
        ['deny', [], { method: 'write', nth: 1 }, (d) => d.deny(U, 'viewer', DOC, P)],
        ['removeDeny', [], { method: 'write', nth: 1 }, (d) => d.removeDeny(U, 'viewer', DOC, P)],
        ['purgeObject (deleteTuples de la purga)', [stored], { method: 'deleteTuples', nth: 1 }, (d) => d.purgeObject(DOC, P)],
      ]
      assert.lengthOf(writeSites, sites.length, red(`los sitios que ESCRIBEN por #guard (${writeSites.length}) no casan con las sondas (${sites.length}): un sitio nuevo necesita la suya`))
      for (const [name, existing, failAt, run] of sites) {
        const { driver } = probe(existing, failAt)
        const caught: any = await run(driver).then(() => null, (e: any) => e)
        assert.equal(caught?.code, 'E_AUTHZ_BACKEND_TIMEOUT', red(`#guard · ${name}: un 504 de la escritura sale ${caught?.code} (${caught?.message}), no indeterminada`))
      }
    }

    // (5) La puerta del modelo NO memoriza un fallo de DESPLIEGUE al leer (401 rotado, store o modelo inexistente: 🟡-6 del
    // tester de L11): 500 E_AUTHZ_CONFIG marcado y la siguiente operación RELEE. En los dos drivers.
    for (const id of ['fake-401-unauthenticated', 'real-read-model-absent', 'fake-404-store']) {
      const fixture = fixtures.find((f) => f.id === id)!
      const relations = fgaDriver()
      const spy = fakeFgaClient(relations, [], { failOn: (method, nth) => (method === 'readAuthorizationModel' && nth === 1 ? fgaErrorFromFixture(fixture) : undefined) })
      const first: any = await relations.check(U, 'viewer', DOC, P).then(() => null, (e: any) => e)
      assert.equal(first?.code, 'E_AUTHZ_CONFIG', red(`relaciones · ${id} al leer el modelo: ${first?.code}`))
      assert.isTrue(isDeploymentFailure(first), red(`relaciones · ${id}: sin marca de despliegue`))
      const second: any = await relations.check(U, 'viewer', DOC, P).then((v) => v, (e: any) => e)
      assert.notInstanceOf(second, Error, red(`relaciones · ${id}: el fallo de despliegue al LEER el modelo se memorizó (${second?.message})`))
      assert.lengthOf(spy.calls.filter((c) => c === 'readAuthorizationModel'), 2, `relaciones · ${id}: relee`)

      const roles: any = new OpenFgaAuthorizationDriver({ apiUrl: 'http://127.0.0.1:9', storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV', modelId: TEST_MODEL_ID, holderTypes: { users: 'user' }, resolveChain: async (s: ScopeRef) => (s.type === 'app' ? [s] : null), acceptScopeDriftRisk: true, logger: { warn: () => {} } } as any)
      let reads = 0
      roles.client.readAuthorizationModel = async () => {
        reads++
        if (reads === 1) throw fgaErrorFromFixture(fixture)
        return { authorization_model: generatedModel({ users: 'user' }) }
      }
      roles.client.read = async () => ({ tuples: [], continuation_token: '' })
      const rolesFirst: any = await roles.listRoleScopes({ type: 'users', uuid: uuidv7() }, 'unit').then(() => null, (e: any) => e)
      assert.equal(rolesFirst?.code, 'E_AUTHZ_CONFIG', red(`roles · ${id} al leer el modelo: ${rolesFirst?.code} ${rolesFirst?.message}`))
      assert.isTrue(isDeploymentFailure(rolesFirst), red(`roles · ${id}: sin marca de despliegue`))
      const rolesSecond: any = await roles.listRoleScopes({ type: 'users', uuid: uuidv7() }, 'unit').then((v: any) => v, (e: any) => e)
      assert.notInstanceOf(rolesSecond, Error, red(`roles · ${id}: el fallo de despliegue al LEER el modelo se memorizó (${rolesSecond?.message})`))
      assert.equal(reads, 2, `roles · ${id}: relee`)
    }

    // (6) Barrido de FUENTE: ninguna rama del clasificador lee el mensaje, y del lado FGA solo las funciones exentas POR
    // NOMBRE (firmadas) aplican una expresión regular al mensaje de un error.
    const guard = readFileSync(`${ROOT}src/shared/backend_guard.ts`, 'utf8')
    for (const name of ['classifyFgaFailure', 'respondedFgaError', 'isTimeoutLike', 'isBareFgaError', 'fgaFailureError']) {
      const body = functionBody(guard, name)
      assert.isAbove(body.length, 0, `${name} existe en backend_guard.ts`)
      assert.isNull(messageReads(body), red(`${name} lee el mensaje (o el cuerpo) del error`))
    }
    const r3Section = guard.slice(guard.indexOf('/* ── R3: el clasificador ÚNICO'), guard.indexOf('/**\n * Ejecuta una consulta SQL con deadline'))
    // Cierre de R3 (🟡-1 del tester / ⚪ R3-A6 del auditor): el barrido mira CUALQUIER lectura del mensaje —no solo
    // `/re/.test(…)`— en el clasificador y TODOS sus ayudantes (la sección R3 entera, `isTimeoutLike`/`isBareFgaError`, y
    // los dos envoltorios que lo llaman: `guardBackendErrors` y `#guard`): `.message`, `apiErrorMessage`, `responseData`,
    // `statusText`, `['message']`, la desestructuración `{ message } =`, `String(…)` y `JSON.stringify(…)` (una
    // asignación a `.message`, la letra del error público, no es lectura). Las exentas POR NOMBRE viven fuera de este
    // alcance (encima de la clase «carrera»).
    const relationsSource = readFileSync(`${ROOT}src/drivers/openfga_relations_driver.ts`, 'utf8')
    const rolesSource = readFileSync(`${ROOT}src/drivers/openfga_driver.ts`, 'utf8')
    const scopes: Array<[string, string]> = [
      ['sección R3 de backend_guard.ts', r3Section],
      ['isTimeoutLike', functionBody(guard, 'isTimeoutLike')],
      ['isBareFgaError', functionBody(guard, 'isBareFgaError')],
      ['guardBackendErrors', functionBody(rolesSource, 'guardBackendErrors')],
      ['#guard', blockFrom(relationsSource, relationsSource.indexOf('async #guard<T>('))],
    ]
    for (const [name, code] of scopes) {
      assert.isAbove(code.length, 0, `${name}: existe`)
      const hit = messageReads(code)
      assert.isNull(hit, red(`${name} lee el mensaje del error: «${hit}»`))
    }
    const readers = [
      ...messageRegexReaders(r3Section),
      ...messageRegexReaders(readFileSync(`${ROOT}src/drivers/openfga_driver.ts`, 'utf8')),
      ...messageRegexReaders(readFileSync(`${ROOT}src/drivers/openfga_relations_driver.ts`, 'utf8')),
    ].sort()
    assert.deepEqual(readers, [...FGA_MESSAGE_READ_EXEMPT.functions].sort(), red(`del lado FGA leen el mensaje: ${readers.join(', ')} (las únicas exentas, firmadas: ${FGA_MESSAGE_READ_EXEMPT.functions.join(', ')})`))
    if (existsSync(DECISIONS_PATH)) {
      const decisions = readFileSync(DECISIONS_PATH, 'utf8')
      assert.include(decisions, FGA_MESSAGE_READ_EXEMPT.fragment, 'la exención por nombre está firmada en decisiones-dueno-2026-08-28.md')
      assert.include(decisions, FGA_MESSAGE_READ_EXEMPT.entry, 'en la entrada firmada')
    }
  }).timeout(60_000)
})

/**
 * **Cierre de R3 (🟡-4 del tester, su T4)**: el `deny` de relaciones distingue el 409 de un deny CONDICIONAL escrito desde
 * fuera (500 con la receta) de la carrera (409 `E_AUTHZ_WRITE_CONFLICT`) mirando la CAUSA del SDK (`cause.statusCode ===
 * 409`) y releyendo la tupla. Hasta este cierre solo se observaba contra OpenFGA; aquí, con el cliente falso y la forma
 * MEDIDA `fake-409-aborted`, sin servidor.
 */
test.group('R3 · el deny condicional de relaciones, sin servidor (🟡-4)', () => {
  const fixture = () => fgaErrorFromFixture(loadFgaFixtures().find((f) => f.id === 'fake-409-aborted')!)
  const deniedKey = (condition: boolean) => ({ user: 'user:x', relation: 'denied_viewer', object: 'document:x', ...(condition ? { condition: { name: 'not_expired' } } : {}) })

  test('409 del Write + la tupla releída CON condición ⇒ 500 conditionalDeny; SIN condición ⇒ 409 E_AUTHZ_WRITE_CONFLICT; un 503 no relee', async ({ assert }) => {
    const conditional = fgaDriver()
    const spyA = fakeFgaClient(conditional, [deniedKey(true)] as any, { failOn: (method) => (method === 'write' ? fixture() : undefined) })
    const a: any = await conditional.deny(U, 'viewer', DOC, P).then(() => null, (e: any) => e)
    assert.equal(a?.code, 'E_AUTHZ_CONFIG', `ROJO (T4): ${a?.code} ${a?.message}`)
    assert.isTrue(a?.denyConditional, 'es el 500 del deny condicional')
    assert.include(spyA.calls, 'read', 'confirma RELEYENDO, no por el mensaje')

    const race = fgaDriver()
    fakeFgaClient(race, [deniedKey(false)] as any, { failOn: (method) => (method === 'write' ? fixture() : undefined) })
    const b: any = await race.deny(U, 'viewer', DOC, P).then(() => null, (e: any) => e)
    assert.equal(b?.status, 409, `${b?.code} ${b?.message}`)
    assert.equal(b?.code, 'E_AUTHZ_WRITE_CONFLICT')

    const down = fgaDriver()
    const spyC = fakeFgaClient(down, [deniedKey(true)] as any, {
      failOn: (method) => (method === 'write' ? fgaErrorFromFixture(loadFgaFixtures().find((f) => f.id === 'fake-503-unavailable')!) : undefined),
    })
    const c: any = await down.deny(U, 'viewer', DOC, P).then(() => null, (e: any) => e)
    assert.equal(c?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE', `${c?.code} ${c?.message}`)
    assert.notInclude(spyC.calls, 'read', 'un 503 no es el 409 de la condición: no se relee')
  })
})

/* ── G-X · las exenciones son EXACTAMENTE las cinco firmadas, atadas a capa×columna ── */

interface ExemptionExtract {
  cabecera: string[]
  signedAt: string
  exemptions: ExemptionExtractEntry[]
}

function loadExtractFile(assert: any): ExemptionExtract {
  assert.isTrue(
    existsSync(EXTRACT_PATH),
    `ROJO (G-X · 🟠 1): falta el extracto VERSIONADO de la firma D6 (tests/fixtures/exemptions_d6.json); en CI es la única fuente de la firma`
  )
  const doc = JSON.parse(readFileSync(EXTRACT_PATH, 'utf8'))
  assert.isTrue(Array.isArray(doc?.exemptions) && Array.isArray(doc?.cabecera), 'el extracto es { cabecera, signedAt, exemptions }')
  return doc
}

function loadExtract(assert: any): ExemptionExtractEntry[] {
  return loadExtractFile(assert).exemptions
}

function sameSet(a: readonly string[], b: readonly string[]): boolean {
  const x = [...a].sort()
  const y = [...b].sort()
  return x.length === y.length && x.every((v, i) => v === y[i])
}

/**
 * **G-X como función PURA** (cierres 🟠 1 y 🟡 4): las exenciones del manifiesto son EXACTAMENTE las cinco
 * firmadas, el extracto versionado dice lo mismo (id, operación, capas, columna, fecha), y cada celda `exempt`
 * de la tabla está en una capa y una columna que la firma cubre, exactamente una vez por capa firmada.
 */
function exemptionViolations(signed: Record<string, SignedExemption>, extract: ExemptionExtractEntry[], table: GuardRow[]): string[] {
  const out: string[] = []
  const ids = Object.keys(signed)
  if (!sameSet(ids, FIVE_SIGNED)) out.push(`las exenciones firmadas son EXACTAMENTE cinco (D6): el manifiesto declara [${ids.join(', ')}] y la firma es [${FIVE_SIGNED.join(', ')}]`)
  const extractIds = extract.map((e) => e.id)
  if (!sameSet(extractIds, FIVE_SIGNED)) out.push(`el extracto versionado no son exactamente las cinco firmadas: [${extractIds.join(', ')}]`)
  for (const entry of extract) {
    const s = signed[entry.id]
    if (!s) continue
    if (entry.operation !== s.operation) out.push(`${entry.id}: operación '${entry.operation}' en el extracto, '${s.operation}' en el manifiesto`)
    if (!sameSet(entry.layers, s.layers)) out.push(`${entry.id}: capas [${entry.layers.join(', ')}] en el extracto, [${s.layers.join(', ')}] en el manifiesto`)
    if (entry.column !== s.column) out.push(`${entry.id}: columna '${entry.column}' en el extracto, '${s.column}' en el manifiesto`)
    if (entry.reason !== s.reason) out.push(`${entry.id}: la razón del extracto y la del manifiesto difieren («cae la exención si cambia la razón»)`)
    if (entry.signedAt !== SIGNED_AT) out.push(`${entry.id}: fecha de firma '${entry.signedAt}', la de D6 es ${SIGNED_AT}`)
    if (typeof entry.d6 !== 'string' || entry.d6.length === 0) out.push(`${entry.id}: sin fragmento d6`)
  }
  const usage = new Map<string, number>()
  for (const r of table) {
    for (const column of GUARD_COLUMNS) {
      const cell = r.cells[column]
      if (!('exempt' in cell)) continue
      const id = cellId(r.layer, r.operation, column)
      const s = signed[cell.exempt]
      if (!s) {
        out.push(`${id}: exención '${cell.exempt}' NO firmada`)
        continue
      }
      if (r.operation !== s.operation.replace('()', '')) out.push(`${id}: la exención ${cell.exempt} es de '${s.operation}', no de '${r.operation}'`)
      if (column !== s.column) out.push(`${id}: la exención ${cell.exempt} está firmada para la columna '${s.column}', no para '${column}'`)
      if (!s.layers.includes(r.layer)) out.push(`${id}: la exención ${cell.exempt} está firmada para [${s.layers.join(', ')}], no para '${r.layer}'`)
      const key = `${cell.exempt}@${r.layer}`
      usage.set(key, (usage.get(key) ?? 0) + 1)
    }
  }
  for (const [id, s] of Object.entries(signed)) {
    for (const layer of s.layers) {
      const n = usage.get(`${id}@${layer}`) ?? 0
      if (n !== 1) out.push(`${id}: firmada para '${layer}' y usada ${n} veces en esa capa (tiene que ser exactamente una)`)
    }
  }
  return out
}

/**
 * En local, el extracto se cruza con el párrafo D6 del fichero de decisiones (fuera de git): difieren ⇒ rojo.
 * **También capa y columna** (cierre-2, 🟡 D): D6 firma exenciones «de la guardia L1», o sea de F-05 ⇒ la columna
 * es `f05`; y las capas son las que la firma nombra («de openfga») o, si no nombra ninguna, TODAS las capas de la
 * tabla que tienen la operación (una firma «protegida por la lista blanca» vale donde exista la operación: ni una
 * capa de más ni una de menos). Ensanchar `layers` de una exención ya no pasa en local.
 */
function d6Violations(extract: ExemptionExtractEntry[], decisions: string, table: GuardRow[] = GUARD_MANIFEST): string[] {
  const out: string[] = []
  const start = decisions.indexOf('D6 exenciones de la')
  if (start < 0) return ['la firma de D6 («D6 exenciones de la guardia L1 firmadas») no está en el fichero de decisiones']
  const end = decisions.indexOf('D7', start)
  const d6 = decisions.slice(start, end > start ? end : start + 800).replace(/\s*\n\s*/g, ' ')
  const headingAt = decisions.lastIndexOf('\n## ', start)
  const heading = decisions.slice(headingAt + 1, decisions.indexOf('\n', headingAt + 1))
  for (const entry of extract) {
    if (!heading.startsWith(`## ${entry.signedAt}`)) out.push(`${entry.id}: firmada el ${entry.signedAt} según el extracto, pero D6 está bajo «${heading}»`)
    if (!d6.includes(entry.d6)) out.push(`${entry.id}: el fragmento firmado «${entry.d6}» no está en el párrafo D6 (la firma cambió o el extracto miente)`)
    const op = entry.operation.replace('()', '')
    if (!entry.d6.includes(`\`${entry.operation}\``)) out.push(`${entry.id}: el fragmento firmado «${entry.d6}» no nombra \`${entry.operation}\``)
    const named = /\bde openfga\b/.test(entry.d6)
    const expectedLayers = named ? ['openfga'] : [...new Set(table.filter((r) => r.operation === op).map((r) => r.layer))]
    if (!sameSet(entry.layers, expectedLayers)) {
      out.push(
        `${entry.id}: D6 firma «${entry.d6}» ⇒ capas [${expectedLayers.join(', ')}] (${named ? 'la firma nombra la capa' : 'todas las capas de la tabla que tienen la operación'}), ` +
          `y el extracto dice [${entry.layers.join(', ')}]`
      )
    }
    if (entry.column !== 'f05') out.push(`${entry.id}: D6 firma exenciones de la guardia L1 (F-05): la columna es 'f05', y el extracto dice '${entry.column}'`)
  }
  const named = [...d6.matchAll(/`([^`]+)`/g)].map((m) => m[1])
  const wanted = [...new Set(extract.map((e) => e.operation))]
  if (!sameSet([...new Set(named)], wanted)) out.push(`D6 nombra [${named.join(', ')}] y el extracto [${wanted.join(', ')}]: difieren`)
  if (!d6.includes('cae la exención si cambia la razón')) out.push('D6 ya no dice «cae la exención si cambia la razón»')
  return out
}

test.group('GS · G-X · exenciones', () => {
  test('las exenciones son EXACTAMENTE las cinco firmadas (extracto versionado tests/fixtures/exemptions_d6.json), cada una en SU capa y SU columna — sin leer nada fuera de git (CI)', ({ assert }) => {
    const extract = loadExtract(assert)
    assert.deepEqual(exemptionViolations(SIGNED_EXEMPTIONS, extract, GUARD_MANIFEST), [])
  })

  test('en local, el extracto coincide con el párrafo D6 de decisiones-dueno-2026-08-28.md (fuera de git: en CI vale el extracto solo)', ({ assert }) => {
    const extract = loadExtract(assert)
    if (!existsSync(DECISIONS_PATH)) {
      // Límite declarado (🟡 D): sin fichero de decisiones la firma es la revisión del diff. Se dice en voz alta fuera de CI (worktrees).
      if (!process.env.CI) console.warn(`[guardia L1] sin ${DECISIONS_PATH}: el cruce local con D6 no corre; ${DECLARED_LIMIT} — la firma es la revisión del diff del extracto`)
      assert.lengthOf(extract, 5, 'sin fichero de decisiones (checkout de CI): la firma es el extracto')
      return
    }
    assert.deepEqual(d6Violations(extract, readFileSync(DECISIONS_PATH, 'utf8')), [])
  })

  test('el LÍMITE está escrito (🟡 D): la cabecera del extracto y CLAUDE.md (punto 6) dicen que en CI y en los worktrees la firma es la revisión del diff', ({ assert }) => {
    const { cabecera, signedAt } = loadExtractFile(assert)
    assert.equal(signedAt, SIGNED_AT)
    assert.isTrue(cabecera.some((line) => line.includes(DECLARED_LIMIT) && line.includes('REVISIÓN DEL DIFF')), `la cabecera del extracto declara el límite: ${cabecera.join(' / ')}`)
    const claude = readFileSync(CLAUDE_MD_PATH, 'utf8')
    const point6 = claude.slice(claude.indexOf('6. **Guardia de superficie.**'), claude.indexOf('7. **Toda salida dice qué rama corrió**'))
    assert.include(point6, DECLARED_LIMIT, 'CLAUDE.md punto 6 declara el límite')
    assert.include(point6, 'revisión del diff', 'CLAUDE.md punto 6 dice cuál es la firma ahí')
  })

  test('la exención de membersOf es SOLO de openfga: en database, en el manager y en el doble membersOf tiene F-05 con sonda', ({ assert }) => {
    for (const layer of ['manager', 'database', 'double'] as GuardLayer[]) {
      const found = rows(layer).find((r) => r.operation === 'membersOf')
      assert.isDefined(found)
      assert.deepEqual(found!.cells.f05, { probe: true }, `${layer}.membersOf.f05`)
    }
  })
})

/* ── Cierre del auditor del lote 0: sus siete repros, INVERTIDOS (rojo = cerrado) ── */

const SIG = { na: 'signature' } as const

test.group('GS · cierre del auditor del lote 0 (repros invertidos)', () => {
  test('🟠1 · G-X se decide con el extracto versionado: con el fichero de decisiones AUSENTE (checkout de CI) no hay violaciones, y sin extracto es rojo', ({ assert }) => {
    const extract = loadExtract(assert)
    assert.deepEqual(exemptionViolations(SIGNED_EXEMPTIONS, extract, GUARD_MANIFEST), [], 'la firma viaja en el extracto, no en .claude/contexto')
    assert.isFalse(EXTRACT_PATH.includes('.claude/'), 'el extracto vive en tests/fixtures (versionado), no en .claude/contexto (gitignored)')
  })

  test('🟠2 · relateMany/checkMany declaradas `platform` con todo `na: signature` (o escritura con f05 `na`) ⇒ la matriz las rechaza nombrando f05 y platform', ({ assert }) => {
    const all = { f05: SIG, trx: SIG, freeze: SIG, write: SIG, actor: SIG, partition: SIG, truncation: SIG, denyable: SIG, model: SIG }
    const asPlatform = manifestViolations([...GUARD_MANIFEST, row('manager', 'relateMany', 'platform', all), row('manager', 'checkMany', 'platform', all)])
    assert.isTrue(asPlatform.some((v) => v.startsWith('manager.relateMany:') && v.includes("'platform' es SOLO")), asPlatform.join('\n'))
    assert.isTrue(asPlatform.some((v) => v.startsWith('manager.relateMany.f05:') && v.includes('f05 NUNCA admite na')), asPlatform.join('\n'))
    assert.isTrue(asPlatform.some((v) => v.startsWith('manager.checkMany.f05:')), asPlatform.join('\n'))
    const P1 = { probe: true } as const
    const asWrite = manifestViolations([...GUARD_MANIFEST, row('manager', 'relateMany', 'write', { f05: SIG, trx: P1, freeze: P1, write: P1, actor: P1, partition: P1, truncation: SIG, denyable: { na: 'notDeny' }, model: { na: 'nomodel' } })])
    assert.deepEqual(asWrite.filter((v) => v.includes('relateMany')).length, 1, asWrite.join('\n'))
    assert.include(asWrite[0], 'f05 NUNCA admite na')
    const asDoctrine = manifestViolations([...GUARD_MANIFEST, row('manager', 'relateMany', 'write', { f05: P1, trx: P1, freeze: { na: 'doctrine' }, write: P1, actor: P1, partition: P1, truncation: SIG, denyable: { na: 'notDeny' }, model: { na: 'nomodel' } })])
    assert.isTrue(asDoctrine.some((v) => v.startsWith('manager.relateMany.freeze:')), 'doctrine solo vale en freeze × driver')
  })

  test('🟡3 · el inventario ve un campo de clase (arrow), un estático y lo heredado de una clase base', ({ assert }) => {
    class Base extends RelationsManager {
      inherited() {}
    }
    class WithField extends Base {
      static fromConfig() {}
      relateFast = async (s: any, r: string, o: any, p: any) => this.driver().relate(s, r, o, p)
    }
    const found = surfaceOperations(WithField, new WithField(spiedDouble().driver, contractRelationsConfig()))
    assert.includeMembers(found, ['relateFast', 'static fromConfig', 'inherited', 'relate', 'driver'])
    const missing = found.filter((n) => !rows('manager').some((r) => r.operation === n))
    assert.sameMembers(missing, ['relateFast', 'static fromConfig', 'inherited'], 'los tres nacen rojos en G-0 (sin fila)')
  })

  test('🟡4 · una sexta exención sin firma (D6-membersOf-double) es rojo en G-X: no son cinco, no está en el extracto, y la capa no está firmada', ({ assert }) => {
    const extract = loadExtract(assert)
    const sixth = { ...SIGNED_EXEMPTIONS, 'D6-membersOf-double': { operation: 'membersOf', layers: ['double'], column: 'f05', reason: 'sin firma' } } as Record<string, SignedExemption>
    const table = GUARD_MANIFEST.map((r) =>
      r.layer === 'double' && r.operation === 'membersOf'
        ? row('double', 'membersOf', 'read', { ...r.cells, f05: { exempt: 'D6-membersOf-double' as any, probe: 'whitelist' } })
        : r
    )
    const violations = exemptionViolations(sixth, extract, table)
    assert.isTrue(violations.some((v) => v.includes('EXACTAMENTE cinco') && v.includes('D6-membersOf-double')), violations.join('\n'))
    // Y aunque se colara en el manifiesto con las cinco firmadas, la celda del doble usaría una firma de OTRA capa:
    const spoofed = exemptionViolations(
      SIGNED_EXEMPTIONS,
      extract,
      GUARD_MANIFEST.map((r) =>
        r.layer === 'double' && r.operation === 'membersOf' ? row('double', 'membersOf', 'read', { ...r.cells, f05: { exempt: 'D6-membersOf-openfga', probe: 'whitelist' } }) : r
      )
    )
    assert.isTrue(spoofed.some((v) => v.startsWith('double.membersOf.f05:') && v.includes("no para 'double'")), spoofed.join('\n'))
  })

  test('🟡5 · la columna write sondea la escritura PARCIAL: openfga.purgeObject/purgeSubject × write son `probe`, no `na`', ({ assert }) => {
    for (const op of ['purgeObject', 'purgeSubject']) {
      assert.deepEqual(rows('openfga').find((r) => r.operation === op)!.cells.write, { probe: true }, `openfga.${op}.write`)
    }
  })

  test('🟡6 · una subclase que escribe por driver() cumple instanceOf e identidad del driver, pero la sonda F-05 de la fila manager sobre ella es ROJA', async ({ assert }) => {
    class Wrapped extends RelationsManager {
      override async relate(s: any, r: string, o: any, p: any, x?: any): Promise<void> {
        await this.driver().relate(s, r, o, p, x)
      }
    }
    const build: ManagerBuild = async (driver, options) => new Wrapped(driver, contractRelationsConfig(), options)
    const spy = spiedDouble()
    const wrapped = await build(spy.driver, {})
    assert.instanceOf(wrapped, RelationsManager)
    assert.strictEqual(wrapped.driver(), spy.driver)
    assert.notStrictEqual(Object.getPrototypeOf(wrapped), RelationsManager.prototype, 'el caso «el servicio» lo caza por prototipo exacto')
    const relate = rows('manager').find((r) => r.operation === 'relate')!
    const caught = await catching(() => probeManager(assert, relate, 'f05', relate.cells.f05, [['subclase', build]]))
    assert.isNotNull(caught, 'DEFECTO CERRADO: la sonda F-05 sobre el envoltorio tiene que fallar')
    assert.include(String(caught?.message), 'manager.relate [subclase] · F-05')
  })

  test('🟡7 · una fila nueva con sonda F-05 y sin variantes es ROJA con la receta (no una sonda vacía)', async ({ assert }) => {
    const caught = await catching(async () => f05VariantsOf(assert, 'manager.relateMany', 'relateMany'))
    assert.isNotNull(caught)
    assert.include(String(caught?.message), 'sonda F-05 VACÍA')
    assert.include(String(caught?.message), 'F05_VARIANTS')
  })

  test('⚪8 · la sonda de *Many lleva ≥ 2 particiones y la variante NUNCA en [0]: validar solo partitions[0] no la pasa', async ({ assert }) => {
    const seen: ScopeRef[][] = []
    const recorder = { enumerateRelationsMany: async (partitions: ScopeRef[]) => void seen.push(partitions) }
    await INVOKE.enumerateRelationsMany(recorder, 'badPartition')
    assert.lengthOf(seen[0], 2)
    assert.deepEqual(seen[0][0], P2, 'la primera es válida')
    assert.deepEqual(seen[0][1], BAD, 'la rota va en la posición 1')
  })

  test('⚪11 · el doble entra en la columna partition: sus catorce operaciones con tupla (checkMany desde el lote A; deny/removeDeny/listDenies/decideMany desde el lote D) tienen sonda (D4 lo alcanza por partitionKey)', ({ assert }) => {
    // Lote D · D2: `denyPhase` no recibe partición (es config del driver; `na: signature` admitido por NA_MATRIX solo para ella).
    const probing = rows('double').filter((r) => r.kind !== 'view' && r.operation !== 'denyPhase').map((r): [string, boolean] => [r.operation, 'probe' in r.cells.partition && r.cells.partition.probe === true])
    assert.deepEqual(probing.filter(([, p]) => !p), [], `celdas partition del doble sin sonda: ${probing.filter(([, p]) => !p).map(([o]) => o).join(', ')}`)
    assert.lengthOf(probing, 14)
  })
})

/* ── Cierre-2 · re-ataque del auditor (`lote0-auditor-cierre.md`), INVERTIDO (rojo = cerrado) ── */

test.group('GS · cierre-2 del auditor del lote 0 (repros invertidos)', () => {
  test('🟡A · una sonda INVOKE.probeMany que invoca check (copy-paste) es ROJA nombrando los dos métodos; la que invoca probeMany pasa', async ({ assert }) => {
    const seen: string[] = []
    const target = {
      async probeMany() {
        seen.push('probeMany')
        return [true]
      },
      async check() {
        seen.push('check')
        return true
      },
    }
    const misrouted = { ...INVOKE, probeMany: (t: any, v: Variant) => t.check(subj(v), rel(v), obj(v), part(v)) }
    const caught = await probeInvoke('probeMany', target, 'valid', undefined, misrouted).then(() => null, (e) => e)
    assert.instanceOf(caught, ProbeMisroutedError, 'DEFECTO CERRADO: la sonda enrutada a OTRO método es roja')
    assert.include(String(caught?.message), "INVOKE.probeMany tiene que invocar 'probeMany'")
    assert.include(String(caught?.message), 'tocó [check]')
    // Y `catching` NO se la traga: una celda que use expectError ve el rojo igual.
    const viaCatching = await catching(() => probeInvoke('probeMany', target, 'valid', undefined, misrouted)).then(() => null, (e) => e)
    assert.instanceOf(viaCatching, ProbeMisroutedError)
    // La honesta pasa, y la que toca DOS métodos (probeMany y check) también es roja.
    const honest = { ...INVOKE, probeMany: (t: any) => t.probeMany() }
    assert.deepEqual(await probeInvoke('probeMany', target, 'valid', undefined, honest), [true])
    const greedy = { ...INVOKE, probeMany: async (t: any) => (await t.check(), t.probeMany()) }
    const both = await probeInvoke('probeMany', target, 'valid', undefined, greedy).then(() => null, (e) => e)
    assert.instanceOf(both, ProbeMisroutedError)
    assert.include(String(both?.message), 'tocó [check, probeMany]')
  })

  test('🟡B · un closure del contenedor que envuelve el resultado de buildRelationsManager (subclase que escribe por driver()) es ROJO en «el servicio» y en la sonda F-05 de manager.relate sobre lo que el contenedor sirve', async ({ assert }) => {
    class WrappingProvider extends AuthzProvider {
      override register() {
        super.register()
        ;(this as any).app.container.singleton('authz.relations', async () => {
          const built = await buildRelationsManager((this as any).app.config.get('authorization'))
          class Served extends RelationsManager {
            override async relate(s: any, r: string, o: any, p: any, x?: any): Promise<void> {
              await this.driver().relate(s, r, o, p, x)
            }
          }
          return Object.setPrototypeOf(built, Served.prototype)
        })
      }
    }
    const spy = spiedDouble()
    const served = await resolveService(serviceConfig(spy.driver, {}), WrappingProvider)
    assert.instanceOf(served, RelationsManager)
    assert.strictEqual(served.driver(), spy.driver, 'cumple instanceOf e identidad del driver: lo único que afirmaba el cierre-1 para buildRelationsManager')
    const violations = serviceViolations(served)
    assert.isTrue(violations.some((v) => v.includes('ENVOLTORIO') && v.includes('Served')), violations.join('\n'))
    const relate = rows('manager').find((r) => r.operation === 'relate')!
    const build: ManagerBuild = (driver, options) => resolveService(serviceConfig(driver, options), WrappingProvider)
    const caught = await catching(() => probeManager(assert, relate, 'f05', relate.cells.f05, [['contenedor envuelto', build]]))
    assert.isNotNull(caught, 'DEFECTO CERRADO: la sonda F-05 sobre lo que el contenedor sirve es roja')
    assert.include(String(caught?.message), 'manager.relate [contenedor envuelto] · F-05')
  })

  test('🟡C · el inventario ve un GETTER de instancia que devuelve función, un namespace admin.relate y rechaza un Proxy devuelto por el constructor; límite declarado: un campo que es instancia de clase no se recorre', ({ assert }) => {
    class Admin {
      relate() {}
    }
    class Sneaky extends RelationsManager {
      constructor(driver: RelationsDriver) {
        super(driver, contractRelationsConfig())
        Object.defineProperty(this, 'relateRaw', { get: () => (s: any, r: string, o: any, p: any) => driver.relate(s, r, o, p), enumerable: false })
        Object.defineProperty(this, 'admin', { value: { relate: (s: any, r: string, o: any, p: any) => driver.relate(s, r, o, p), nested: { purge: () => {} } }, enumerable: false })
        Object.defineProperty(this, 'sdk', { value: new Admin(), enumerable: false })
      }
    }
    const found = surfaceOperations(Sneaky, new Sneaky(spiedDouble().driver))
    assert.includeMembers(found, ['relateRaw', 'admin.relate', 'admin.nested.purge', 'relate', 'driver'])
    const missing = found.filter((n) => !rows('manager').some((r) => r.operation === n))
    assert.sameMembers(missing, ['relateRaw', 'admin.relate', 'admin.nested.purge'], 'los tres nacen rojos en G-0 (sin fila); `sdk` (instancia de clase) NO se recorre: límite declarado en el manifiesto')
    assert.notInclude(found, 'sdk.relate')
    // Un Proxy devuelto por el constructor mantiene el prototipo exacto y sirve cualquier nombre: la reflexión no lo ve, isProxy sí.
    class Proxied extends RelationsManager {
      constructor(driver: RelationsDriver) {
        super(driver, contractRelationsConfig())
        return new Proxy(this, { get: (t, p, r) => (p === 'hidden' ? async () => driver.relate(U, 'viewer', DOC, P) : Reflect.get(t, p, r)) })
      }
    }
    const proxied = new Proxied(spiedDouble().driver)
    assert.strictEqual(Object.getPrototypeOf(proxied), Proxied.prototype, 'el Proxy conserva el prototipo exacto: «el servicio» por prototipo no lo ve')
    assert.isFunction((proxied as any).hidden)
    assert.notInclude(surfaceOperations(Proxied, proxied), 'hidden', 'la reflexión NO ve lo que sirve un Proxy')
    const caught = (() => {
      try {
        assertNotProxy(assert, 'new Proxied(…)', proxied)
        return null
      } catch (e) {
        return e
      }
    })()
    assert.isNotNull(caught, 'DEFECTO CERRADO: la instancia-Proxy es roja en G-0')
    assert.include(String((caught as Error)?.message), 'es un Proxy')
    assert.isTrue(serviceViolations(proxied).some((v) => v.includes('Proxy')), 'y «el servicio» lo rechaza igual')
  })

  test('🟡D · el cruce local coteja capa y columna (ensanchar layers o cambiar column es rojo), la sonda whitelist sobre check es roja, y una sexta exención no entra ni sin fichero de decisiones', async ({ assert }) => {
    const extract = loadExtract(assert)
    const decisions = existsSync(DECISIONS_PATH)
      ? readFileSync(DECISIONS_PATH, 'utf8')
      : '## 2026-10-14 (2) — x\n**2026-10-14 · D3–D16** D6 exenciones de la guardia L1 firmadas: `driver()`, `capabilities()`, `enumerateRelations`, `enumerateRelationsMany` (protegidos por la lista blanca, no por F-05), `membersOf` de openfga (no implementado); cae la exención si cambia la razón · D7 x'
    assert.deepEqual(d6Violations(extract, decisions), [], 'el extracto de verdad cruza limpio')
    const widened = extract.map((e) => (e.id === 'D6-enumerateRelationsMany' ? { ...e, layers: [...e.layers, 'double' as GuardLayer] } : e))
    const v1 = d6Violations(widened, decisions)
    assert.isTrue(v1.some((v) => v.startsWith('D6-enumerateRelationsMany:') && v.includes('capas [manager, database, openfga]') && v.includes('[manager, database, openfga, double]')), v1.join('\n'))
    const narrowed = extract.map((e) => (e.id === 'D6-membersOf-openfga' ? { ...e, layers: ['openfga', 'double'] as GuardLayer[] } : e))
    const v2 = d6Violations(narrowed, decisions)
    assert.isTrue(v2.some((v) => v.startsWith('D6-membersOf-openfga:') && v.includes('la firma nombra la capa')), v2.join('\n'))
    const recolumned = extract.map((e) => (e.id === 'D6-driver' ? { ...e, column: 'trx' as GuardColumn } : e))
    const v3 = d6Violations(recolumned, decisions)
    assert.isTrue(v3.some((v) => v.startsWith('D6-driver:') && v.includes("la columna es 'f05'")), v3.join('\n'))
    // La sonda sustituta EJECUTA la operación exenta: `whitelist` sobre check (la sexta exención del auditor) es roja aunque la firma se falsifique.
    const forged = row('double', 'check', 'read', { ...rows('double').find((r) => r.operation === 'check')!.cells, f05: { exempt: 'D6-enumerateRelations', probe: 'whitelist' } })
    const caught = await catching(() => probeDouble(assert, forged, 'f05', forged.cells.f05))
    assert.isNotNull(caught, 'DEFECTO CERRADO: la sonda whitelist sobre check es roja')
    assert.include(String(caught?.message), "'check' no es una enumeración")
    // Y sin fichero de decisiones (CI/worktree), la sexta exención sigue siendo roja en G-X por el extracto: no son cinco.
    const sixth = [...extract, { id: 'D6-check-double' as any, operation: 'check', layers: ['double' as GuardLayer], column: 'f05' as GuardColumn, reason: 'sin firma', signedAt: SIGNED_AT, d6: '`membersOf`' }]
    const v4 = exemptionViolations(SIGNED_EXEMPTIONS, sixth, GUARD_MANIFEST)
    assert.isTrue(v4.some((v) => v.includes('el extracto versionado no son exactamente las cinco firmadas') && v.includes('D6-check-double')), v4.join('\n'))
  })

  // Lote D: `deny` YA está clasificada (PORT_WRITES) y nació roja exactamente así (informe del lote D1, §0). El repro
  // invertido pasa a una operación hipotética del lote C (`listObjectsForSubject`), que tiene que nacer roja igual.
  test('🟡E · una operación del inventario que no está en PORT_WRITES ni en PORT_READS (listObjectsForSubject, lote C; deny nació así en el lote D) es ROJA con su nombre; una escritura clasificada como lectura también; PORT_OPERATIONS se deriva de las dos listas', ({ assert }) => {
    const inventory = { manager: ['relate', 'check', 'deny', 'listObjectsForSubject', 'driver', 'static fromConfig'], database: ['listObjectsForSubject', 'withClock'] }
    const violations = classificationViolations(inventory, PORT_WRITES, PORT_READS, GUARD_MANIFEST)
    assert.deepEqual(
      violations.map((v) => v.slice(0, v.indexOf(':'))),
      ['manager.listObjectsForSubject', 'database.listObjectsForSubject'],
      'DEFECTO CERRADO: una operación sin clasificar nace roja (driver/static/withClock no cuentan aquí: los juzga G-0); deny ya está clasificada'
    )
    assert.include(violations[0], 'SIN CLASIFICAR')
    assert.include(violations[0], 'PORT_WRITES o a PORT_READS')
    // Clasificada en las dos listas, o fila cuyo kind contradice la lista ⇒ rojo.
    assert.isTrue(classificationViolations({}, [...PORT_WRITES, 'check'], PORT_READS, GUARD_MANIFEST).some((v) => v.includes("'check' está en PORT_WRITES Y en PORT_READS")))
    const misfiled = classificationViolations({}, PORT_WRITES, PORT_READS, [row('manager', 'relate', 'read', { f05: SIG, trx: SIG, freeze: SIG, write: SIG, actor: SIG, partition: SIG, truncation: SIG, denyable: SIG, model: SIG })])
    assert.deepEqual(misfiled, ["manager.relate: la fila es 'read' y la clasificación del puerto dice 'write'"])
    assert.sameMembers([...PORT_OPERATIONS], [...PORT_WRITES, ...PORT_READS])
    assert.sameMembers([...WRITES], [...PORT_WRITES], 'WRITES del spec se DERIVA de PORT_WRITES')
  })
})

/* ── R1 · relations.group.depth ── */

/**
 * **`relations.group.depth`** (lote «antes de RC» · R1; decisiones del dueño 2026-10-17 (5) y (5-bis)): el límite de
 * anidación de grupos, juzgado SIN servidor en sus cinco puntos de paso — la regla pura (`groupNestingVerdict` /
 * `groupChainDepth`: camino MÁS LARGO, arriba Y abajo, ciclos), la validación de `maxGroupDepth`, la calibración
 * (`calibrateGroupDepth`: el MÍNIMO de las dos sondas) y su memo (solo el éxito), el gate de los DOS drivers (en
 * `database` leyendo por la trx del llamante —T-6— y sin eximir renovaciones; en `openfga` con un cliente falso que
 * calcula la profundidad de las tuplas contextuales) y el PLAN del reconcile (la partición se NIEGA sobre el estado
 * FINAL, nunca se salta la arista). Los casos de motor y los de :8090 viven en `tests/relations_group_depth.spec.ts`.
 */
test.group('GS · P · relations.group.depth (lote «antes de RC» · R1)', () => {
  const property = GUARD_PROPERTIES.find((p) => p.id === 'relations.group.depth')!
  test(property.title, async ({ assert }) => {
    const {
      groupNestingVerdict,
      groupChainDepth,
      assertMaxGroupDepth,
      calibrateGroupDepth,
      groupDepthLimitError,
      plannedRelateOptions,
      GroupDepthBudget,
      GroupDepthBudgetExceeded,
      GROUP_DEPTH_MAX_READS,
      GROUP_DEPTH_MAX_TUPLES,
      GROUP_DEPTH_DEADLINE_MS,
      GROUP_DEPTH_CALIBRATION_BACKOFF_MS,
      GROUP_DEPTH_RECALIBRATION_MIN_INTERVAL_MS,
    } = await import('../src/relations/group_depth.js')
    const { ResolutionLimitError } = await import('../src/errors.js')
    const reader = (edges: Array<[string, string]>) => ({
      parentsOf: async (groups: string[]) => edges.filter(([c]) => groups.includes(c)).map(([child, parent]) => ({ child, parent })),
      childrenOf: async (groups: string[]) => edges.filter(([, p]) => groups.includes(p)).map(([child, parent]) => ({ child, parent })),
    })

    // (1) Pura · el camino MÁS LARGO (T-3): x ⊂ g0, y g0 llega a `top` por un salto directo Y por L1…L5.
    const dag: Array<[string, string]> = [['g0', 'top'], ['g0', 'l1'], ['l1', 'l2'], ['l2', 'l3'], ['l3', 'l4'], ['l4', 'l5'], ['l5', 'top']]
    assert.equal(groupChainDepth(dag.map(([child, parent]) => ({ child, parent }))).depth, 6, 'camino más largo del DAG')
    assert.equal((await groupNestingVerdict({ child: 'x', parent: 'g0' }, 6, reader(dag))).kind, 'too-deep', 'ROJO: contó el camino CORTO (BFS) y no el largo')
    assert.equal((await groupNestingVerdict({ child: 'x', parent: 'g0' }, 7, reader(dag))).kind, 'ok')
    // (2) Pura · arriba Y abajo, y la unión: a⊂b⊂c (2) + la arista c⊂d + d⊂e⊂f (2) = 5.
    const halves: Array<[string, string]> = [['a', 'b'], ['b', 'c'], ['d', 'e'], ['e', 'f']]
    assert.equal((await groupNestingVerdict({ child: 'c', parent: 'd' }, 4, reader(halves))).kind, 'too-deep', 'ROJO: no miró hacia ABAJO (o hacia arriba)')
    assert.equal((await groupNestingVerdict({ child: 'c', parent: 'd' }, 5, reader(halves))).kind, 'ok')
    assert.equal((await groupNestingVerdict({ child: 'z', parent: 'a' }, 4, reader(halves))).kind, 'ok', 'por encima de a hay 2: 2 + 1 = 3')
    // (3) Pura · ciclos: la arista que lo cierra (y el autolazo) ⇒ cycle; un diamante NO es ciclo.
    assert.equal((await groupNestingVerdict({ child: 'c', parent: 'a' }, 20, reader(halves))).kind, 'cycle', 'ROJO: no detectó el ciclo')
    assert.equal((await groupNestingVerdict({ child: 'b', parent: 'b' }, 20, reader(halves))).kind, 'cycle')
    const diamond: Array<[string, string]> = [['m', 'n1'], ['m', 'n2'], ['n1', 'o'], ['n2', 'o']]
    assert.equal((await groupNestingVerdict({ child: 'w', parent: 'm' }, 20, reader(diamond))).kind, 'ok', 'un diamante no es un ciclo')
    // (3b) Pura · un ciclo PREEXISTENTE pesa k − 1 (I del tester): a⊂b⊂c⊂d⊂a (4 nodos ⇒ 3) + d⊂e ⇒ 4, nunca 1.
    const ring = [['a', 'b'], ['b', 'c'], ['c', 'd'], ['d', 'a'], ['d', 'e']].map(([child, parent]) => ({ child, parent }))
    assert.equal(groupChainDepth(ring).depth, 4, 'ROJO (I): el ciclo preexistente no pesó k − 1 saltos')
    // (3c) Pura · el corte por NODOS (H): con maxNodes = 3 la región de `halves` ⇒ too-many-groups, y su letra.
    const crowded = await groupNestingVerdict({ child: 'c', parent: 'd' }, 20, reader(halves), 3)
    assert.deepEqual([crowded.kind, (crowded as any).budget], ['too-many-groups', 'nodes'], 'ROJO (H): el corte por nodos no salta')
    const crowdedError = groupDepthLimitError(crowded as any, 'group:d#member@group:c#member', 20)
    assert.equal(crowdedError.code, 'E_AUTHZ_GROUP_DEPTH_LIMIT')
    assert.include(crowdedError.message, 'no se puede comprobar')
    // (3d) Pura · el PRESUPUESTO del lector (🟠 1 del auditor): requests, tuplas y deadline ⇒ too-many-groups.
    const budgeted = (budget: InstanceType<typeof GroupDepthBudget>) => ({
      parentsOf: async (groups: string[]) => {
        budget.beforeRead()
        budget.charge(1)
        return reader(halves).parentsOf(groups)
      },
      childrenOf: async (groups: string[]) => {
        budget.beforeRead()
        budget.charge(1)
        return reader(halves).childrenOf(groups)
      },
    })
    const byReads = await groupNestingVerdict({ child: 'c', parent: 'd' }, 20, budgeted(new GroupDepthBudget({ reads: 2, tuples: 1e9, deadlineMs: 1e9 })))
    assert.deepEqual([byReads.kind, (byReads as any).budget], ['too-many-groups', 'reads'])
    let tick = 0
    const slow = new GroupDepthBudget({ reads: 1e9, tuples: 1e9, deadlineMs: 50 }, () => (tick += 40))
    const byDeadline = await groupNestingVerdict({ child: 'c', parent: 'd' }, 20, budgeted(slow))
    assert.deepEqual([byDeadline.kind, (byDeadline as any).budget], ['too-many-groups', 'deadline'], 'ROJO: el deadline TOTAL del veredicto no corta')
    assert.instanceOf(new GroupDepthBudgetExceeded('tuples'), Error)
    assert.isAbove(GROUP_DEPTH_MAX_READS, 0)
    // (3e) La letra del 503 de LECTURA (R del tester; decisión 5: «con la misma letra»): nombra los dos mandos.
    const readLimit = new ResolutionLimitError('openfga-relations', 'check')
    assert.include(readLimit.message, 'maxGroupDepth', 'ROJO (R): el 503 de lectura no nombra maxGroupDepth')
    assert.include(readLimit.message, 'OPENFGA_RESOLVE_NODE_LIMIT')

    // (4) Validación de maxGroupDepth AL ARRANCAR (V2-1): solo enteros 1..97 o false.
    for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, 1e9, 24.5, 98, '24', '', null, true]) {
      assert.throws(() => assertMaxGroupDepth(bad), /maxGroupDepth/, `ROJO: aceptó ${String(bad)} (${typeof bad})`)
    }
    for (const good of [1, 22, 97, false, undefined]) assert.equal(assertMaxGroupDepth(good), good)
    // (4b) Cierre-2 · D1 (a), A2 del tester: la ruta LITERAL de la decisión (5), `relations.maxGroupDepth` en defineConfig,
    // es 500 con la receta del sitio bueno (`defineRelationsConfig`), no el genérico «clave desconocida»; sin alias.
    const { defineConfig } = await import('../src/define_config.js')
    for (const key of ['maxGroupDepth', 'enforceGroupDepth']) {
      const misplaced = (() => {
        try {
          defineConfig({ relations: { [key]: key === 'maxGroupDepth' ? 10 : true } } as any)
          return null
        } catch (e) {
          return e as any
        }
      })()
      expectError(assert, misplaced, 500, 'E_AUTHZ_CONFIG', `relations.${key} en defineConfig`)
      assert.include(misplaced.message, `relations.${key}`)
      assert.include(misplaced.message, 'defineRelationsConfig', `ROJO (D1 · A2): relations.${key} no apunta a defineRelationsConfig`)
      // Cierre-3 · R-6: nombra la vía PÚBLICA de la pasada, no el primitivo que salió de la raíz.
      if (key === 'maxGroupDepth') assert.include(misplaced.message, 'runRelationsReconcile')
      assert.notMatch(misplaced.message, /(^|[^.\w])reconcileRelations\b/, 'ROJO (R-6): el 500 nombra reconcileRelations, que ya no es API pública')
    }
    // Cierre-3 · R-6: las lápidas se buscan con `Object.hasOwn` — una clave del PROTOTIPO (`constructor`, `toString`, un
    // `__proto__` propio de un JSON) es el 500 genérico de clave desconocida con su nombre, no `function Object()…`.
    for (const raw of ['{"constructor": 1}', '{"toString": 1}', '{"__proto__": 1}', '{"relations": {"constructor": 1}}']) {
      const proto = (() => {
        try {
          defineConfig(JSON.parse(raw))
          return null
        } catch (e) {
          return e as any
        }
      })()
      expectError(assert, proto, 500, 'E_AUTHZ_CONFIG', `clave del prototipo ${raw}`)
      assert.notInclude(proto.message, '[native code]', `ROJO (R-6): ${raw} leyó el prototipo de la tabla de lápidas`)
      assert.include(proto.message, 'no existe', raw)
    }

    // (5) Calibración · el MÍNIMO de las dos sondas (5-bis): positiva hasta 30, negativa hasta 28 ⇒ 28.
    const probeWith = (positive: number, negative: number) => async (k: number, side: 'positive' | 'negative') =>
      k <= (side === 'positive' ? positive : negative) ? ('ok' as const) : ('too-complex' as const)
    assert.equal(await calibrateGroupDepth(probeWith(30, 28)), 28, 'ROJO: calibró solo con la sonda POSITIVA')
    assert.equal(await calibrateGroupDepth(probeWith(24, 22)), 22)

    // (6) openfga · un cliente FALSO que EVALÚA las tuplas contextuales de la sonda (cierre de R1 · N/M del tester: hasta
    // entonces respondía `allowed: positive` sin mirarlas, y quitar la membresía del no-miembro —la sonda CIEGA de M-c—
    // sobrevivía) y un store MUTABLE (`write` escribe, `deletes` borra) con condiciones. El falso imita al servidor medido
    // (F0 · M-c): un miembro resuelve hasta `positive` saltos, un no-miembro CON membresía hasta `negative`, uno SIN
    // membresías responde F a cualquier profundidad (sonda ciega), y la forma `group#member` resuelve un salto más que la
    // de dominio (T-4). `invert` responde al revés (un servidor que no evalúa como el medido).
    const cfg = (extra: Record<string, unknown> = {}) =>
      defineRelationsConfig({ objectTypes: [{ type: 'document', relations: [{ name: 'viewer' }], deny: 'write' }], holderTypes: ['user'], ...extra } as any)
    const tooComplex = () => fgaErrorFromFixture(loadFgaFixtures().find((f) => f.id === 'real-check-resolution-too-complex')!)
    const unavailable = () => fgaErrorFromFixture(loadFgaFixtures().find((f) => f.id === 'fake-503-unavailable')!)
    type StoredFga = FgaTuple & { condition?: { name: string; context?: Record<string, unknown> } }
    const reachable = (tuples: FgaTuple[], from: string, target: string) => {
      const seen = new Set([from])
      const queue = [from]
      while (queue.length > 0) {
        const node = queue.shift()!
        for (const t of tuples) {
          if (t.user !== node) continue
          const next = `${t.object}#${t.relation}`
          if (next === target) return true
          if (!seen.has(next)) {
            seen.add(next)
            queue.push(next)
          }
        }
      }
      return false
    }
    const fga = (
      config: any,
      opts: {
        positive: number
        negative: number
        stored?: StoredFga[]
        failChecks?: number
        /** El error de los `Check` que fallan (por defecto, un 503 transitorio). */
        failWith?: () => unknown
        invert?: boolean
        onCheck?: () => void
        /** Cada `Read` (cierre-3 · R-2: un servidor LENTO en el gate). */
        onRead?: () => void
        /** Reloj monótono del driver (cierre-2 · D5: backoff y cota de la re-calibración). */
        monotonic?: () => number
        /** Un `Check` SIN tuplas contextuales (una lectura del tenant, no la sonda) responde resolution_too_complex. */
        readTooComplex?: boolean
      }
    ) => {
      const driver = new OpenFgaRelationsDriver(config, {
        apiUrl: 'http://127.0.0.1:9',
        storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
        modelId: '01ARZ3NDEKTSV4RRFFQ69G5FAW',
        holderTypes: { user: 'user' },
        timeoutMs: 1000,
        listObjectsDeadlineMs: 1000,
        logger: { warn: () => {} },
        ...(opts.monotonic ? { [MONOTONIC_CLOCK]: opts.monotonic } : {}),
      } as any)
      const calls: string[] = []
      const checks: any[] = []
      const model = { authorization_model: openFgaFactsModel({ user: 'user' }, [], { objectTypes: config.objectTypes }) }
      const stored: StoredFga[] = opts.stored ?? []
      const matches = (t: FgaTuple, f: any) =>
        (f.user === undefined || t.user === f.user) &&
        (f.relation === undefined || t.relation === f.relation) &&
        (f.object === undefined || (f.object.endsWith(':') ? t.object.startsWith(f.object) : t.object === f.object))
      const remove = (keys: FgaTuple[] = []) => {
        for (const k of keys) {
          const i = stored.findIndex((t) => t.user === k.user && t.relation === k.relation && t.object === k.object)
          if (i >= 0) stored.splice(i, 1)
        }
      }
      ;(driver as any).client = new Proxy({}, {
        get(_t, prop) {
          if (typeof prop !== 'string') return undefined
          return async (request: any) => {
            calls.push(prop)
            if (prop === 'readAuthorizationModel') return model
            if (prop === 'read') opts.onRead?.()
            if (prop === 'read') return { tuples: stored.filter((t) => matches(t, request ?? {})).map((key) => ({ key })), continuation_token: '' }
            if (prop === 'write') {
              remove(request?.deletes)
              stored.push(...(request?.writes ?? []))
              return {}
            }
            if (prop === 'deleteTuples') {
              remove(request)
              return {}
            }
            if (prop === 'check') {
              if (calls.filter((c) => c === 'check').length <= (opts.failChecks ?? 0)) throw (opts.failWith ?? unavailable)()
              if (opts.readTooComplex && !(request.contextualTuples?.length > 0)) throw tooComplex()
              checks.push(request)
              opts.onCheck?.()
              const ctx: FgaTuple[] = request.contextualTuples ?? []
              const hops = ctx.filter((t) => t.relation === 'member' && /\|g\d+#member$/.test(t.user)).length
              const depth = request.relation === 'member' ? hops - 1 : hops
              const positive = String(request.user).endsWith('-member')
              const hasMembership = ctx.some((t) => t.user === request.user)
              if (positive && depth > opts.positive) throw tooComplex()
              if (!positive && hasMembership && depth > opts.negative) throw tooComplex()
              const allowed = reachable(ctx, request.user, `${request.object}#${request.relation}`)
              return { allowed: opts.invert ? !allowed : allowed }
            }
            return {}
          }
        },
      })
      return { driver, calls, checks, stored }
    }
    {
      const { driver, calls } = fga(cfg(), { positive: 30, negative: 28 })
      assert.equal(await driver.groupDepthLimit(), 28, 'openfga · calibrado = mínimo')
      const before = calls.length
      assert.equal(await (driver.withClock(() => new Date()) as OpenFgaRelationsDriver).groupDepthLimit(), 28)
      assert.equal(calls.length, before, 'el éxito se memoriza (también para la vista withClock)')
      // N: la sonda negativa SIN membresía es ciega (F a cualquier profundidad): con ella el techo sería el positivo.
      assert.equal(await fga(cfg(), { positive: 24, negative: 22 }).driver.groupDepthLimit(), 22, 'ROJO (N): la sonda negativa no lleva la membresía del no-miembro (ciega)')
    }
    {
      // M: un servidor que responde AL REVÉS (el miembro F, el no-miembro T) ⇒ 500, jamás un techo.
      expectError(assert, await catching(() => fga(cfg(), { positive: 24, negative: 22, invert: true }).driver.groupDepthLimit()), 500, 'E_AUTHZ_CONFIG', 'ROJO (M): una sonda ciega pasó')
      expectError(assert, await catching(() => calibrateGroupDepth(async () => 'blind' as const)), 500, 'E_AUTHZ_CONFIG', 'pura · blind ⇒ 500')
    }
    {
      // F: sin ningún tipo con relación (solo con una config construida a mano: defineRelationsConfig exige ≥ 1 relación
      // por tipo) la calibración usa la forma `group#member`, que resuelve un salto MÁS (T-4) ⇒ resta 1.
      const bare = fga({ ...cfg(), objectTypes: [] }, { positive: 24, negative: 22 })
      assert.equal(await bare.driver.groupDepthLimit(), 22, 'ROJO (F): la forma group#member no restó el salto de más')
      assert.isTrue(bare.checks.every((c) => c.relation === 'member' && String(c.object).startsWith('group:')), 'la sonda pregunta group#member')
    }
    {
      // Memo SOLO del éxito (C13a): la primera calibración cae (503) y, pasada la ESPERA (cierre-2 · D5, backoff), la
      // siguiente vuelve a calibrar. Dentro de la espera: el MISMO error, sin sondear.
      let clock = 1_000
      const { driver, calls } = fga(cfg(), { positive: 24, negative: 22, failChecks: 1, monotonic: () => clock })
      const first = await catching(() => driver.groupDepthLimit())
      expectError(assert, first, 503, 'E_AUTHZ_BACKEND_UNAVAILABLE', 'openfga · calibración que cae')
      const checksAfterFailure = calls.filter((c) => c === 'check').length
      clock += GROUP_DEPTH_CALIBRATION_BACKOFF_MS - 1
      const waiting = await catching(() => driver.groupDepthLimit())
      // Cierre-3 · R-5: la MISMA clase (503, mismo code) pero una instancia NUEVA por llamada, con el memorizado de `cause`.
      expectError(assert, waiting, 503, 'E_AUTHZ_BACKEND_UNAVAILABLE', 'ROJO (D5): dentro de la espera no relanzó el error de la calibración')
      assert.strictEqual(waiting.cause, first, 'el error de la espera lleva el memorizado de cause')
      assert.equal(calls.filter((c) => c === 'check').length, checksAfterFailure, 'ROJO (D5): sin espera tras el fallo, volvió a sondear dentro del backoff')
      const again = await catching(() => driver.groupDepthLimit())
      assert.notStrictEqual(again, waiting, 'ROJO (R-5): dos llamadas de la espera comparten la MISMA instancia de error')
      assert.notStrictEqual(again, first)
      clock += 1
      assert.equal(await catching(() => driver.groupDepthLimit()), null, 'ROJO: memorizó el FALLO de la calibración')
      assert.equal(await driver.groupDepthLimit(), 22)
      assert.isAbove(calls.filter((c) => c === 'check').length, 2)
    }
    {
      // Cierre-3 · R-5: una calibración que vence su DEADLINE hace indeterminada la escritura que la disparó (tocó la red),
      // pero NO las de la espera: no tocaron la red y no escribieron — 503 no-timeout, sin evento.
      let clock = 1_000
      const timedOut = () => Object.assign(new Error('sonda vencida'), { code: 'ETIMEDOUT' })
      const slow = fga(cfg(), { positive: 24, negative: 22, failChecks: 1, failWith: timedOut, monotonic: () => clock })
      const events: any[] = []
      const manager = new RelationsManager(slow.driver, cfg(), { onRelationWrite: (e: any) => void events.push(e) })
      const nest = (child: string, parent: string) =>
        catching(() => manager.relate({ object: { type: 'group', id: child }, relation: 'member' }, 'member', { type: 'group', id: parent }, P))
      const first = await nest('t0', 't1')
      expectError(assert, first, 503, 'E_AUTHZ_BACKEND_TIMEOUT', 'la calibración que vence su deadline')
      assert.deepEqual(events.map((e) => e.indeterminate === true), [true], 'la escritura que DISPARÓ la sonda es indeterminada (tocó la red)')
      const checks = slow.calls.filter((c) => c === 'check').length
      clock += 1
      const inWindow = await nest('t2', 't3')
      expectError(assert, inWindow, 503, 'E_AUTHZ_BACKEND_UNAVAILABLE', 'ROJO (R-5): dentro de la espera el timeout se relanzó como timeout')
      assert.notInstanceOf(inWindow, AuthorizationBackendTimeoutError)
      assert.instanceOf(inWindow.cause, AuthorizationBackendTimeoutError, 'el memorizado viaja de cause')
      assert.lengthOf(events, 1, 'ROJO (R-5): una escritura de la espera, que no tocó la red, notificó indeterminate')
      assert.equal(slow.calls.filter((c) => c === 'check').length, checks, 'dentro de la espera: cero Check')
      assert.notInclude(slow.calls, 'write')
    }
    {
      // K4 (tester): dos `relate` de anidación CONCURRENTES en frío comparten UNA calibración (la en vuelo se comparte).
      const single = fga(cfg(), { positive: 24, negative: 22 })
      await single.driver.groupDepthLimit()
      const once = single.checks.length
      const both = fga(cfg(), { positive: 24, negative: 22 })
      const nestCold = (child: string, parent: string) =>
        both.driver.relate({ object: { type: 'group', id: child }, relation: 'member' }, 'member', { type: 'group', id: parent }, P)
      await Promise.all([nestCold('k0', 'k1'), nestCold('k2', 'k3')])
      assert.equal(both.checks.length, once, `ROJO (K4): dos relate en frío calibraron dos veces (${both.checks.length} Check frente a ${once})`)
      // K5 (tester): lo que NO es una arista de anidación —membresía de un holder, relación de dominio, unrelate, lecturas—
      // no calibra: cero Check con tuplas contextuales.
      const quiet = fga(cfg(), { positive: 24, negative: 22 })
      const someone = { type: 'user', uuid: uuidv7() }
      await quiet.driver.relate(someone, 'member', { type: 'group', id: 'k0' }, P)
      await quiet.driver.relate({ object: { type: 'group', id: 'k0' }, relation: 'member' }, 'viewer', { type: 'document', id: 'k-doc' }, P)
      await quiet.driver.unrelate({ object: { type: 'group', id: 'k0' }, relation: 'member' }, 'member', { type: 'group', id: 'k1' }, P)
      await quiet.driver.check(someone, 'viewer', { type: 'document', id: 'k-doc' }, P)
      assert.equal(
        quiet.checks.filter((c) => (c.contextualTuples?.length ?? 0) > 0).length,
        0,
        'ROJO (K5): una operación que no es una arista de anidación calibró'
      )
    }
    {
      // P2 del juez (cierre-2 · D5): un 503 de PROFUNDIDAD en una lectura re-calibra la siguiente escritura de anidación —el
      // operador BAJÓ el límite del servidor sin reiniciar la app—, como mucho una vez por GROUP_DEPTH_RECALIBRATION_MIN_INTERVAL_MS.
      let clock = 1_000
      const opts = { positive: 24, negative: 22, monotonic: () => clock, readTooComplex: false }
      const live = fga(cfg(), opts)
      const someone = { type: 'user', uuid: uuidv7() }
      const doc = { type: 'document', id: 'p2-doc' }
      const calibrations = () => live.checks.filter((c) => (c.contextualTuples?.length ?? 0) > 0).length
      assert.equal(await live.driver.groupDepthLimit(), 22)
      const first = calibrations()
      // El servidor baja su límite: el no-miembro con membresía ya solo resuelve 20; una lectura del tenant da 503.
      opts.negative = 20
      opts.readTooComplex = true
      expectError(assert, await catching(() => live.driver.check(someone, 'viewer', doc, P)), 503, 'E_AUTHZ_RESOLUTION_LIMIT', 'la lectura de una cadena que ya no cabe')
      opts.readTooComplex = false
      assert.equal(await live.driver.groupDepthLimit(), 20, 'ROJO (P2): tras el 503 de profundidad el techo memorizado siguió en 22 (sin re-calibrar)')
      const second = calibrations()
      assert.isAbove(second, first)
      // Otro 503 DENTRO de la cota: no re-calibra (una forma que da 503 en cada lectura no dispara una calibración por lectura).
      opts.negative = 18
      opts.readTooComplex = true
      await catching(() => live.driver.check(someone, 'viewer', doc, P))
      opts.readTooComplex = false
      assert.equal(await live.driver.groupDepthLimit(), 20, 'ROJO (P2): la re-calibración no está acotada en frecuencia')
      assert.equal(calibrations(), second, 'dentro de la cota: cero Check de calibración')
      // Pasada la cota, el siguiente 503 sí re-calibra.
      clock += GROUP_DEPTH_RECALIBRATION_MIN_INTERVAL_MS
      opts.readTooComplex = true
      await catching(() => live.driver.check(someone, 'viewer', doc, P))
      opts.readTooComplex = false
      assert.equal(await live.driver.groupDepthLimit(), 18)
      // Un 503 de la PROPIA calibración no invalida nada (no hay techo memorizado que olvidar): lo cubre el backoff.
    }
    {
      const high = fga(cfg({ maxGroupDepth: 25 }), { positive: 24, negative: 22 })
      const highError = await catching(() => high.driver.groupDepthLimit())
      expectError(assert, highError, 500, 'E_AUTHZ_CONFIG', 'openfga · maxGroupDepth > calibrado')
      // Cierre-2 · D5: la letra ya no dice «reinicia» a secas — subir el límite del servidor pide reinicio, bajarlo no.
      assert.include(highError.message, 'SUBIR el límite no lo detecta nada')
      assert.include(highError.message, 'BAJARLO sí, sin reinicio')
      assert.equal(await fga(cfg({ maxGroupDepth: 20 }), { positive: 24, negative: 22 }).driver.groupDepthLimit(), 20, 'la config BAJA el techo')
      // G: IGUAL al calibrado es la config documentada («22»): entra.
      assert.equal(await catching(() => fga(cfg({ maxGroupDepth: 22 }), { positive: 24, negative: 22 }).driver.groupDepthLimit()), null, 'ROJO (G): maxGroupDepth IGUAL al calibrado dio 500')
      assert.equal(await fga(cfg({ maxGroupDepth: 22 }), { positive: 24, negative: 22 }).driver.groupDepthLimit(), 22)
      const off = fga(cfg({ maxGroupDepth: false }), { positive: 24, negative: 22 })
      assert.isNull(await off.driver.groupDepthLimit())
      assert.notInclude(off.calls, 'check', 'apagado: ni calibra')
    }
    // El gate de `relate` en openfga, por sus DOS caras y con la vigencia del store.
    const pk = `${P.type}|${P.uuid}`
    const g = (name: string) => `group:${pk}|${name}`
    const chainOf = (n: number, from = 0): StoredFga[] =>
      Array.from({ length: n }, (_, i) => ({ user: `${g(`g${from + i}`)}#member`, relation: 'member', object: g(`g${from + i + 1}`) }))
    const nestFga = (driver: OpenFgaRelationsDriver, child: string, parent: string, options?: any) =>
      driver.relate({ object: { type: 'group', id: child }, relation: 'member' }, 'member', { type: 'group', id: parent }, P, options)
    const expiry = (at: Date) => ({ name: 'not_expired', context: { valid_until: at.toISOString() } })
    {
      // Una cadena de 22 en el store; la arista 23 por ARRIBA ⇒ 422 y CERO escrituras.
      const { driver, calls } = fga(cfg(), { positive: 24, negative: 22, stored: chainOf(22) })
      const caught = await catching(() => nestFga(driver, 'g22', 'g23'))
      expectError(assert, caught, 422, 'E_AUTHZ_GROUP_DEPTH_LIMIT', 'ROJO: openfga escribió la arista 23')
      assert.notInclude(calls, 'write', 'openfga · 422 con cero escrituras')
      assert.notInclude(caught.message, 'OPENFGA_RESOLVE_NODE_LIMIT', 'el message es del tenant: el mando del servidor va en details')
      assert.include(caught.details.server, 'OPENFGA_RESOLVE_NODE_LIMIT')
      assert.notInclude(JSON.stringify(caught), 'OPENFGA_RESOLVE_NODE_LIMIT', 'details NO enumerable')
      // 🔴 A del tester: la arista POR DEBAJO de la cadena (x ⊂ g0) solo la ve la lectura hacia ARRIBA.
      expectError(assert, await catching(() => nestFga(driver, 'x', 'g0')), 422, 'E_AUTHZ_GROUP_DEPTH_LIMIT', 'ROJO (A): openfga no miró hacia ARRIBA (x ⊂ g0 sobre una cadena de 22)')
      // Y el ciclo, que necesita las dos direcciones.
      const cycle = await catching(() => nestFga(driver, 'g22', 'g0'))
      expectError(assert, cycle, 422, 'E_AUTHZ_GROUP_DEPTH_LIMIT', 'openfga · el ciclo')
      assert.equal(cycle.details.reason, 'cycle')
      assert.notInclude(calls, 'write')
      // 🟡 2 del auditor: la marca del plan no se falsifica con un Proxy, ni se reutiliza para OTRA arista.
      const forged = new Proxy({}, { get: (t: any, k) => (typeof k === 'symbol' ? true : t[k]) })
      expectError(assert, await catching(() => nestFga(driver, 'g22', 'g23', forged)), 422, 'E_AUTHZ_GROUP_DEPTH_LIMIT', 'ROJO: un Proxy forjó la marca del plan')
      const other = plannedRelateOptions({ expiresAt: null }, { subject: { object: { type: 'group', id: 'zz' }, relation: 'member' }, relation: 'member', object: { type: 'group', id: 'yy' }, partition: P })
      expectError(assert, await catching(() => nestFga(driver, 'g22', 'g23', other)), 422, 'E_AUTHZ_GROUP_DEPTH_LIMIT', 'ROJO: la marca de OTRA arista abrió el gate')
      assert.notInclude(calls, 'write')
      const genuine = plannedRelateOptions({ expiresAt: null }, { subject: { object: { type: 'group', id: 'g22' }, relation: 'member' }, relation: 'member', object: { type: 'group', id: 'g23' }, partition: P })
      assert.isTrue(Object.isFrozen(genuine))
      assert.isNull(await catching(() => nestFga(driver, 'g22', 'g23', genuine)), 'la marca de ESTA arista (solo el reconcile la crea) no consulta el gate')
      assert.isNull(await catching(() => nestFga(driver, 'q30', 'q31')), 'una arista suelta entra')
      assert.include(calls, 'write')
    }
    {
      // O2 (invariante 6): un `relate` IDÉNTICO de una arista preexistente en una cadena que YA excede (sembrada antes
      // de alpha.4 o con el gate apagado) sigue siendo un no-op — sin 422 y sin escribir.
      const { driver, calls } = fga(cfg(), { positive: 24, negative: 22, stored: chainOf(23) })
      assert.isNull(await catching(() => nestFga(driver, 'g22', 'g23')), 'ROJO (O2): el no-op idéntico pasó por el gate')
      assert.notInclude(calls, 'write')
    }
    {
      // B: RENOVAR (otra caducidad) una arista de una cadena de 23 ⇒ 422 sin escribir (también en openfga).
      const at = new Date(Date.now() + 3_600_000)
      const stored = chainOf(23)
      stored[22] = { ...stored[22], condition: expiry(at) }
      const { driver, calls } = fga(cfg(), { positive: 24, negative: 22, stored })
      expectError(assert, await catching(() => nestFga(driver, 'g22', 'g23', { expiresAt: new Date(at.getTime() + 60_000) })), 422, 'E_AUTHZ_GROUP_DEPTH_LIMIT', 'ROJO (B): la RENOVACIÓN quedó exenta en openfga')
      assert.notInclude(calls, 'write')
      assert.notInclude(calls, 'deleteTuples')
    }
    {
      // D: una arista VENCIDA en el camino no conecta ⇒ la 22.ª entra.
      const stored = chainOf(22)
      stored[0] = { ...stored[0], condition: expiry(new Date(Date.now() - 60_000)) }
      const { driver, calls } = fga(cfg(), { positive: 24, negative: 22, stored })
      assert.isNull(await catching(() => nestFga(driver, 'g22', 'g23')), 'ROJO (D): contó una arista vencida')
      assert.include(calls, 'write')
    }
    {
      // E: una arista con condición ILEGIBLE (foreign) CUENTA (más 422, nunca menos).
      const stored = chainOf(22)
      stored[0] = { ...stored[0], condition: { name: 'otra_condicion', context: {} } }
      const { driver, calls } = fga(cfg(), { positive: 24, negative: 22, stored })
      expectError(assert, await catching(() => nestFga(driver, 'g22', 'g23')), 422, 'E_AUTHZ_GROUP_DEPTH_LIMIT', 'ROJO (E): una condición ilegible no contó')
      assert.notInclude(calls, 'write')
    }
    {
      // Panel (cierre de R1): el deadline del presupuesto empieza DESPUÉS de la calibración. Un servidor lento al calibrar
      // (cada Check «tarda» un deadline entero en el reloj monotónico) no convierte el primer relate en frío en un 422.
      const realNow = performance.now.bind(performance)
      let skew = 0
      Object.defineProperty(performance, 'now', { value: () => realNow() + skew, configurable: true, writable: true })
      try {
        const cold = fga(cfg(), { positive: 24, negative: 22, stored: chainOf(3), onCheck: () => void (skew += GROUP_DEPTH_DEADLINE_MS) })
        assert.isNull(await catching(() => nestFga(cold.driver, 'g3', 'g4')), 'ROJO: la calibración lenta consumió el deadline del gate (422 espurio en frío)')
        assert.include(cold.calls, 'write')
      } finally {
        delete (performance as any).now
      }
      assert.strictEqual(performance.now, Object.getPrototypeOf(performance).now, 'performance.now restaurado')
    }
    {
      // Cierre-3 · R-2 (decisión firmada (3): lo transitorio es 503): un servidor LENTO —cada `Read` del gate «tarda» medio
      // deadline en el reloj monótono— agota el deadline del presupuesto. Eso no dice nada de los datos (descargado, el mismo
      // grafo entra): 503 E_AUTHZ_BACKEND_UNAVAILABLE transitorio, NO la subclase timeout, sin `Write` y SIN evento
      // `indeterminate` en el manager (la escritura no ocurrió). Nunca el 422 «aplana la anidación».
      const realNow = performance.now.bind(performance)
      let skew = 0
      Object.defineProperty(performance, 'now', { value: () => realNow() + skew, configurable: true, writable: true })
      try {
        const slow = fga(cfg(), { positive: 24, negative: 22, stored: chainOf(6), onRead: () => void (skew += GROUP_DEPTH_DEADLINE_MS / 2) })
        const events: any[] = []
        const manager = new RelationsManager(slow.driver, cfg(), { onRelationWrite: (e: any) => void events.push(e) })
        const caught = await catching(() =>
          manager.relate({ object: { type: 'group', id: 'g6' }, relation: 'member' }, 'member', { type: 'group', id: 'g7' }, P)
        )
        expectError(assert, caught, 503, 'E_AUTHZ_BACKEND_UNAVAILABLE', 'ROJO (R-2): el deadline del presupuesto (servidor lento) no es un 503 transitorio')
        assert.notInstanceOf(caught, AuthorizationBackendTimeoutError, 'ROJO (R-2): la subclase timeout haría la escritura indeterminada')
        assert.include(caught.message, 'reintenta')
        assert.notInclude(caught.message, 'Aplana')
        assert.notInclude(slow.calls, 'write')
        assert.deepEqual(events, [], 'ROJO (R-2): una escritura que no ocurrió notificó un evento')
        // El mismo grafo, con el servidor descargado, entra: el 503 era la latencia, no los datos.
        skew = 0
        const fast = fga(cfg(), { positive: 24, negative: 22, stored: chainOf(6) })
        assert.isNull(await catching(() => nestFga(fast.driver, 'g6', 'g7')), 'el mismo grafo, con el servidor descargado, entra')
      } finally {
        delete (performance as any).now
      }
      assert.strictEqual(performance.now, Object.getPrototypeOf(performance).now, 'performance.now restaurado')
    }
    {
      // Panel (cierre de R1): la entrada de NA_MATRIX de `groupDepthLimit` es ESTRECHA — `f05`/`partition` en `na` en
      // cualquier OTRA lectura de database/openfga sigue siendo una violación del manifiesto.
      for (const layer of ['database', 'openfga'] as const) {
        const row = GUARD_MANIFEST.find((r) => r.layer === layer && r.operation === 'check')!
        for (const column of ['f05', 'partition'] as const) {
          const forged = { ...row, cells: { ...row.cells, [column]: { na: 'signature' } } } as GuardRow
          assert.isTrue(
            manifestViolations([forged]).some((v) => v.startsWith(`${layer}.check.${column}`)),
            `ROJO: NA_MATRIX admite ${column} na en ${layer}.check (la entrada de groupDepthLimit no es estrecha)`
          )
        }
      }
      // Cierre-2 de R1 · D2 (a), doctrina firmada: «f05 nunca na salvo operaciones SIN tupla, por nombre: withClock y
      // groupDepthLimit». Caso META: una fila NUEVA con f05 na fuera de esas dos es roja AUNQUE la matriz tenga una regla
      // que la admita (el candado es por NOMBRE y va aparte de NA_MATRIX).
      assert.deepEqual([...F05_NA_OPERATIONS], ['withClock', 'groupDepthLimit'], 'la lista firmada: dos nombres, ni uno más')
      const fooRow = row('database', 'fooLimit', 'read', { ...GUARD_MANIFEST.find((r) => r.layer === 'database' && r.operation === 'groupDepthLimit')!.cells })
      const widened: NaRule[] = [...NA_MATRIX, { reason: 'signature', layers: ['database'], kinds: ['read'], columns: ['f05', 'partition'], operations: ['fooLimit'] }]
      const meta = manifestViolations([fooRow], widened)
      assert.isTrue(
        meta.some((v) => v.startsWith('database.fooLimit.f05') && v.includes('f05 NUNCA admite na salvo')),
        `ROJO (D2): una fila nueva con f05 na fuera de withClock/groupDepthLimit pasó con una regla de matriz que la admite: ${JSON.stringify(meta)}`
      )
      assert.isFalse(meta.some((v) => v.startsWith('database.fooLimit.partition')), 'la partition sí la admite la regla nueva: el candado es SOLO de f05')
      assert.deepEqual(
        GUARD_MANIFEST.filter((r) => 'na' in r.cells.f05).map((r) => r.operation).filter((op) => !(F05_NA_OPERATIONS as readonly string[]).includes(op)),
        [],
        'el manifiesto vivo: f05 na solo en las dos operaciones nombradas'
      )
      // Aridad cero: la juzga el compilador (`GROUP_DEPTH_LIMIT_ZERO_ARITY`); en ejecución, el `length` de los dos drivers.
      assert.deepEqual(GROUP_DEPTH_LIMIT_ZERO_ARITY, { port: true, database: true, openfga: true })
      assert.deepEqual([DatabaseRelationsDriver.prototype.groupDepthLimit.length, OpenFgaRelationsDriver.prototype.groupDepthLimit.length], [0, 0])
    }
    {
      // 🟠 1 del auditor: el PRESUPUESTO del gate (el Read hacia abajo trae también los holders: no se puede filtrar).
      const many: StoredFga[] = Array.from({ length: GROUP_DEPTH_MAX_TUPLES + 1 }, (_, i) => ({ user: `user:u${i}`, relation: 'member', object: g('big') }))
      const tuples = fga(cfg(), { positive: 24, negative: 22, stored: many })
      const byTuples = await catching(() => nestFga(tuples.driver, 'big', 'top'))
      expectError(assert, byTuples, 422, 'E_AUTHZ_GROUP_DEPTH_LIMIT', 'ROJO: el gate leyó más tuplas que el presupuesto')
      assert.deepEqual([byTuples.details.reason, byTuples.details.budget], ['too-many-groups', 'tuples'])
      assert.notInclude(tuples.calls, 'write')
      const wide: StoredFga[] = Array.from({ length: GROUP_DEPTH_MAX_READS + 1 }, (_, i) => ({ user: `${g(`w${i}`)}#member`, relation: 'member', object: g('wide') }))
      const reads = fga(cfg(), { positive: 24, negative: 22, stored: wide })
      const byReads = await catching(() => nestFga(reads.driver, 'wide', 'top'))
      expectError(assert, byReads, 422, 'E_AUTHZ_GROUP_DEPTH_LIMIT', 'ROJO: el gate hizo más requests que el presupuesto')
      assert.equal(byReads.details.budget, 'reads')
      assert.isAtMost(reads.calls.filter((c) => c === 'read').length, GROUP_DEPTH_MAX_READS + 1, 'el corte llega ANTES de la request de más (más la del relate)')
      assert.notInclude(reads.calls, 'write')
    }

    // (7) database (opt-in) · techo 3; el grafo se lee por el MISMO cliente que escribe (T-6) y la renovación no se exime.
    const dbCfg = cfg({ maxGroupDepth: 3, database: { enforceGroupDepth: true } })
    const plain = new DatabaseRelationsDriver(cfg(), { timeoutMs: 1500 })
    const gated = new DatabaseRelationsDriver(dbCfg, { timeoutMs: 1500 })
    assert.isNull(await plain.groupDepthLimit(), 'database SIN límite por defecto')
    assert.equal(await gated.groupDepthLimit(), 3)
    // Q del tester (movido aquí desde el spec de motor para que el corredor lo vea): el NÚMERO solo no activa el gate.
    assert.isNull(await new DatabaseRelationsDriver(cfg({ maxGroupDepth: 3 })).groupDepthLimit(), 'ROJO (Q): maxGroupDepth sin el opt-in activó el gate de database')
    // 🟡 4 del auditor: los drivers RE-VALIDAN (una config extendida con spread no pasó por defineRelationsConfig).
    for (const [label, build] of [
      ['database · NaN', () => new DatabaseRelationsDriver({ ...dbCfg, maxGroupDepth: Number.NaN } as any)],
      ['database · enforce sin número', () => new DatabaseRelationsDriver({ ...cfg(), enforceGroupDepth: true } as any)],
      ['database · enforce no booleano', () => new DatabaseRelationsDriver({ ...cfg({ maxGroupDepth: 3 }), enforceGroupDepth: 'yes' } as any)],
      ['openfga · NaN', () => fga({ ...cfg(), maxGroupDepth: Number.NaN }, { positive: 24, negative: 22 })],
      ['openfga · 0', () => fga({ ...cfg(), maxGroupDepth: 0 }, { positive: 24, negative: 22 })],
    ] as const) {
      const error = (() => {
        try {
          build()
          return null
        } catch (e) {
          return e
        }
      })()
      expectError(assert, error, 500, 'E_AUTHZ_CONFIG', `ROJO: el driver no re-validó maxGroupDepth (${label})`)
    }
    const part: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const grp = (id: string) => ({ object: { type: 'group', id }, relation: 'member' })
    const nest = (driver: DatabaseRelationsDriver, child: string, parent: string, options?: any) =>
      driver.relate(grp(child), 'member', { type: 'group', id: parent }, part, options)
    const rows = async () => Number(((await db.from('authz_relations').where('partition_key', `${part.type}|${part.uuid}`).count('* as n')) as any)[0].n)
    for (const [c, p] of [['a', 'b'], ['b', 'c'], ['c', 'd']]) await nest(gated, c, p)
    const n0 = await rows()
    expectError(assert, await catching(() => nest(gated, 'd', 'e')), 422, 'E_AUTHZ_GROUP_DEPTH_LIMIT', 'database · la arista 4 por arriba')
    expectError(assert, await catching(() => nest(gated, 'x', 'a')), 422, 'E_AUTHZ_GROUP_DEPTH_LIMIT', 'database · la arista 4 por abajo')
    expectError(assert, await catching(() => nest(gated, 'd', 'a')), 422, 'E_AUTHZ_GROUP_DEPTH_LIMIT', 'database · el ciclo')
    assert.equal(await rows(), n0, 'database · 422 con cero escrituras')
    // Cierre-2 · D3 (b), P4/P5 del tester en `database` (el gemelo de openfga, arriba): la marca del plan no se falsifica
    // con un Proxy que responde a todo símbolo, ni se reutiliza la de OTRA arista; la genuina de ESTA arista sí entra.
    const forgedDb = new Proxy({}, { get: (t: any, k) => (typeof k === 'symbol' ? true : t[k]) })
    expectError(assert, await catching(() => nest(gated, 'd', 'e', forgedDb)), 422, 'E_AUTHZ_GROUP_DEPTH_LIMIT', 'ROJO (P4): un Proxy forjó la marca del plan en database')
    const otherDb = plannedRelateOptions({}, { subject: grp('zz'), relation: 'member', object: { type: 'group', id: 'yy' }, partition: part })
    expectError(assert, await catching(() => nest(gated, 'd', 'e', otherDb)), 422, 'E_AUTHZ_GROUP_DEPTH_LIMIT', 'ROJO (P5): la marca de OTRA arista abrió el gate de database')
    const otherPartition = plannedRelateOptions({}, { subject: grp('d'), relation: 'member', object: { type: 'group', id: 'e' }, partition: { type: 'unit', uuid: uuidv7() } })
    expectError(assert, await catching(() => nest(gated, 'd', 'e', otherPartition)), 422, 'E_AUTHZ_GROUP_DEPTH_LIMIT', 'ROJO (P5): la marca de la MISMA arista en otra partición abrió el gate')
    assert.equal(await rows(), n0, 'database · marcas falsas: cero escrituras')
    // P7: congelada — cambiarle la caducidad no surte efecto (lanza en modo estricto del módulo).
    const genuineDb = plannedRelateOptions({ expiresAt: null }, { subject: grp('pz0'), relation: 'member', object: { type: 'group', id: 'pz1' }, partition: part })
    assert.throws(() => {
      ;(genuineDb as any).expiresAt = new Date(0)
    }, TypeError)
    assert.isNull((genuineDb as any).expiresAt)
    // Vencida no cuenta: h0⊂h1 vencida, h1⊂h2⊂h3 vivas ⇒ h3⊂h4 entra (3 saltos).
    await nest(gated, 'h0', 'h1', { expiresAt: new Date(Date.now() - 60_000) })
    for (const [c, p] of [['h1', 'h2'], ['h2', 'h3'], ['h3', 'h4']]) await nest(gated, c, p)
    // Renovación: f0⊂f1⊂f2⊂f3⊂f4 sembrada SIN gate; renovar f3⊂f4 (otra caducidad) con el gate ⇒ 422; unrelate nunca se bloquea.
    for (const [c, p] of [['f0', 'f1'], ['f1', 'f2'], ['f2', 'f3'], ['f3', 'f4']]) await nest(plain, c, p)
    // O (invariante 6): el `relate` IDÉNTICO de una arista preexistente en una cadena que YA excede es un no-op.
    const nf = await rows()
    assert.isNull(await catching(() => nest(gated, 'f3', 'f4')), 'ROJO (O): el no-op idéntico pasó por el gate de database')
    assert.equal(await rows(), nf)
    expectError(assert, await catching(() => nest(gated, 'f3', 'f4', { expiresAt: new Date(Date.now() + 3_600_000) })), 422, 'E_AUTHZ_GROUP_DEPTH_LIMIT', 'ROJO: la RENOVACIÓN de una arista que excede quedó exenta')
    assert.isNull(await catching(() => gated.unrelate(grp('f3'), 'member', { type: 'group', id: 'f4' }, part)), 'unrelate nunca pasa por el gate')
    // T-6: UNA transacción del llamante con t0⊂t1⊂t2⊂t3 y luego t3⊂t4 ⇒ la cuarta ve las tres (sin confirmar) ⇒ 422.
    const trx = await db.transaction()
    try {
      for (const [c, p] of [['t0', 't1'], ['t1', 't2'], ['t2', 't3']]) await nest(gated, c, p, { transaction: trx })
      expectError(assert, await catching(() => nest(gated, 't3', 't4', { transaction: trx })), 422, 'E_AUTHZ_GROUP_DEPTH_LIMIT', 'ROJO (T-6): el conteo no leyó por la transacción del llamante')
    } finally {
      await trx.rollback()
    }

    // (8) El PLAN del reconcile: la partición cuya cadena FINAL excede se NIEGA (cero escrituras), nunca se salta la arista.
    const relCfg = cfg()
    const from = makeRelationsDriver({ config: relCfg, capabilities: FULL })
    const toBase = makeRelationsDriver({ config: relCfg, capabilities: FULL })
    const to = Object.assign(Object.create(toBase), { groupDepthLimit: async () => 3 }) as RelationsDriver
    const deep: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const fine: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const extra: ScopeRef = { type: 'unit', uuid: uuidv7() }
    const user = { type: 'user', uuid: uuidv7() }
    const chain = async (driver: RelationsDriver, partition: ScopeRef, ids: string[]) => {
      for (let i = 0; i + 1 < ids.length; i++) await driver.relate(grp(ids[i]), 'member', { type: 'group', id: ids[i + 1] }, partition)
    }
    await chain(from, deep, ['c0', 'c1', 'c2', 'c3', 'c4'])
    await from.relate(user, 'member', { type: 'group', id: 'c0' }, deep)
    await chain(from, fine, ['k0', 'k1', 'k2'])
    await chain(from, extra, ['e0', 'e1', 'e2'])
    await chain(toBase, extra, ['e2', 'e3', 'e4'])
    const count = async (partition: ScopeRef) => (await toBase.enumerateRelations!(partition)).tuples.length
    for (const dryRun of [true, false]) {
      const report = await reconcileRelations({ from, to, partitions: [deep, fine, extra], dryRun, toConfig: relCfg })
      const refused = (report.partitionsRefused ?? []).map((r) => `${r.partition}:${r.causes.map((c) => c.reason).join(',')}`).sort()
      assert.deepEqual(
        refused,
        [`unit|${deep.uuid}:too-deep`, `unit|${extra.uuid}:too-deep`].sort(),
        `ROJO (${dryRun ? 'dry-run' : 'real'}): la partición con la cadena FINAL > techo no se negó (o se calculó solo sobre el ORIGEN)`
      )
      assert.lengthOf(report.tooDeep ?? [], 2)
    }
    assert.equal(await count(deep), 0, 'ROJO: escribió (o saltó la arista y escribió el resto) en la partición NEGADA')
    assert.equal(await count(fine), 2, 'la partición sana migra')
    assert.equal(await count(extra), 2, 'la negada queda COMO ESTABA')
    // Con --prune las sobras del destino se borran: la cadena final es la del origen (2) y migra.
    const pruned = await reconcileRelations({ from, to, partition: extra, prune: true, toConfig: relCfg })
    assert.deepEqual(pruned.partitionsRefused, [])
    // J: una cadena EXACTAMENTE en el techo (3 saltos, techo 3) migra.
    const exact: ScopeRef = { type: 'unit', uuid: uuidv7() }
    await chain(from, exact, ['x0', 'x1', 'x2', 'x3'])
    const exactReport = await reconcileRelations({ from, to, partition: exact, toConfig: relCfg })
    assert.deepEqual(exactReport.partitionsRefused, [], 'ROJO (J): el plan negó una cadena IGUAL al techo')
    assert.equal(exactReport.written, 3)
    // L: la cadena larga está SOLO en el destino (el origen no anida nada): sin --prune se queda ⇒ se niega.
    const destOnly: ScopeRef = { type: 'unit', uuid: uuidv7() }
    await from.relate(user, 'member', { type: 'group', id: 'd0' }, destOnly)
    await chain(toBase, destOnly, ['d0', 'd1', 'd2', 'd3', 'd4'])
    const destOnlyReport = await reconcileRelations({ from, to, partition: destOnly, toConfig: relCfg })
    assert.deepEqual(
      (destOnlyReport.partitionsRefused ?? []).map((r) => r.causes.map((c) => c.reason)),
      [['too-deep']],
      'ROJO (L): el plan solo preguntó el techo si el ORIGEN anidaba'
    )
    // 🟡 3 del auditor + K del tester: el RESIDUO del destino (nunca se borra, ni con --prune) sigue VIVO y cuenta —
    // invalid-identity (ids fuera de la gramática) e invalid-condition—. Origen r0⊂r1⊂r2 (2) + residuo ⇒ 4 > 3.
    const residual = async (extraTuples: (p: ScopeRef) => any[]) => {
      const partition: ScopeRef = { type: 'unit', uuid: uuidv7() }
      await chain(from, partition, ['r0', 'r1', 'r2'])
      const withResidue = Object.assign(Object.create(to), {
        enumerateRelations: async (p: ScopeRef, page?: any) => {
          const base = await toBase.enumerateRelations!(p, page)
          return { ...base, tuples: [...base.tuples, ...extraTuples(p)] }
        },
      }) as RelationsDriver
      return reconcileRelations({ from, to: withResidue, partition, prune: true, toConfig: relCfg })
    }
    const nesting = (p: ScopeRef, child: string, parent: string, more: Record<string, unknown> = {}) => ({
      subject: grp(child),
      relation: 'member',
      object: { type: 'group', id: parent },
      partition: p,
      expiresAt: null,
      kind: 'allow',
      ...more,
    })
    const byIdentity = await residual((p) => [nesting(p, 'r2', 'BAD1'), nesting(p, 'BAD1', 'BAD2')])
    assert.deepEqual(
      (byIdentity.partitionsRefused ?? []).map((r) => r.causes.map((c) => c.reason)),
      [['too-deep']],
      'ROJO (🟡 3): el residuo invalid-identity VIVO no contó en la cadena final'
    )
    const byCondition = await residual((p) => [
      nesting(p, 'r2', 'q1', { invalidCondition: 'foreign: otra_condicion' }),
      nesting(p, 'q1', 'q2', { invalidCondition: 'foreign: otra_condicion' }),
    ])
    assert.deepEqual(
      (byCondition.partitionsRefused ?? []).map((r) => r.causes.map((c) => c.reason)),
      [['too-deep']],
      'ROJO (K): el residuo invalid-condition bajo --prune no contó en la cadena final'
    )
    const byExpired = await residual((p) => [nesting(p, 'r2', 'BAD1', { expiresAt: new Date(Date.now() - 60_000) }), nesting(p, 'BAD1', 'BAD2', { expiresAt: new Date(Date.now() - 60_000) })])
    assert.deepEqual(byExpired.partitionsRefused, [], 'el residuo VENCIDO no conecta nada')
    // (9) Un ciclo PREEXISTENTE no niega la partición (OpenFGA lo evalúa) y la pasada lo MIGRA a un destino con gate: la
    // escritura lleva la marca del plan; sin ella el gate del driver rechazaría la arista que cierra el ciclo a mitad de
    // pasada (y saltarla quitaría los denies que transporta).
    const cyclic: ScopeRef = { type: 'unit', uuid: uuidv7() }
    await chain(from, cyclic, ['y0', 'y1', 'y0'])
    const cycleReport = await reconcileRelations({ from, to: gated, partition: cyclic, toConfig: dbCfg })
    assert.deepEqual(cycleReport.partitionsRefused, [], 'un ciclo preexistente no niega la partición')
    assert.equal(cycleReport.written, 2, 'ROJO: el gate del driver se volvió a consultar en la pasada (el ciclo no se migró entero)')
    // C del tester: lo MISMO con destino OPENFGA (la dirección real del cutover: database → openfga).
    const fgaCyclic: ScopeRef = { type: 'unit', uuid: uuidv7() }
    await chain(from, fgaCyclic, ['v0', 'v1', 'v0'])
    const fgaDest = fga(cfg(), { positive: 24, negative: 22 })
    const fgaCycleReport = await reconcileRelations({ from, to: fgaDest.driver, partition: fgaCyclic, toConfig: cfg() })
    assert.deepEqual(fgaCycleReport.partitionsRefused, [], 'openfga · un ciclo preexistente no niega la partición')
    assert.equal(fgaCycleReport.written, 2, 'ROJO (C): openfga volvió a consultar el gate en la pasada (el ciclo no se migró entero)')
    assert.lengthOf(fgaDest.stored.filter((t) => t.relation === 'member'), 2)
    // 🟡 2 del auditor: el MANAGER pasa al driver un objeto NUEVO con solo las claves conocidas (ni símbolos, ni extras).
    const seen: any[] = []
    const spyDriver = Object.assign(Object.create(gated), {
      relate: async (...args: any[]) => void seen.push(args[4]),
      unrelate: async (...args: any[]) => void seen.push(args[4]),
    }) as RelationsDriver
    const viaManager = new RelationsManager(spyDriver, dbCfg)
    const raw: any = { expiresAt: null, extra: 1, [Symbol('marca')]: true }
    await viaManager.relate(grp('m0'), 'member', { type: 'group', id: 'm1' }, part, raw)
    await viaManager.unrelate(grp('m0'), 'member', { type: 'group', id: 'm1' }, part, raw)
    for (const passed of seen) {
      assert.notStrictEqual(passed, raw, 'ROJO: el manager pasó al driver el objeto de opciones del llamante')
      assert.deepEqual(Object.keys(passed), ['expiresAt'])
      assert.lengthOf(Object.getOwnPropertySymbols(passed), 0)
    }
    // Cierre-2 · D3 (b): la lista de claves que cruzan es EXHAUSTIVA (la decide el compilador: `satisfies
    // Record<keyof RelationWriteOptions, true>` en manager.ts) y TODAS cruzan: las tres conocidas llegan al driver, sin extras.
    assert.deepEqual([...KNOWN_WRITE_OPTION_KEYS].sort(), ['actor', 'expiresAt', 'transaction'])
    seen.length = 0
    const actorRef = { type: 'user', uuid: uuidv7() }
    await viaManager.relate(grp('m0'), 'member', { type: 'group', id: 'm1' }, part, { transaction: undefined, actor: actorRef, expiresAt: null, extra: 2 } as any)
    assert.deepEqual(seen.map((o) => Object.keys(o).sort()), [['actor', 'expiresAt', 'transaction']], 'ROJO (D3): una clave conocida se perdió en el manager')
    assert.deepEqual(seen[0].actor, actorRef)
  }).timeout(TEST_TIMEOUT)
})

/**
 * **P3 · el diente de la precisión del invariante 6** (cierre-2 de R1 · D6 (a), decisión del dueño 2026-10-20, condición
 * de la firma; endurecido en el cierre-3 · R-1 del re-ataque): «con `{ transaction }` la escritura va por la trx del
 * LLAMANTE; la autoridad, nunca» admite UNA lectura más por la trx, el gate de profundidad de grupos de `database` (dato de
 * la escritura, como el «¿ya existe?»; no decide permisos). Sin diente, esa precisión sería el precedente para leer
 * AUTORIDAD por la trx (el freeze, el catálogo, `resolveChain`). Guardia de FUENTE, patrón de `clock.spec`/`purity`: en
 * cada `src/**\/database_*.ts`, en los métodos alcanzables con el cliente de la trx del llamante (los que llaman
 * `writer()`/`#writer()` y, transitivamente, los que reciben `trx`/`client` de ellos), CADA uso del cliente se clasifica:
 *  - **sentencia**: `trx.from(…)`/`trx.table(…)` sin `delete`/`insert`/`update` es una LECTURA de esa tabla; cualquier
 *    OTRO método del cliente (`rawQuery`, `raw`, `query`, `knexQuery`, …) es una lectura sin más (conservador: un SQL crudo
 *    por la trx tiene que estar en la lista). `trx.transaction(cb)` abre la interna; su callback vive en el mismo cuerpo;
 *  - **paso**: argumento de otro método de la clase (se sigue) o de un cierre `const f = (…) =>` del MISMO miembro;
 *  - **declaración**: parámetro tipado o el destructuring de `writer()` SIN renombrar.
 * Todo lo demás —pasarlo a una función de módulo o importada (`readFreezeVia(client)`), un alias (`const c = trx`), un
 * renombrado en el destructuring (`{ client: c }`), leer `options.transaction` fuera de `writer()`— es ROJO con su línea.
 * Y las lecturas se cuentan por SENTENCIA y con su tabla: una lectura de autoridad colada en un método que ya estaba en la
 * lista (`#upsert`) cambia el multiconjunto y es roja. El número es TEXTUAL (sentencias en el fuente, no ejecuciones: el
 * `findExisting` de `grant` corre como `find` y como `race`, y es UNA).
 * Límites declarados: un miembro de clase se reconoce por su cabecera con sangría de 2 espacios (un método declarado como
 * propiedad flecha cae dentro del miembro anterior); un cierre local que recibe el cliente se analiza como parte del
 * miembro, no como función aparte; y la clasificación es de regex sobre el fuente sin comentarios, no un AST.
 */
const CALLER_TRX_READS: Record<string, Record<string, { reads: string[]; why: string }>> = {
  'src/drivers/database_driver.ts': {
    deny: { reads: ["'authz_denies'"], why: '¿ya existe? del deny (deny.find / deny.race, una sentencia): parte de la escritura' },
    grant: { reads: ["'authz_assignments'"], why: '¿ya existe? de la asignación (grant.find / grant.race, una sentencia): parte de la escritura' },
  },
  'src/drivers/database_relations_driver.ts': {
    '#assertGroupNesting': {
      reads: ['RELATIONS_TABLE'],
      why: 'el gate de profundidad de grupos de R1 (D6 (a)): la ÚNICA lectura por la trx que no es parte de la escritura',
    },
    '#upsert': { reads: ['RELATIONS_TABLE'], why: '¿ya existe? de la tupla (relate/deny, renovación): parte de la escritura' },
  },
}

/** Comentarios fuera, conservando los saltos de línea (los nombres de método y las cadenas siguen en su sitio). */
function stripComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:'"`])\/\/[^\n]*/g, (m, p) => p + ' '.repeat(m.length - p.length))
}

/** Fin de la SENTENCIA que empieza en `from` (sube por los paréntesis que la envuelven: `whereScopeIn(client…).delete()`). */
function statementEnd(body: string, from: number): number {
  let depth = 0
  let min = 0
  for (let i = from; i < body.length; i++) {
    const ch = body[i]
    if (ch === '(' || ch === '[' || ch === '{') depth++
    else if (ch === ')' || ch === ']' || ch === '}') min = Math.min(min, --depth)
    else if (ch === '\n' && depth <= min && min <= 0) {
      const next = body.slice(i + 1).trimStart()[0]
      const prev = body.slice(0, i).trimEnd().slice(-1)
      if (!['.', ')', ',', ']'].includes(next) && !['(', ',', '.', '=', '>', '&', '|', '?', ':', '+', '['].includes(prev)) return i
    }
  }
  return body.length
}

/** Los argumentos de la llamada cuyo `(` está en `open`, con paréntesis equilibrados. */
function callArgs(body: string, open: number): string {
  let depth = 0
  for (let i = open; i < body.length; i++) {
    if (body[i] === '(') depth++
    else if (body[i] === ')' && --depth === 0) return body.slice(open + 1, i)
  }
  return body.slice(open + 1)
}

/**
 * Los usos del cliente de la trx del llamante en una clase de `database_*` (pura sobre el fuente): `reads` = por método,
 * el multiconjunto ordenado de sus SENTENCIAS de lectura (la tabla de `from`/`table`, o `<método>()` para cualquier otro
 * método del cliente); `unclassified` = cada uso que no es sentencia, paso ni declaración, con su línea.
 */
function callerTrxUses(source: string): { reads: Record<string, string[]>; unclassified: string[] } {
  const src = stripComments(source)
  const header = /^  (?:private |protected |public |static )*(?:async )?(#?[A-Za-z_]\w*)\s*(?:<[^>\n]*>)?\(/gm
  const members: Array<{ name: string; start: number; body: string }> = []
  for (let m = header.exec(src); m; m = header.exec(src)) members.push({ name: m[1], start: m.index, body: '' })
  members.forEach((x, i) => (x.body = src.slice(x.start, i + 1 < members.length ? members[i + 1].start : src.length)))
  const isWriter = (name: string) => /^#?writer$/.test(name)
  const reachable = new Set(members.filter((x) => /\b(?:this\.)?#?writer\(/.test(x.body) && !isWriter(x.name)).map((x) => x.name))
  for (let grew = true; grew; ) {
    grew = false
    for (const x of members) {
      if (!reachable.has(x.name)) continue
      for (const y of members) {
        if (reachable.has(y.name)) continue
        const call = new RegExp(`this\\.${y.name.replace('#', '\\#')}\\(`, 'g')
        for (let c = call.exec(x.body); c; c = call.exec(x.body)) {
          if (/\b(trx|client)\b/.test(callArgs(x.body, c.index + c[0].length - 1))) {
            reachable.add(y.name)
            grew = true
          }
        }
      }
    }
  }
  const reads: Record<string, string[]> = {}
  const unclassified: string[] = []
  // La trx del llamante entra SOLO por `writer()`: `options.transaction` fuera de él es una puerta lateral.
  for (const x of members) {
    if (!isWriter(x.name) && /\.transaction\b(?!\s*\()/.test(x.body)) unclassified.push(`${x.name}: .transaction fuera de writer()`)
  }
  for (const x of members) {
    if (!reachable.has(x.name)) continue
    const locals = new Set([...x.body.matchAll(/\bconst\s+([A-Za-z_]\w*)\s*=\s*(?:async\s*)?\(/g)].map((m) => m[1]))
    const use = /\b(trx|client)\b/g
    for (let u = use.exec(x.body); u; u = use.exec(x.body)) {
      const before = x.body.slice(0, u.index)
      const after = x.body.slice(u.index + u[0].length)
      const line = x.body.slice(before.lastIndexOf('\n') + 1, u.index + u[0].length + Math.max(0, after.indexOf('\n'))).trim()
      // Declaración: parámetro tipado (`(trx: any)`, `client: WriteClient`), parámetro de un cierre o el destructuring de
      // `writer()` SIN renombrar (`{ client: c }` no es declaración: es un alias).
      if (/^\s*:\s*[A-Za-z][\w.<>[\]| ]*\s*[,)=]/.test(after) && /[(,]\s*$/.test(before) && !/\{[^{}()]*$/.test(before)) continue
      if (/^\s*[,}]/.test(after) && /\{\s*(?:[A-Za-z_]\w*\s*,\s*)*$/.test(before) && /^[^\n]*\}\s*=\s*this\.#?writer\(/.test(after)) continue
      if (/(?:async\s*)?\(\s*$/.test(before) && /^\s*(?::\s*\w+\s*)?\)\s*=>/.test(after)) continue
      // Sentencia.
      const member = /^\s*\.\s*([A-Za-z_]\w*)\s*\(/.exec(after)
      if (member) {
        const method = member[1]
        if (method === 'transaction') continue
        const statement = x.body.slice(u.index, statementEnd(x.body, u.index))
        const isTable = method === 'from' || method === 'table'
        if (isTable && /\.(delete|insert|update|del)\(/.test(statement)) continue
        const what = isTable ? callArgs(x.body, u.index + u[0].length + member[0].length - 1).trim() : `${method}()`
        ;(reads[x.name] ??= []).push(what)
        continue
      }
      // Paso: a otro método de la clase (se sigue) o a un cierre local del mismo miembro.
      const callee = /(this\.#?[A-Za-z_]\w*|[A-Za-z_]\w*)\s*\(\s*(?:[^()]*,\s*)?$/.exec(before)
      if (callee && /^\s*[,)]/.test(after)) {
        const name = callee[1]
        if (name.startsWith('this.') && members.some((y) => `this.${y.name}` === name)) continue
        if (locals.has(name)) continue
        unclassified.push(`${x.name}: el cliente de la trx pasa a ${name}(…) — ${line}`)
        continue
      }
      unclassified.push(`${x.name}: uso no clasificado del cliente de la trx — ${line}`)
    }
  }
  for (const name of Object.keys(reads)) reads[name].sort()
  return { reads, unclassified }
}

test.group('GS · P · database.trx.reads (cierre-2 de R1 · P3; cierre-3 · R-1)', () => {
  const property = GUARD_PROPERTIES.find((p) => p.id === 'database.trx.reads')!
  test(property.title, ({ assert }) => {
    const root = fileURLToPath(new URL('../', import.meta.url))
    const files = (readdirSync(new URL('../src/', import.meta.url), { recursive: true }) as string[])
      .map((f) => `src/${String(f).split('\\').join('/')}`)
      .filter((f) => /(^|\/)database_[^/]*\.ts$/.test(f))
      .sort()
    assert.includeMembers(files, Object.keys(CALLER_TRX_READS), 'los ficheros de la lista existen')
    const expectedOf = (file: string) =>
      Object.fromEntries(Object.entries(CALLER_TRX_READS[file] ?? {}).map(([name, entry]) => [name, [...entry.reads].sort()]))
    for (const file of files) {
      const found = callerTrxUses(readFileSync(`${root}${file}`, 'utf8'))
      assert.deepEqual(
        found.unclassified,
        [],
        `ROJO (P3): ${file} saca el cliente de la transacción del LLAMANTE de lo que la guardia puede contar (función fuera de ` +
          'la clase, alias, renombrado u options.transaction fuera de writer()). Pásalo solo a métodos de la clase o a cierres del mismo método.'
      )
      assert.deepEqual(
        found.reads,
        expectedOf(file),
        `ROJO (P3): ${file} lee por la transacción del LLAMANTE fuera de la lista cerrada (sentencia a sentencia, con su tabla; ` +
          'o la lista nombra una que ya no existe). Por la trx va la escritura y su «¿ya existe?», más el gate de profundidad de ' +
          'grupos (precisión del invariante 6, R1); la AUTORIDAD (freeze, catálogo, resolveChain, F-05, assertWrite) va por la conexión del motor.'
      )
    }
    // El analizador no es vacío: cada inyección del re-ataque (R-1) y las del cierre-2 aparecen con su nombre.
    const relations = readFileSync(`${root}src/drivers/database_relations_driver.ts`, 'utf8')
    const anchor = '    const { client, external } = this.#writer(operation, options)\n    try {\n'
    assert.equal(relations.split(anchor).length, 2, 'el ancla del caso meta casa una vez')
    const inDelete = (line: string) => relations.replace(anchor, anchor.replace('    try {\n', `${line}\n    try {\n`))
    const base = callerTrxUses(relations)
    // (cierre-2) una lectura en `#deleteTuple`, un DELETE puro.
    assert.deepEqual(callerTrxUses(inDelete("    await client.from('authz_relations').where('uuid', 'x').select('uuid')")).reads['#deleteTuple'], ["'authz_relations'"])
    // (R-1 · 1) una lectura de AUTORIDAD por la trx DENTRO de `#upsert`, que ya estaba en la lista: cambia sus lecturas.
    const upsertAnchor = '      const current = existing[0]\n'
    assert.equal(relations.split(upsertAnchor).length, 2, 'el ancla de #upsert casa una vez')
    const freeze = callerTrxUses(relations.replace(upsertAnchor, `${upsertAnchor}      await trx.from('authz_catalog_version').where('id', 2).first()\n`))
    assert.deepEqual(freeze.reads['#upsert'], ["'authz_catalog_version'", 'RELATIONS_TABLE'], 'ROJO (R-1): una lectura más en #upsert no se cuenta')
    assert.notDeepEqual(freeze.reads, base.reads)
    // (R-1 · 2) SQL crudo por la trx en un método NO listado: `rawQuery` y `raw` son lecturas.
    assert.deepEqual(callerTrxUses(inDelete("    await client.rawQuery('select * from authz_catalog_version where id = 2')")).reads['#deleteTuple'], ['rawQuery()'])
    assert.deepEqual(callerTrxUses(inDelete("    await client.raw('select 1')")).reads['#deleteTuple'], ['raw()'])
    // (R-1 · 3) el cliente pasado a una función de MÓDULO (también dentro de `#sql`): rojo con su nombre.
    for (const line of ['    await readFreezeVia(client)', '    await this.#sql(operation, () => readFreezeVia(client))']) {
      const found = callerTrxUses(`${inDelete(line)}\nasync function readFreezeVia(c: any) {\n  return c.from('authz_catalog_version').where('id', 2).first()\n}\n`)
      assert.lengthOf(found.unclassified, 1, line)
      assert.include(found.unclassified[0], 'readFreezeVia(…)')
    }
    // El límite que el cierre-2 declaraba, cerrado: un alias y un renombrado en el destructuring.
    assert.include(callerTrxUses(inDelete('    const c = client')).unclassified[0], 'const c = client')
    const renamed = relations.replace(anchor, '    const { external, client: c } = this.#writer(operation, options)\n    try {\n')
    assert.include(callerTrxUses(renamed).unclassified[0], 'client: c')
    // Y la trx no entra por otra puerta que `writer()`.
    assert.include(callerTrxUses(inDelete('    const t = options?.transaction')).unclassified[0], '.transaction fuera de writer()')
    // Uno que NO recibe la trx del llamante (su propia `db.transaction`) no cuenta: `purgeRole` lee por su trx interna.
    assert.notProperty(callerTrxUses(readFileSync(`${root}src/drivers/database_driver.ts`, 'utf8')).reads, 'purgeRole')
  })
})
