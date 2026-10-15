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
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { types as utilTypes } from 'node:util'
import { v7 as uuidv7 } from 'uuid'
import { Container } from '@adonisjs/fold'
import db from '@adonisjs/lucid/services/db'
import AuthzProvider from '../providers/authz_provider.js'
import { RelationsManager } from '../src/relations/manager.js'
import type { RelationsManagerOptions } from '../src/relations/manager.js'
import { DatabaseRelationsDriver } from '../src/drivers/database_relations_driver.js'
import { OpenFgaRelationsDriver } from '../src/drivers/openfga_relations_driver.js'
import { makeRelationsDriver, contractRelationsConfig } from '../src/testing/relations_contract.js'
import { AuthorizationManager } from '../src/manager.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { buildRelationsManager } from '../providers/authz_provider.js'
import { AuthorizationBackendError, AuthorizationBackendTimeoutError, isPartialWrite, markPartialWrite } from '../src/errors.js'
import { countQueries } from './helpers/spies.js'
import type { RelationsDriver, RelationsDriverCapabilities, ScopeRef, SubjectRef } from '../src/types.js'
import {
  GUARD_MANIFEST,
  GUARD_COLUMNS,
  PORT_OPERATIONS,
  PORT_WRITES,
  PORT_READS,
  PLATFORM_OPERATIONS,
  VIEW_OPERATIONS,
  NA_MATRIX,
  NON_SURFACE_CLASSES,
  NON_SURFACE_FUNCTIONS,
  SIGNED_EXEMPTIONS,
  NA_REASONS,
  DASHLESS_PARTITION,
  row,
  cellTitle,
  cellId,
} from './fixtures/guard_manifest.js'
import type {
  ExemptionExtractEntry,
  GuardCell,
  GuardColumn,
  GuardLayer,
  GuardMutant,
  GuardRow,
  SignedExemption,
} from './fixtures/guard_manifest.js'

const TYPE_UNKNOWN = 'E_AUTHZ_RELATION_TYPE_UNKNOWN'
const REL_UNKNOWN = 'E_AUTHZ_RELATION_UNKNOWN'
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
}

function rows(layer: GuardLayer): GuardRow[] {
  return GUARD_MANIFEST.filter((r) => r.layer === layer)
}

/* ── Entradas por operación y variante ──────────────────────────────────── */

type Variant = 'valid' | 'type' | 'relation' | 'undefined' | 'userset' | 'badPartition' | 'dashless'

const U: SubjectRef = { type: 'user', uuid: uuidv7() }
const P: ScopeRef = { type: 'unit', uuid: uuidv7() }
/** Una segunda partición VÁLIDA: en `*Many` va en la posición 0 para que la mala NUNCA sea `[0]` (cierre ⚪ 8). */
const P2: ScopeRef = { type: 'unit', uuid: uuidv7() }
/** Gramática rota (`#` y mayúsculas): lo que `assertScope` corta hoy. */
const BAD: ScopeRef = { type: 'unit', uuid: 'A#B' }
/** D4: uuid canónico escrito SIN guiones (32 hex). Hoy entra; lote A ⇒ 422. */
const DASHLESS: ScopeRef = { type: 'unit', uuid: uuidv7().replace(/-/g, '') }
const DOC = { type: 'document', id: uuidv7() }
const GROUP = { type: 'group', id: uuidv7() }
const BINDING = { type: 'role_binding', id: uuidv7() }

const subj = (v: Variant) => (v === 'userset' ? { object: BINDING, relation: 'assignee' } : U)
const rel = (v: Variant) => (v === 'relation' || v === 'type' ? 'assignee' : v === 'undefined' ? (undefined as any) : 'viewer')
const obj = (v: Variant) => (v === 'type' ? BINDING : DOC)
const objType = (v: Variant) => (v === 'type' ? 'role_binding' : 'document')
const part = (v: Variant) => (v === 'badPartition' ? BAD : v === 'dashless' ? DASHLESS : P)

/** Cómo se invoca cada operación con una variante de entrada. `options` solo lo reciben las escrituras. */
const INVOKE: Record<string, (t: any, v: Variant, options?: any) => Promise<unknown>> = {
  relate: (t, v, o) => t.relate(subj(v), rel(v), obj(v), part(v), o),
  unrelate: (t, v, o) => t.unrelate(subj(v), rel(v), obj(v), part(v), o),
  check: (t, v) => t.check(subj(v), rel(v), obj(v), part(v)),
  listObjects: (t, v) => t.listObjects(subj(v), rel(v), objType(v), part(v)),
  listSubjects: (t, v) => t.listSubjects(rel(v), obj(v), part(v)),
  membersOf: (t, v) =>
    v === 'type' || v === 'relation' || v === 'undefined'
      ? t.membersOf(obj(v), rel(v), part(v))
      : t.membersOf(GROUP, 'member', part(v)),
  purgeObject: (t, v, o) => t.purgeObject(obj(v), part(v), o),
  purgeSubject: (t, v, o) =>
    t.purgeSubject(
      v === 'userset' ? { object: BINDING, relation: 'role' } : v === 'undefined' ? { object: DOC, relation: undefined } : U,
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
  relate: [['type', TYPE_UNKNOWN], ['relation', REL_UNKNOWN], ['undefined', REL_UNKNOWN], ['userset', TYPE_UNKNOWN]],
  unrelate: [['type', TYPE_UNKNOWN], ['relation', REL_UNKNOWN], ['undefined', REL_UNKNOWN], ['userset', TYPE_UNKNOWN]],
  check: [['type', TYPE_UNKNOWN], ['relation', REL_UNKNOWN], ['undefined', REL_UNKNOWN], ['userset', TYPE_UNKNOWN]],
  listObjects: [['type', TYPE_UNKNOWN], ['relation', REL_UNKNOWN], ['undefined', REL_UNKNOWN], ['userset', TYPE_UNKNOWN]],
  listSubjects: [['type', TYPE_UNKNOWN], ['relation', REL_UNKNOWN], ['undefined', REL_UNKNOWN]],
  membersOf: [['type', TYPE_UNKNOWN], ['relation', REL_UNKNOWN], ['undefined', REL_UNKNOWN]],
  purgeObject: [['type', TYPE_UNKNOWN]],
  purgeSubject: [['userset', TYPE_UNKNOWN], ['undefined', REL_UNKNOWN]],
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
    if (column === 'partition') {
      const spy = spiedDouble()
      const { manager, events } = await managerOver(build, spy)
      const bad = await catching(() => invoke(manager, 'badPartition'))
      expectError(assert, bad, 422, 'E_AUTHZ_INVALID_IDENTITY', `${label} · partición con gramática rota`)
      assert.equal(spy.calls(), 0, `${label} · partición rota: CERO llamadas al driver`)
      assert.lengthOf(events, 0, `${label} · partición rota: CERO eventos`)
      // D4: la ortografía SIN guiones. Hoy ENTRA tal cual (el manager no canoniza particiones); lote A ⇒ 422.
      const dashless = await catching(() => invoke(manager, 'dashless'))
      if (DASHLESS_PARTITION === 'accepted') {
        assert.isNull(dashless, `${label} · uuid sin guiones: hoy se ACEPTA (${dashless?.message})`)
        assert.isAtLeast(spy.calls(), 1, `${label} · uuid sin guiones: llegó al driver`)
        if (r.kind === 'write') {
          assert.lengthOf(events, 1)
          assert.equal(events[0].partition.uuid, DASHLESS.uuid, 'el evento lleva la partición TAL COMO la pasó el llamante')
        }
      } else {
        expectError(assert, dashless, DASHLESS_PARTITION.status, DASHLESS_PARTITION.code, `${label} · uuid sin guiones (D4)`)
        assert.equal(spy.calls(), 0, `${label} · uuid sin guiones: CERO llamadas al driver`)
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
  if (column === 'partition') {
    for (const [label, target] of dbTargets()) {
      const { result: bad, queries } = await countQueries(() => catching(() => invoke(target, 'badPartition')))
      expectError(assert, bad, 422, 'E_AUTHZ_INVALID_IDENTITY', `database.${op} [${label}] · partición con gramática rota`)
      assert.lengthOf(queries, 0, `database.${op} [${label}] · partición rota: CERO sentencias`)
      const { result: dashless, queries: ran } = await countQueries(() => catching(() => invoke(target, 'dashless')))
      if (DASHLESS_PARTITION === 'accepted') {
        assert.isNull(dashless, `database.${op} [${label}] · uuid sin guiones: hoy se ACEPTA (${dashless?.message})`)
        assert.isAtLeast(ran.length, 1, `database.${op} [${label}] · uuid sin guiones: llegó al motor`)
      } else {
        expectError(assert, dashless, DASHLESS_PARTITION.status, DASHLESS_PARTITION.code, `database.${op} [${label}] · uuid sin guiones (D4)`)
        assert.lengthOf(ran, 0, `database.${op} [${label}] · uuid sin guiones: CERO sentencias`)
      }
    }
    await db.from('authz_relations').where('partition_key', `${DASHLESS.type}|${DASHLESS.uuid}`).delete()
    return
  }
  assert.fail(`columna sin sonda en database: ${column}`)
}

/* ── Capa OPENFGA: el driver real con un cliente FALSO que cuenta, base y vista ── */

type FgaTuple = { user: string; relation: string; object: string }
type FgaScript = { failOn?: (method: string, nth: number) => Error | undefined }

/**
 * Sustituye `driver.client` (propiedad pública en runtime, como hace `spyFgaClient`) por un cliente que anota
 * cada método y responde vacío (o con `tuples` en `read`); `script.failOn(method, nth)` hace fallar la enésima
 * llamada a un método (la purga PARCIAL, 🟡 5). Cero llamadas = la guarda cortó ANTES de componer una request;
 * ≥ 1 = entró. Sin servidor: el `:8101` no hace falta para juzgar guardas que cortan antes del cliente.
 */
function fakeFgaClient(driver: object, tuples: FgaTuple[] = [], script: FgaScript = {}) {
  const calls: string[] = []
  const counts = new Map<string, number>()
  const responses: Record<string, unknown> = {
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
          return responses[prop] ?? {}
        }
      },
    }
  )
  return { calls, total: () => calls.length }
}

function fgaDriver(): OpenFgaRelationsDriver {
  return new OpenFgaRelationsDriver(contractRelationsConfig(), {
    apiUrl: 'http://127.0.0.1:9',
    storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV',
    holderTypes: { user: 'user', admin: 'admin', integration: 'integration' },
    timeoutMs: 1000,
    logger: { warn: () => {} },
  })
}

/** Base y vista `withClock` (H11), cada una con su cliente falso (la vista hereda el del momento de crearse; se le pone el suyo). */
function fgaTargets(tuples?: FgaTuple[], script?: FgaScript): Array<[string, OpenFgaRelationsDriver, ReturnType<typeof fakeFgaClient>]> {
  const base = fgaDriver()
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
    const afterDelete: FgaScript = { failOn: (m, nth) => (m === 'read' && nth === 2 ? new Error('backend caído tras borrar (no es timeout)') : undefined) }
    for (const [label, target, spy] of fgaTargets(stored, afterDelete)) {
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
    const [[, base]] = fgaTargets(stored, afterDelete)
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
  if (column === 'partition') {
    for (const [label, target, spy] of fgaTargets()) {
      const bad = await catching(() => invoke(target, 'badPartition'))
      expectError(assert, bad, 422, 'E_AUTHZ_INVALID_IDENTITY', `openfga.${op} [${label}] · partición con gramática rota`)
      assert.equal(spy.total(), 0, `openfga.${op} [${label}] · partición rota: CERO llamadas al cliente`)
      const dashless = await catching(() => invoke(target, 'dashless'))
      if (DASHLESS_PARTITION === 'accepted') {
        assert.isNull(dashless, `openfga.${op} [${label}] · uuid sin guiones: hoy se ACEPTA (${dashless?.message})`)
        assert.isAtLeast(spy.total(), 1, `openfga.${op} [${label}] · uuid sin guiones: llegó al cliente`)
      } else {
        expectError(assert, dashless, DASHLESS_PARTITION.status, DASHLESS_PARTITION.code, `openfga.${op} [${label}] · uuid sin guiones (D4)`)
        assert.equal(spy.total(), 0, `openfga.${op} [${label}] · uuid sin guiones: CERO llamadas al cliente`)
      }
    }
    return
  }
  assert.fail(`columna sin sonda en openfga: ${column}`)
}

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
  if (column === 'partition') {
    // ⚪ 11: el doble también dice qué hace con la partición (D4 lo alcanzará por `scopeKey`).
    for (const [label, target] of doubleTargets()) {
      const bad = await catching(() => invoke(target, 'badPartition'))
      expectError(assert, bad, 422, 'E_AUTHZ_INVALID_IDENTITY', `double.${op} [${label}] · partición con gramática rota`)
      const dashless = await catching(() => invoke(target, 'dashless'))
      if (DASHLESS_PARTITION === 'accepted') {
        assert.isNull(dashless, `double.${op} [${label}] · uuid sin guiones: hoy se ACEPTA (${dashless?.message})`)
      } else {
        expectError(assert, dashless, DASHLESS_PARTITION.status, DASHLESS_PARTITION.code, `double.${op} [${label}] · uuid sin guiones (D4)`)
      }
    }
    return
  }
  assert.fail(`double.${op}: columna sin sonda en el doble: ${column} (D13: F-05 y partición)`)
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
 * `NA_MATRIX` para esa (razón, capa, tipo de fila, columna[, operación]); `f05` nunca es `na` (la matriz solo lo
 * admite en la vista `withClock`); `platform` es SOLO `driver()`/`capabilities()` del manager y `view` SOLO
 * `withClock`; una lectura no tiene sondas de escritura; `platform`/`view` no tienen sondas.
 */
function manifestViolations(table: GuardRow[]): string[] {
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
        const admitted = NA_MATRIX.some(
          (rule) =>
            rule.reason === cell.na &&
            rule.layers.includes(r.layer) &&
            rule.kinds.includes(r.kind) &&
            rule.columns.includes(column) &&
            (!rule.operations || rule.operations.includes(r.operation))
        )
        if (!admitted) {
          out.push(
            `${id}: 'na: ${cell.na}' NO está admitido por NA_MATRIX para ${r.layer}×${column} (fila '${r.kind}')` +
              (column === 'f05' ? ' — la columna f05 NUNCA admite na: o sonda o exención firmada (D6)' : '')
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
    const covered = new Set(mutants.flatMap((m) => m.cells))
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
      assert.isAtLeast(m.cells.length, 1, `${m.id}: sin celdas`)
      for (const id of m.cells) assert.isTrue(known.has(id), `${m.id}: la celda '${id}' no existe en el manifiesto o no tiene sonda`)
      const edits = Array.isArray(m.edits) ? m.edits : [{ find: m.find!, replace: m.replace! }]
      for (const edit of edits) {
        const file = edit.file ?? m.file
        const text = readFileSync(ROOT + file, 'utf8')
        assert.isString(edit.find, `${m.id}: find`)
        const occurrences = text.split(edit.find).length - 1
        assert.equal(occurrences, 1, `ROJO (G-M): el 'find' del mutante ${m.id} casa ${occurrences} veces en ${file} (tiene que casar EXACTAMENTE una): el código cambió y el mutante ya no apunta a la guarda`)
        assert.notEqual(edit.find, edit.replace, `${m.id}: el mutante no cambia nada`)
      }
      const titles = m.cells.map((id) => {
        const [layer, operation, column] = id.split('.') as [GuardLayer, string, GuardColumn]
        return cellTitle(layer, operation, column)
      })
      assert.sameMembers(m.expectRed, titles, `${m.id}: expectRed tiene que ser exactamente los títulos canónicos de sus celdas`)
    }
    assert.isAtLeast(mutants.length, 50, 'hay un manifiesto de mutantes de verdad')
  })

  test('el manifiesto es coherente: toda `na` está admitida por la matriz cerrada NA_MATRIX (f05 nunca `na`; doctrine solo freeze×driver; platform solo driver()/capabilities())', ({
    assert,
  }) => {
    assert.deepEqual(manifestViolations(GUARD_MANIFEST), [])
  })

  test('toda fila con celda f05 en sonda tiene variantes F-05 (una sonda vacía es roja, 🟡 7)', ({ assert }) => {
    const empty = GUARD_MANIFEST.filter((r) => 'probe' in r.cells.f05 && r.cells.f05.probe === true && !(F05_VARIANTS[r.operation]?.length > 0)).map((r) => `${r.layer}.${r.operation}`)
    assert.deepEqual(empty, [], `ROJO (🟡 7): filas con sonda F-05 sin variantes en F05_VARIANTS: ${empty.join(', ')}`)
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
    const all = { f05: SIG, trx: SIG, freeze: SIG, write: SIG, actor: SIG, partition: SIG }
    const asPlatform = manifestViolations([...GUARD_MANIFEST, row('manager', 'relateMany', 'platform', all), row('manager', 'checkMany', 'platform', all)])
    assert.isTrue(asPlatform.some((v) => v.startsWith('manager.relateMany:') && v.includes("'platform' es SOLO")), asPlatform.join('\n'))
    assert.isTrue(asPlatform.some((v) => v.startsWith('manager.relateMany.f05:') && v.includes('f05 NUNCA admite na')), asPlatform.join('\n'))
    assert.isTrue(asPlatform.some((v) => v.startsWith('manager.checkMany.f05:')), asPlatform.join('\n'))
    const P1 = { probe: true } as const
    const asWrite = manifestViolations([...GUARD_MANIFEST, row('manager', 'relateMany', 'write', { f05: SIG, trx: P1, freeze: P1, write: P1, actor: P1, partition: P1 })])
    assert.deepEqual(asWrite.filter((v) => v.includes('relateMany')).length, 1, asWrite.join('\n'))
    assert.include(asWrite[0], 'f05 NUNCA admite na')
    const asDoctrine = manifestViolations([...GUARD_MANIFEST, row('manager', 'relateMany', 'write', { f05: P1, trx: P1, freeze: { na: 'doctrine' }, write: P1, actor: P1, partition: P1 })])
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

  test('⚪11 · el doble entra en la columna partition: sus nueve operaciones con tupla tienen sonda (D4 lo alcanza por scopeKey)', ({ assert }) => {
    const probing = rows('double').filter((r) => r.kind !== 'view').map((r): [string, boolean] => [r.operation, 'probe' in r.cells.partition && r.cells.partition.probe === true])
    assert.deepEqual(probing.filter(([, p]) => !p), [], `celdas partition del doble sin sonda: ${probing.filter(([, p]) => !p).map(([o]) => o).join(', ')}`)
    assert.lengthOf(probing, 9)
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

  test('🟡E · una operación del inventario que no está en PORT_WRITES ni en PORT_READS (deny) es ROJA con su nombre; una escritura clasificada como lectura también; PORT_OPERATIONS se deriva de las dos listas', ({ assert }) => {
    const inventory = { manager: ['relate', 'check', 'deny', 'driver', 'static fromConfig'], database: ['deny', 'withClock'] }
    const violations = classificationViolations(inventory, PORT_WRITES, PORT_READS, GUARD_MANIFEST)
    assert.deepEqual(
      violations.map((v) => v.slice(0, v.indexOf(':'))),
      ['manager.deny', 'database.deny'],
      'DEFECTO CERRADO: deny sin clasificar nace rojo (driver/static/withClock no cuentan aquí: los juzga G-0)'
    )
    assert.include(violations[0], 'SIN CLASIFICAR')
    assert.include(violations[0], 'PORT_WRITES o a PORT_READS')
    // Clasificada en las dos listas, o fila cuyo kind contradice la lista ⇒ rojo.
    assert.isTrue(classificationViolations({}, [...PORT_WRITES, 'check'], PORT_READS, GUARD_MANIFEST).some((v) => v.includes("'check' está en PORT_WRITES Y en PORT_READS")))
    const misfiled = classificationViolations({}, PORT_WRITES, PORT_READS, [row('manager', 'relate', 'read', { f05: SIG, trx: SIG, freeze: SIG, write: SIG, actor: SIG, partition: SIG })])
    assert.deepEqual(misfiled, ["manager.relate: la fila es 'read' y la clasificación del puerto dice 'write'"])
    assert.sameMembers([...PORT_OPERATIONS], [...PORT_WRITES, ...PORT_READS])
    assert.sameMembers([...WRITES], [...PORT_WRITES], 'WRITES del spec se DERIVA de PORT_WRITES')
  })
})
