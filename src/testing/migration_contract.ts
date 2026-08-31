/**
 * **El contrato de MIGRACIÓN** (3b-3b · B3) — la pieza que convierte «migra»
 * en «migra sin perder nada que no esté declarado».
 *
 *   import { runMigrationContract } from '@jantstack/adonis-authz/testing'
 *
 * Se publica junto al resto de la suite de contrato porque un driver de
 * TERCEROS tiene que poder correrlo: el paquete promete migración idempotente
 * y bidireccional entre drivers, y esa promesa no la puede sostener un test
 * privado del paquete.
 *
 * Cómo funciona, y por qué así:
 *
 *  1. **Siembra FIJA** — 7 nodos, 6 holders, 4 roles, 14 grants, 5
 *     caducidades y 6 denies, escritos siempre con la API del driver. Fija a
 *     propósito: un fixture que cambia con cada corrida no permite comparar
 *     dos versiones del paquete, y el juez del panel 2 pedía «un set fijo de
 *     preguntas».
 *  2. **448 preguntas idénticas** en origen y destino: 168 `authorize`
 *     (6 holders × 7 scopes × 4 permisos), 168 `hasRole` (× 4 roles), 42
 *     `listRoles`, 24 `listScopes`, 28 `listSubjects` y 18 `listRoleScopes`.
 *     Se preguntan ANTES de migrar sobre el origen y DESPUÉS sobre el
 *     destino, y las respuestas tienen que coincidir.
 *  3. **`expectedLosses`** — la migración **no es sin pérdida** (panel 2,
 *     requisito 3 del dueño: *«posible con pérdidas declaradas y con
 *     ventana»*), así que las pérdidas se declaran DE ANTEMANO y el contrato
 *     las cruza en las dos direcciones:
 *       - una pérdida declarada tiene que aparecer **contada en
 *         `report.skipped`**; si no aparece, el contrato FALLA (una pérdida
 *         que nunca ocurre es una línea falsa en el README);
 *       - una respuesta que cambia y que NINGUNA pérdida declarada explica
 *         hace FALLAR el contrato. Ese es todo el punto: **nunca se ignora
 *         ninguna**.
 *  4. **El CENSO de la siembra** (lote 3b-4 · C1) — y esto es lo que hace
 *     que el punto 3 sea una garantía y no un formulario. Las dos caras de
 *     `expectedLosses` cruzan `Object.keys(report.skipped)`, o sea **lo que
 *     el driver se auto-declara**: cierran las omisiones DESCUIDADAS, no las
 *     silenciosas. Un driver que tira un hecho sin contarlo no puebla
 *     `skipped` y, si esa pérdida no mueve ninguna de las 448, pasaba.
 *     Medido, y no es teórico: los denies solo se observan por `authorize`,
 *     que no distingue un deny en su sitio de uno reubicado a otro scope de
 *     la misma cadena.
 *     El censo no le pregunta al driver qué se dejó: mira el destino **hecho
 *     a hecho** (los 20 de la siembra: 14 asignaciones + 6 denies) por el
 *     camino DIRECTO del puerto —`listRoles`/`listDenies`, invariante 7— y
 *     una ausencia sin motivo declarado **y contado** hace FALLAR el
 *     contrato. `listDenies` es opcional en el puerto: un driver que no lo
 *     traiga deja sus denies observados solo por `authorize`, y el veredicto
 *     lo dice en `censusLimits` en vez de callárselo.
 *  5. **El CRUCE DE CADUCIDADES** — ninguna de las 448 devuelve un
 *     `expiresAt` y el contrato no adelanta ningún reloj, así que perder la
 *     caducidad de un grant VIVO (convertirlo en permanente: fail-OPEN) era
 *     invisible. Se cruza por el único camino de solo-lectura-efectiva que
 *     hay en el puerto: `grant` con `expiresAt` OMITIDO devuelve
 *     `previousExpiresAt` (invariante 10).
 *  6. **Tres combinaciones**: ida, vuelta e ida-y-vuelta (con `--prune`, que
 *     es la que demuestra que el viaje redondo no inventa ni pierde).
 *
 * **El límite de `a→b→a`, dicho en voz alta** (tester Fase 3b · M3): las 448
 * de la vuelta se le preguntan al ORIGEN, y **nadie lo vacía** entre los dos
 * tramos. Así que esa combinación observa lo que el tramo de vuelta DESTRUYE
 * (un `--prune` que se lleva de más) y **no** lo que deja de escribir: con el
 * origen ya lleno, «todo `unchanged`» es la respuesta correcta y un tramo
 * omisivo es indistinguible de uno bueno. Quien migra de verdad (vacía el
 * origen y lo reconstruye) está cubierto por las combinaciones `a→b` y `b→a`,
 * que sí preguntan al destino recién llenado. Cerrar el hueco pide un gancho
 * nuevo en el harness («vacía los hechos de este extremo»), que es una
 * decisión del dueño y no se toma aquí.
 *
 * El motor está separado del registro de casos (`runMigrationDirection` /
 * `runMigrationContract`) para que el propio paquete pueda comprobar que el
 * contrato **sabe fallar**: un contrato que no falla no es una garantía.
 */

import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import type { AuthorizationDriver, CatalogSpec, ReconcileReport, ScopeRef, SubjectRef } from '../types.js'
import { APP_SCOPE } from '../types.js'
import { scopeKey } from '../identity.js'
import type { ContractScopeTree } from './scope_tree.js'
import { memoryScopeTree } from './scope_tree.js'
import type { ContractTestApi } from './contract.js'

/* ── El vocabulario ──────────────────────────────────────────────────────── */

/** Las tres combinaciones que el plan exige. */
export type MigrationDirection = 'a→b' | 'b→a' | 'a→b→a'

/** Una pregunta del set fijo, ya identificada por su texto. */
export interface MigrationQuestion {
  id: string
  kind: 'authorize' | 'hasRole' | 'listRoles' | 'listScopes' | 'listSubjects' | 'listRoleScopes'
  ask(driver: AuthorizationDriver): Promise<string>
}

/**
 * Una pérdida DECLARADA de la migración. Declararla es un compromiso en las
 * dos direcciones: tiene que ocurrir (salir contada en `skipped`) y solo
 * puede explicar las respuestas que diga `changesAnswer`.
 */
export interface ExpectedLoss {
  /** El motivo, tal y como sale en `report.skipped` (`expired`, `unknown-scope`, `folded-scope`…). */
  reason: string
  /** Por qué se pierde y **dónde se mide**. Va al informe y al README; no es decorativo. */
  why: string
  /** En qué combinaciones se espera. Default: las tres. */
  directions?: MigrationDirection[]
  /**
   * Qué preguntas puede cambiar de respuesta. **Default: ninguna** — lo
   * normal es que una pérdida no cambie ninguna (una asignación ya caducada
   * no concedía nada), y decir «cambia cualquiera» sería una declaración sin
   * contenido: taparía cualquier bug.
   */
  changesAnswer?(question: MigrationQuestion): boolean
}

export interface MigrationContractHarness {
  name: string
  /** Los dos extremos, por su clave en `drivers` del manager que devuelve `setup`. */
  a: string
  b: string
  /** El árbol del CONSUMIDOR. Es compartido y **no se migra**. Default: `memoryScopeTree()`. */
  makeTree?(): Promise<ContractScopeTree>
  /** Materializa el catálogo del contrato (siempre local, en `authz_*`). */
  seedCatalog(catalog: CatalogSpec): Promise<unknown>
  /**
   * Construye los dos drivers sobre ese árbol y devuelve el manager que los
   * conoce por `a`/`b` (es quien congela, resuelve el origen y llama a
   * `reconcile`). `drivers` son las MISMAS instancias, para preguntarles.
   */
  setup(tree: ContractScopeTree): Promise<{
    reconcile(options: { to: string; from?: string; prune?: boolean }): Promise<ReconcileReport>
    drivers: Record<string, AuthorizationDriver>
  }>
  /** Borra hechos y catálogo entre combinaciones. */
  cleanup(): Promise<void>
  /** Las pérdidas, declaradas de antemano. Una lista vacía es un compromiso fuerte. */
  expectedLosses: ExpectedLoss[]
}

/* ── La siembra FIJA ─────────────────────────────────────────────────────── */

/** Los 4 permisos del contrato de migración. `admin:all` no lo lleva ningún rol: hay preguntas que son `false` en todas partes. */
export const MIGRATION_PERMISSIONS = ['docs:read', 'docs:write', 'billing:read', 'admin:all'] as const

/** Los 4 roles, uno por nivel útil (dos a `app`, para que el nivel no sea la única variable). */
export const MIGRATION_ROLES = ['mig-editor', 'mig-viewer', 'mig-lead', 'mig-auditor'] as const

export const MIGRATION_CATALOG: CatalogSpec = {
  permissions: MIGRATION_PERMISSIONS.map((slug) => ({ slug })),
  roles: [
    { slug: 'mig-editor', scopeType: 'app', permissions: ['docs:read', 'docs:write'] },
    { slug: 'mig-viewer', scopeType: 'organization', permissions: ['docs:read'] },
    { slug: 'mig-lead', scopeType: 'unit', permissions: ['docs:read', 'docs:write', 'billing:read'] },
    { slug: 'mig-auditor', scopeType: 'app', permissions: ['billing:read'] },
  ],
}

/** Los 7 nodos y los 6 holders de una corrida (uuids nuevos por corrida; la FORMA es la fija). */
export interface MigrationSeed {
  scopes: { app: ScopeRef; org1: ScopeRef; org2: ScopeRef; unit1: ScopeRef; unit2: ScopeRef; unit3: ScopeRef; unit4: ScopeRef }
  holders: SubjectRef[]
  /** El instante de la corrida: las caducidades se colocan alrededor. */
  now: Date
}

export function makeMigrationSeed(now: Date = new Date()): MigrationSeed {
  const shared = uuidv7()
  return {
    scopes: {
      app: APP_SCOPE,
      org1: { type: 'organization', uuid: uuidv7() },
      org2: { type: 'organization', uuid: uuidv7() },
      unit1: { type: 'unit', uuid: uuidv7() },
      unit2: { type: 'unit', uuid: uuidv7() },
      unit3: { type: 'unit', uuid: uuidv7() },
      unit4: { type: 'unit', uuid: uuidv7() },
    },
    holders: [
      { type: 'users', uuid: uuidv7() },
      { type: 'users', uuid: uuidv7() },
      { type: 'users', uuid: uuidv7() },
      { type: 'users', uuid: shared },
      // Invariante 4: el MISMO uuid con otro morph name jamás se cruza.
      { type: 'admins', uuid: shared },
      { type: 'admins', uuid: uuidv7() },
    ],
    now,
  }
}

/** El árbol: 7 nodos con profundidad 4 (`app → org1 → unit1 → unit4`). */
export async function plantMigrationTree(tree: ContractScopeTree, seed: MigrationSeed): Promise<void> {
  const s = seed.scopes
  await tree.attach(s.org1, s.app)
  await tree.attach(s.org2, s.app)
  await tree.attach(s.unit1, s.org1)
  await tree.attach(s.unit2, s.org1)
  await tree.attach(s.unit3, s.org2)
  await tree.attach(s.unit4, s.unit1)
}

/**
 * Los 14 grants (5 con caducidad: 4 vivas y **1 ya pasada**, que es la
 * pérdida declarada `expired`) y los 6 denies, escritos con la API del
 * driver — nunca a mano: lo que se migra tiene que ser lo que el motor
 * escribe.
 */
export interface MigrationGrant {
  holder: SubjectRef
  role: string
  scope: ScopeRef
  /** Omitido = sin caducidad; una `Date` = la caducidad exacta sembrada. */
  expiresAt?: Date
  /** La única ya vencida: es la pérdida declarada `expired`. */
  expired?: true
}

/** Un deny de la siembra. Tabla, y no una lista suelta, por lo mismo que los grants. */
export interface MigrationDeny {
  holder: SubjectRef
  permission: string
  scope: ScopeRef
}

/**
 * **Los 14 grants, en una tabla** — para que la siembra y el CRUCE DE
 * CADUCIDADES salgan del mismo sitio: dos listas paralelas se separan al
 * primer cambio y el cruce dejaría de comprobar lo que se sembró.
 */
export function migrationGrants(seed: MigrationSeed): MigrationGrant[] {
  const s = seed.scopes
  const [u1, u2, u3, u4, a1, a2] = seed.holders
  const soon = new Date(seed.now.getTime() + 3_600_000)
  const later = new Date(seed.now.getTime() + 7_200_000)
  const past = new Date(seed.now.getTime() - 3_600_000)
  return [
    { holder: u1, role: 'mig-editor', scope: s.app },
    { holder: u1, role: 'mig-viewer', scope: s.org2 },
    { holder: u2, role: 'mig-viewer', scope: s.org1 },
    { holder: u2, role: 'mig-lead', scope: s.unit3, expiresAt: soon },
    { holder: u3, role: 'mig-lead', scope: s.unit1 },
    { holder: u3, role: 'mig-lead', scope: s.unit2, expiresAt: later },
    // La caducada: existe en el origen y NO concede. Es la pérdida `expired`.
    { holder: u3, role: 'mig-auditor', scope: s.app, expiresAt: past, expired: true },
    { holder: u4, role: 'mig-lead', scope: s.unit4 },
    { holder: u4, role: 'mig-viewer', scope: s.org1, expiresAt: later },
    { holder: a1, role: 'mig-editor', scope: s.app },
    { holder: a1, role: 'mig-lead', scope: s.unit1 },
    { holder: a2, role: 'mig-viewer', scope: s.org2 },
    { holder: a2, role: 'mig-auditor', scope: s.app },
    { holder: u2, role: 'mig-lead', scope: s.unit4, expiresAt: soon },
  ]
}

/**
 * **Los 6 denies, en una tabla** — misma razón que los grants: el CENSO
 * (abajo) tiene que preguntar por lo que se sembró, y dos listas paralelas se
 * separan al primer cambio.
 */
export function migrationDenies(seed: MigrationSeed): MigrationDeny[] {
  const s = seed.scopes
  const [u1, u2, u3, u4, a1, a2] = seed.holders
  return [
    { holder: u1, permission: 'docs:write', scope: s.org2 },
    { holder: u2, permission: 'docs:read', scope: s.unit3 },
    { holder: u3, permission: 'docs:write', scope: s.unit1 },
    { holder: u4, permission: 'billing:read', scope: s.app },
    { holder: a1, permission: 'docs:read', scope: s.unit1 },
    { holder: a2, permission: 'billing:read', scope: s.org2 },
  ]
}

export async function plantMigrationFacts(driver: AuthorizationDriver, seed: MigrationSeed): Promise<void> {
  for (const g of migrationGrants(seed)) {
    await driver.grant(g.holder, g.role, g.scope, g.expiresAt ? { expiresAt: g.expiresAt } : {})
  }
  for (const d of migrationDenies(seed)) {
    await driver.deny(d.holder, d.permission, d.scope)
  }
}

/* ── El CENSO: los hechos SEMBRADOS, uno a uno ───────────────────────────── */

/**
 * Un hecho de la siembra tal como el CENSO lo busca en el destino. Es la
 * lista contra la que se comprueba que la migración no perdió nada: no
 * depende de que alguna de las 448 respuestas se mueva, ni de que el driver
 * se auto-declare nada.
 */
export interface MigrationFact {
  kind: 'assignment' | 'deny'
  holder: SubjectRef
  scope: ScopeRef
  /** `assignment`: el slug del rol. `deny`: el slug del permiso. */
  name: string
  /**
   * El motivo DECLARADO que justifica que este hecho NO llegue al destino.
   * Sin él, que falte es una pérdida **silenciosa** y el contrato falla —
   * cuente el driver lo que cuente en `report.skipped`.
   */
  expectedLoss?: string
}

/** Los 20 hechos de la siembra (14 asignaciones + 6 denies), en un solo sitio. */
export function migrationFacts(seed: MigrationSeed): MigrationFact[] {
  const facts: MigrationFact[] = migrationGrants(seed).map((g) => ({
    kind: 'assignment' as const,
    holder: g.holder,
    scope: g.scope,
    name: g.role,
    // La caducada NO llega al destino, y eso está declarado: es la pérdida
    // `expired`. Cualquier otra ausencia es un fallo.
    ...(g.expired ? { expectedLoss: 'expired' } : {}),
  }))
  for (const d of migrationDenies(seed)) {
    facts.push({ kind: 'deny', holder: d.holder, scope: d.scope, name: d.permission })
  }
  return facts
}

/** Cómo se nombra un hecho en el informe del contrato. */
export function describeMigrationFact(fact: MigrationFact): string {
  return `${fact.kind === 'deny' ? 'deny' : 'grant'} ${tag(fact.holder)} ${fact.name} @ ${scopeTag(fact.scope)}`
}

export interface MigrationCensus {
  present: MigrationFact[]
  missing: MigrationFact[]
  /** Lo que ESTE driver no deja censar, dicho en voz alta (nunca un hueco callado). */
  limits: string[]
}

/**
 * **El censo** (lote 3b-4 · C1): pregunta al destino, hecho a hecho, si lo
 * que se sembró está. Se lee por el camino DIRECTO del puerto —invariante 7,
 * hechos directos del scope exacto—: `listRoles` para las asignaciones y
 * `listDenies` para los denies. No mira `report.skipped`, no compara
 * respuestas y no depende de que la pérdida cambie ninguna de las 448.
 *
 * `listDenies` es OPCIONAL en el puerto: un driver que no lo trae deja sus
 * denies censados solo por `authorize` (lo dice `limits`, y está escrito en
 * el README). Los dos drivers del paquete lo implementan.
 */
export async function censusMigrationFacts(
  driver: AuthorizationDriver,
  seed: MigrationSeed
): Promise<MigrationCensus> {
  const present: MigrationFact[] = []
  const missing: MigrationFact[] = []
  const limits: string[] = []
  let denyReadable = typeof driver.listDenies === 'function'
  if (!denyReadable) {
    limits.push(
      'este driver no implementa `listDenies`, así que los 6 denies de la siembra no se pueden ' +
        'censar uno a uno: solo los observa `authorize`, que no los ve donde no bloquean nada.'
    )
  }
  for (const fact of migrationFacts(seed)) {
    if (fact.kind === 'assignment') {
      const roles = await driver.listRoles(fact.holder, fact.scope)
      ;(roles.includes(fact.name) ? present : missing).push(fact)
      continue
    }
    if (!denyReadable) continue
    try {
      const denies = await driver.listDenies!(fact.holder, fact.scope)
      ;(denies.some((deny) => deny.permission === fact.name) ? present : missing).push(fact)
    } catch (error: any) {
      // `listDenies: false` declarado con 500 `E_AUTHZ_UNSUPPORTED`: es la
      // misma respuesta que no traerlo, y se dice igual.
      if (error?.code !== 'E_AUTHZ_UNSUPPORTED') throw error
      denyReadable = false
      limits.push(
        'este driver responde 500 `E_AUTHZ_UNSUPPORTED` a `listDenies`, así que los denies de la ' +
          'siembra no se censan uno a uno: solo los observa `authorize`.'
      )
    }
  }
  return { present, missing, limits }
}

/* ── Las 448 preguntas ───────────────────────────────────────────────────── */

function tag(subject: SubjectRef): string {
  return `${subject.type}:${subject.uuid}`
}

function scopeTag(scope: ScopeRef): string {
  return scopeKey(scope)
}

function scopeList(scopes: ScopeRef[]): string {
  return scopes.map(scopeTag).sort().join(',')
}

function subjectList(subjects: SubjectRef[]): string {
  return subjects.map(tag).sort().join(',')
}

/**
 * Las 448: **168 + 168 + 42 + 24 + 28 + 18**. No es un número redondo por
 * casualidad — es el producto de la siembra fija, y por eso el contrato
 * puede afirmar «448 preguntas idénticas» y no «unas cuantas».
 */
export function migrationQuestions(seed: MigrationSeed): MigrationQuestion[] {
  const s = seed.scopes
  const scopes: ScopeRef[] = [s.app, s.org1, s.org2, s.unit1, s.unit2, s.unit3, s.unit4]
  const holders = seed.holders
  const questions: MigrationQuestion[] = []

  for (const holder of holders) {
    for (const scope of scopes) {
      for (const permission of MIGRATION_PERMISSIONS) {
        questions.push({
          id: `authorize(${tag(holder)}, ${permission}, ${scopeTag(scope)})`,
          kind: 'authorize',
          ask: async (driver) => String(await driver.authorize(holder, permission, scope)),
        })
      }
    }
  }
  for (const holder of holders) {
    for (const scope of scopes) {
      for (const role of MIGRATION_ROLES) {
        questions.push({
          id: `hasRole(${tag(holder)}, ${role}, ${scopeTag(scope)})`,
          kind: 'hasRole',
          ask: async (driver) => String(await driver.hasRole(holder, role, scope)),
        })
      }
    }
  }
  for (const holder of holders) {
    for (const scope of scopes) {
      questions.push({
        id: `listRoles(${tag(holder)}, ${scopeTag(scope)})`,
        kind: 'listRoles',
        ask: async (driver) => [...(await driver.listRoles(holder, scope))].sort().join(','),
      })
    }
  }
  for (const holder of holders) {
    for (const permission of MIGRATION_PERMISSIONS) {
      questions.push({
        id: `listScopes(${tag(holder)}, ${permission})`,
        kind: 'listScopes',
        ask: async (driver) => scopeList(await driver.listScopes(holder, permission)),
      })
    }
  }
  for (const role of MIGRATION_ROLES) {
    for (const scope of scopes) {
      questions.push({
        id: `listSubjects(${role}, ${scopeTag(scope)})`,
        kind: 'listSubjects',
        ask: async (driver) => subjectList(await driver.listSubjects(role, scope)),
      })
    }
  }
  for (const holder of holders) {
    for (const scopeType of ['app', 'organization', 'unit']) {
      questions.push({
        id: `listRoleScopes(${tag(holder)}, ${scopeType})`,
        kind: 'listRoleScopes',
        ask: async (driver) => scopeList(await driver.listRoleScopes(holder, scopeType)),
      })
    }
  }
  return questions
}

/** Cuántas preguntas tiene el set fijo. Es una CIFRA del contrato, no un detalle. */
export const MIGRATION_QUESTION_COUNT = 448

/* ── El motor ────────────────────────────────────────────────────────────── */

export interface MigrationVerdict {
  direction: MigrationDirection
  /** Los reportes de cada tramo (dos en `a→b→a`). */
  reports: ReconcileReport[]
  questions: number
  /** Respuestas que cambiaron, con la pérdida declarada que las explica (o `null`). */
  mismatches: Array<{ question: string; before: string; after: string; explainedBy: string | null }>
  /** Motivos declarados que NO aparecieron contados en `skipped`. */
  declaredButAbsent: string[]
  /** Caducidades que el destino no conservó (tester Fase 3b · M1). */
  expiryMismatches: Array<{ grant: string; before: string; after: string }>
  /**
   * Hechos de la SIEMBRA que el destino no tiene y que NADIE declaró (lote
   * 3b-4 · C1). Es el censo, no `report.skipped`: aquí caen las pérdidas que
   * el driver no cuenta.
   */
  silentLosses: Array<{ fact: string; at: string }>
  /** Lo que el driver no deja censar, dicho en voz alta (nunca un hueco callado). */
  censusLimits: string[]
  /** Todo lo que hace fallar el contrato, en texto. Vacío = verde. */
  failures: string[]
}

function reasonsOf(reports: ReconcileReport[]): Set<string> {
  const out = new Set<string>()
  for (const report of reports) for (const reason of Object.keys(report.skipped)) out.add(reason)
  return out
}

/**
 * Corre UNA combinación de punta a punta y devuelve el veredicto. Es el
 * motor: `runMigrationContract` solo lo envuelve en tres casos de Japa, y el
 * paquete lo usa directamente para demostrar que el contrato **sabe fallar**.
 */
export async function runMigrationDirection(
  harness: MigrationContractHarness,
  direction: MigrationDirection
): Promise<MigrationVerdict> {
  await harness.cleanup()
  await harness.seedCatalog(MIGRATION_CATALOG)
  const tree = harness.makeTree ? await harness.makeTree() : memoryScopeTree()
  const { reconcile, drivers } = await harness.setup(tree)
  const seed = makeMigrationSeed()
  await plantMigrationTree(tree, seed)

  const origin = direction === 'b→a' ? harness.b : harness.a
  const other = origin === harness.a ? harness.b : harness.a
  await plantMigrationFacts(drivers[origin], seed)

  const questions = migrationQuestions(seed)
  const before = new Map<string, string>()
  for (const question of questions) before.set(question.id, await question.ask(drivers[origin]))

  const reports: ReconcileReport[] = []
  const failures: string[] = []
  const mismatches: MigrationVerdict['mismatches'] = []

  const explains = (question: MigrationQuestion) =>
    harness.expectedLosses.find(
      (candidate) =>
        (candidate.directions ?? ['a→b', 'b→a', 'a→b→a']).includes(direction) &&
        candidate.changesAnswer?.(question) === true
    ) ?? null

  /** Compara las 448 contra UN extremo y apunta lo que cambió sin explicación. */
  const compareAgainst = async (driverKey: string, label: string) => {
    for (const question of questions) {
      const after = await question.ask(drivers[driverKey])
      const was = before.get(question.id)!
      if (after === was) continue
      const loss = explains(question)
      const id = label ? `${label} ${question.id}` : question.id
      mismatches.push({ question: id, before: was, after, explainedBy: loss?.reason ?? null })
      if (!loss) {
        failures.push(
          `[${direction}] la respuesta CAMBIÓ y no hay pérdida declarada que lo explique: ` +
            `${id} — antes '${was}', después '${after}'`
        )
      }
    }
  }

  /**
   * **Un tramo tiene que HACER algo** (tester Fase 3b · M3). Sin esto, en
   * `a→b→a` el tramo de vuelta podía no ejecutarse siquiera: como las
   * preguntas se le hacen al ORIGEN —que nadie vacía—, un tramo de vuelta que
   * no escribe, no borra y no lee NADA es indistinguible de uno correcto y
   * las 448 salen idénticas. Medido: quitando el `reconcile` de vuelta la
   * suite entera seguía en verde.
   */
  const legDidSomething = (report: ReconcileReport, leg: string) => {
    const seen = report.written + report.updated + report.unchanged + report.extra + report.deleted
    if (seen > 0) return
    failures.push(
      `[${direction}] el tramo ${leg} no tocó NI UNA tupla (written/updated/unchanged/extra/deleted todo a cero). ` +
        `Una migración que no mira nada no es una migración: comprueba el origen, el destino y el --from.`
    )
  }

  /* ── El CENSO de la siembra (lote 3b-4 · C1) ─────────────────────────
   *
   * `expectedLosses` cruzaba `Object.keys(report.skipped)`, o sea **lo que el
   * propio driver se auto-declara**: cerraba las omisiones DESCUIDADAS y no
   * las silenciosas. Un driver que tira un hecho sin contarlo no puebla
   * `skipped`, y si esa pérdida no mueve ninguna de las 448 —los denies solo
   * se observan por `authorize`, y `authorize` no ve un deny reubicado dentro
   * de la misma cadena— el contrato pasaba.
   *
   * El censo no pregunta al driver qué se dejó: **mira el destino hecho a
   * hecho** por el camino DIRECTO del puerto y compara con lo que el propio
   * contrato sembró. Una ausencia sin motivo DECLARADO **y CONTADO** es un
   * fallo, cuente el driver lo que cuente.
   */
  const silentLosses: MigrationVerdict['silentLosses'] = []
  const censusLimits: string[] = []
  const censusAt = async (driverKey: string, label: string) => {
    const census = await censusMigrationFacts(drivers[driverKey], seed)
    for (const limit of census.limits) if (!censusLimits.includes(limit)) censusLimits.push(limit)
    const seen = reasonsOf(reports)
    const known = new Set(
      harness.expectedLosses
        .filter((loss) => (loss.directions ?? ['a→b', 'b→a', 'a→b→a']).includes(direction))
        .map((loss) => loss.reason)
    )
    for (const fact of census.missing) {
      const id = describeMigrationFact(fact)
      if (!fact.expectedLoss) {
        silentLosses.push({ fact: id, at: driverKey })
        failures.push(
          `[${direction}] PÉRDIDA SILENCIOSA: '${id}' se sembró y '${driverKey}'${label} no lo tiene. ` +
            `No hay ninguna pérdida declarada que lo cubra y el driver TAMPOCO lo contó en report.skipped ` +
            `(motivos vistos: ${[...seen].sort().join(', ') || 'ninguno'}). Que las 448 respuestas no se ` +
            `muevan no lo salva: un hecho que desaparece sin contarse es exactamente lo que la migración ` +
            `no puede hacer.`
        )
        continue
      }
      if (!known.has(fact.expectedLoss)) {
        failures.push(
          `[${direction}] '${id}' no está en '${driverKey}'${label} y el contrato lo atribuye a la pérdida ` +
            `'${fact.expectedLoss}', que este harness NO declara en expectedLosses.`
        )
        continue
      }
      if (!seen.has(fact.expectedLoss)) {
        failures.push(
          `[${direction}] '${id}' no está en '${driverKey}'${label}: la pérdida '${fact.expectedLoss}' ` +
            `OCURRIÓ y el driver no la contó en report.skipped. Perderla está declarado; perderla en ` +
            `silencio, no.`
        )
      }
    }
  }

  reports.push(await reconcile({ to: other, from: origin }))
  legDidSomething(reports[0], `${origin} → ${other}`)

  // La ida y vuelta lleva `--prune`: es la única forma de comprobar que el
  // viaje redondo no deja de MÁS en el origen (y de ver que lo que se lleva
  // por delante es exactamente una pérdida DECLARADA).
  if (direction === 'a→b→a') {
    // Y el INTERMEDIO también se pregunta: si no, el tramo de ida podría
    // haberse dejado media siembra y la vuelta —que ni siquiera necesita
    // escribir, porque el origen sigue lleno— lo taparía.
    await compareAgainst(other, `[intermedio ${other}]`)
    await censusAt(other, ' (intermedio)')
    reports.push(await reconcile({ to: origin, from: other, prune: true }))
    legDidSomething(reports[1], `${other} → ${origin} (--prune)`)
  }

  const asked = direction === 'a→b→a' ? origin : other
  await compareAgainst(asked, '')
  await censusAt(asked, '')

  // **Las dos caras, y las dos son obligatorias.**
  //
  // (i) Todo lo que la pasada dejó fuera —cada motivo de `report.skipped`—
  //     tiene que estar DECLARADO. Es la mitad que hace del contrato una
  //     garantía y no un adorno: sin ella, un driver puede saltarse lo que
  //     quiera mientras no cambie ninguna de las 448 respuestas de ESTA
  //     siembra, que es justo la clase de bug que una siembra fija no ve.
  //     «Nunca se ignora ninguna» significa esto.
  const counted = reasonsOf(reports)
  const declared = new Set(
    harness.expectedLosses
      .filter((loss) => (loss.directions ?? ['a→b', 'b→a', 'a→b→a']).includes(direction))
      .map((loss) => loss.reason)
  )
  for (const reason of [...counted].sort()) {
    if (declared.has(reason)) continue
    failures.push(
      `[${direction}] la pasada NO migró algo por '${reason}' y esa pérdida no está declarada en ` +
        `expectedLosses. Declárala (con su motivo medido) o arregla la migración: una pérdida que no ` +
        `está escrita es una pérdida silenciosa.`
    )
  }

  // (ii) Y al revés: una pérdida declarada tiene que OCURRIR y salir contada.
  //      Si no, es una línea falsa en el README, y el README es el contrato
  //      con el consumidor.
  const declaredButAbsent: string[] = []
  for (const loss of harness.expectedLosses) {
    if (!(loss.directions ?? ['a→b', 'b→a', 'a→b→a']).includes(direction)) continue
    if (counted.has(loss.reason)) continue
    declaredButAbsent.push(loss.reason)
    failures.push(
      `[${direction}] la pérdida declarada '${loss.reason}' NO aparece contada en report.skipped ` +
        `(motivos vistos: ${[...counted].sort().join(', ') || 'ninguno'}). Una pérdida que nunca ocurre ` +
        `no se declara: se borra.`
    )
  }

  /* ── El CRUCE DE CADUCIDADES (tester Fase 3b · M1) ────────────────────
   *
   * Ninguna de las 448 preguntas devuelve un `expiresAt`, y no hay reloj que
   * adelantar: una migración que se deja por el camino la caducidad de un
   * grant VIVO —lo convierte en permanente— responde exactamente lo mismo a
   * las 448 y no cuenta nada en `skipped`. Medido: con
   * `reconcile --to=database` escribiendo `expires_at: null`, las TRES
   * combinaciones seguían en VERDE. Es la pérdida de datos que el contrato
   * decía cortar y no cortaba, y además es fail-OPEN (un permiso temporal que
   * ya no caduca).
   *
   * Se cruza por el ÚNICO camino del puerto que devuelve una caducidad sin
   * inventar un método nuevo: `grant` con `expiresAt` OMITIDO devuelve
   * `previousExpiresAt` (invariante 10, «omitido preserva»). Va DESPUÉS de
   * las 448 —es una escritura, aunque idempotente y sin cambio de estado— y
   * por eso no puede alterar ninguna respuesta ya medida.
   */
  const expiryMismatches: MigrationVerdict['expiryMismatches'] = []
  const stamp = (value: Date | null | undefined) =>
    value === undefined ? 'ausente' : value === null ? 'sin caducidad' : value.toISOString()
  const crossExpiries = async (driverKey: string, label: string) => {
    for (const g of migrationGrants(seed)) {
      // La caducada es la pérdida declarada: en el destino no está, y `grant`
      // con `{}` la REVIVIRÍA (invariante 10). No se cruza.
      if (g.expired) continue
      const outcome = await drivers[driverKey].grant(g.holder, g.role, g.scope, {})
      const after = stamp(outcome.existed ? (outcome.previousExpiresAt ?? null) : undefined)
      const was = stamp(g.expiresAt ?? null)
      if (after === was) continue
      const id = `${tag(g.holder)} ${g.role} @ ${scopeTag(g.scope)}`
      expiryMismatches.push({ grant: `${driverKey}${label} ${id}`, before: was, after })
      failures.push(
        `[${direction}] la CADUCIDAD no sobrevivió a la migración: ${id} en '${driverKey}'${label} ` +
          `— antes '${was}', después '${after}'. Ninguna de las ${MIGRATION_QUESTION_COUNT} ` +
          `preguntas lo ve (no devuelven caducidades) y perderla es fail-OPEN: un permiso temporal que ya no caduca.`
      )
    }
  }
  // El INTERMEDIO también se cruza (lote 3b-4 · C1): en `a→b→a` las 448 y el
  // cruce se le hacen al ORIGEN, que nadie vacía, así que una caducidad que
  // el tramo de IDA se dejó quedaba tapada. Se hace DESPUÉS del segundo
  // tramo a propósito: `grant` con `{}` es una escritura y crearía en el
  // intermedio el hecho que falta, falseando la pasada de vuelta.
  if (direction === 'a→b→a') await crossExpiries(other, ' (intermedio)')
  await crossExpiries(asked, '')

  // Los TRAMOS que la combinación promete: `a→b→a` son DOS pasadas, no una.
  // Es la comprobación barata que delata un motor —o un harness— al que se le
  // ha caído un tramo por el camino (tester Fase 3b · M3).
  const expectedLegs = direction === 'a→b→a' ? 2 : 1
  if (reports.length !== expectedLegs) {
    failures.push(
      `[${direction}] la combinación son ${expectedLegs} pasada(s) de reconcile y se ejecutaron ${reports.length}`
    )
  }

  if (questions.length !== MIGRATION_QUESTION_COUNT) {
    failures.push(`[${direction}] el set fijo tiene ${questions.length} preguntas y no ${MIGRATION_QUESTION_COUNT}`)
  }

  return {
    direction,
    reports,
    questions: questions.length,
    mismatches,
    declaredButAbsent,
    expiryMismatches,
    silentLosses,
    censusLimits,
    failures,
  }
}

/**
 * Registra las tres combinaciones como casos de Japa. Llámala en el TOP LEVEL
 * del spec (Japa descarta los grupos registrados tarde).
 */
export function runMigrationContract(harness: MigrationContractHarness) {
  return registerMigrationContract(harness, {
    group: (title, define) => test.group(title, define as any),
    test: (title, fn) => test(title, fn as any),
  })
}

export function registerMigrationContract(harness: MigrationContractHarness, api: ContractTestApi) {
  api.group(`migration contract [${harness.name}]`, (group) => {
    group.teardown(async () => {
      await harness.cleanup()
    })

    for (const direction of ['a→b', 'b→a', 'a→b→a'] as const) {
      const label =
        direction === 'a→b'
          ? `${harness.a} → ${harness.b}`
          : direction === 'b→a'
            ? `${harness.b} → ${harness.a}`
            : `${harness.a} → ${harness.b} → ${harness.a} (--prune)`
      api.test(
        `${MIGRATION_QUESTION_COUNT} preguntas idénticas, ${label}: las respuestas coinciden y toda pérdida está declarada`,
        async ({ assert }) => {
          const verdict = await runMigrationDirection(harness, direction)
          assert.equal(verdict.questions, MIGRATION_QUESTION_COUNT)
          assert.deepEqual(verdict.failures, [])
        }
      )?.timeout(600_000)
    }
  })
}
