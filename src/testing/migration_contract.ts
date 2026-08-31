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
 *  4. **Tres combinaciones**: ida, vuelta e ida-y-vuelta (con `--prune`, que
 *     es la que demuestra que el viaje redondo no inventa ni pierde).
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
export async function plantMigrationFacts(driver: AuthorizationDriver, seed: MigrationSeed): Promise<void> {
  const s = seed.scopes
  const [u1, u2, u3, u4, a1, a2] = seed.holders
  const soon = new Date(seed.now.getTime() + 3_600_000)
  const later = new Date(seed.now.getTime() + 7_200_000)
  const past = new Date(seed.now.getTime() - 3_600_000)

  await driver.grant(u1, 'mig-editor', s.app, {})
  await driver.grant(u1, 'mig-viewer', s.org2, {})
  await driver.grant(u2, 'mig-viewer', s.org1, {})
  await driver.grant(u2, 'mig-lead', s.unit3, { expiresAt: soon })
  await driver.grant(u3, 'mig-lead', s.unit1, {})
  await driver.grant(u3, 'mig-lead', s.unit2, { expiresAt: later })
  // La caducada: existe en el origen y NO concede. Es la pérdida `expired`.
  await driver.grant(u3, 'mig-auditor', s.app, { expiresAt: past })
  await driver.grant(u4, 'mig-lead', s.unit4, {})
  await driver.grant(u4, 'mig-viewer', s.org1, { expiresAt: later })
  await driver.grant(a1, 'mig-editor', s.app, {})
  await driver.grant(a1, 'mig-lead', s.unit1, {})
  await driver.grant(a2, 'mig-viewer', s.org2, {})
  await driver.grant(a2, 'mig-auditor', s.app, {})
  await driver.grant(u2, 'mig-lead', s.unit4, { expiresAt: soon })

  await driver.deny(u1, 'docs:write', s.org2)
  await driver.deny(u2, 'docs:read', s.unit3)
  await driver.deny(u3, 'docs:write', s.unit1)
  await driver.deny(u4, 'billing:read', s.app)
  await driver.deny(a1, 'docs:read', s.unit1)
  await driver.deny(a2, 'billing:read', s.org2)
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
  reports.push(await reconcile({ to: other, from: origin }))
  // La ida y vuelta lleva `--prune`: es la única forma de comprobar que el
  // viaje redondo no deja de MÁS en el origen (y de ver que lo que se lleva
  // por delante es exactamente una pérdida DECLARADA).
  const asked = direction === 'a→b→a' ? origin : other
  if (direction === 'a→b→a') reports.push(await reconcile({ to: origin, from: other, prune: true }))

  const failures: string[] = []
  const mismatches: MigrationVerdict['mismatches'] = []
  for (const question of questions) {
    const after = await question.ask(drivers[asked])
    const was = before.get(question.id)!
    if (after === was) continue
    const loss =
      harness.expectedLosses.find(
        (candidate) =>
          (candidate.directions ?? ['a→b', 'b→a', 'a→b→a']).includes(direction) &&
          candidate.changesAnswer?.(question) === true
      ) ?? null
    mismatches.push({ question: question.id, before: was, after, explainedBy: loss?.reason ?? null })
    if (!loss) {
      failures.push(
        `[${direction}] la respuesta CAMBIÓ y no hay pérdida declarada que lo explique: ` +
          `${question.id} — antes '${was}', después '${after}'`
      )
    }
  }

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

  if (questions.length !== MIGRATION_QUESTION_COUNT) {
    failures.push(`[${direction}] el set fijo tiene ${questions.length} preguntas y no ${MIGRATION_QUESTION_COUNT}`)
  }

  return { direction, reports, questions: questions.length, mismatches, declaredButAbsent, failures }
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
