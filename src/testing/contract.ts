import '@japa/assert'
import type { Assert } from '@japa/assert'
import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import type {
  AuthorizationDriver,
  CatalogSpec,
  ScopeRef,
  SubjectRef,
} from '../types.js'
import { APP_SCOPE } from '../types.js'
import { memoryScopeTree } from './scope_tree.js'
import type { ContractScopeTree } from './scope_tree.js'

/**
 * Suite de contrato del sistema de autorización — EL JUEZ.
 *
 * Cualquier driver (database, openfga, custom del consumidor) debe pasar
 * estos casos sin modificarlos: son la definición ejecutable de la semántica
 * documentada en `../types.js`. Para enchufar un driver:
 *
 *   runAuthorizationDriverContract({
 *     name: 'mi-driver',
 *     level: '2.0',                      // omitido = 'core': solo los casos de 1.x
 *     capabilities: { hierarchyFacts: false, transactions: false, truncationSignal: false,
 *                     singleCheckAuthorize: false, injectableClock: false },
 *     seedCatalog: (catalog) => ...,     // materializa roles/permisos
 *     makeDriver: (tree) => new MiDriver({ resolveAncestors: ... }), // recibe el árbol
 *     cleanup: () => ...,                // borra hechos + catálogo entre tests
 *   })
 *
 * Llámala en el TOP LEVEL del spec (no dentro de un `test` ni de un hook):
 * Japa registra los grupos al importar el archivo y descarta los tardíos.
 *
 * `seedCatalog`/`cleanup` son del harness (no del contrato) porque cada
 * backend materializa el catálogo a su manera (tablas propias, FGA model...).
 *
 * El ÁRBOL de scopes también es del harness (`makeTree`, por defecto
 * `memoryScopeTree()`): la suite lo construye caso a caso con `tree.attach` y
 * el driver lo ve a través de lo que el harness le inyecte (un
 * `resolveAncestors` que lo camina, o hechos en el backend). Así el
 * invariante 1 se prueba con cadenas reales y no con el resolutor plano.
 */

/**
 * Lo que un driver DECLARA poder hacer. Cada capacidad tiene en la suite un
 * par de casos `{ whenTrue, whenFalse }` — nunca un `skip`. Hoy hay par para
 * `truncationSignal: false` (con `exhaustiveLists`) y `hierarchyFacts: false`;
 * los demás llegan con su fase, y mientras tanto declararlos `true` hace que
 * la suite lance al registrarse: una promesa sin juez no pasa.
 */
export interface DriverCapabilities {
  /** El driver materializa el árbol como hechos propios (Fase 3b). */
  hierarchyFacts: boolean
  /** Acepta `{ trx }` externa en las escrituras (Fase 2.5). */
  transactions: boolean
  /**
   * Los `list*` lanzan si el backend trunca. Ningún driver del paquete trunca
   * (L0.7 se cerró enumerando con `Read` paginado), así que no hay caso para
   * `true`: es el par que un driver de terceros con backend con tope tendría
   * que traer.
   */
  truncationSignal: boolean
  /** `authorize` = una sola llamada al backend (modo facts, Fase 3b). */
  singleCheckAuthorize: boolean
  /** Acepta `now()` inyectado (Fase 2.5). */
  injectableClock: boolean
  /**
   * Los `list*` devuelven TODO sin tope. Es la verdad de los dos drivers del
   * paquete: `database` (SQL sin límite) y `openfga` (enumeración por `Read`
   * paginado, L0.7). Con `false` el harness debe dar `limits.listMaxResults`
   * y el juez prueba solo la frontera exacta: es la declaración honesta de
   * un driver de terceros cuyo backend trunca y que no lo señala.
   */
  exhaustiveLists: boolean
}

export type ContractLevel = 'core' | '2.0'

export interface DriverContractHarness {
  name: string
  /** `core` (default): los 19 casos de 1.x. `'2.0'`: además los de la Fase 0+. */
  level?: ContractLevel
  capabilities: DriverCapabilities
  /** Tope de resultados del backend de test. Obligatorio con `exhaustiveLists: false`. */
  limits?: { listMaxResults?: number }
  seedCatalog(catalog: CatalogSpec): Promise<void>
  /** Árbol que usará la suite. Default: `memoryScopeTree()`. */
  makeTree?(): Promise<ContractScopeTree>
  makeDriver(tree: ContractScopeTree): AuthorizationDriver | Promise<AuthorizationDriver>
  cleanup(): Promise<void>
}

/**
 * Catálogo de prueba: roles a nivel app y a nivel organization. Los dos
 * últimos existen solo para el invariante 8: `rank` es metadata y el motor no
 * lo evalúa (un rol de rango alto no concede lo que no tiene).
 */
const CONTRACT_CATALOG: CatalogSpec = {
  permissions: [{ slug: 'docs:read' }, { slug: 'docs:write' }, { slug: 'billing:read' }],
  roles: [
    { slug: 'editor', scopeType: 'app', permissions: ['docs:read', 'docs:write'] },
    { slug: 'viewer', scopeType: 'app', permissions: ['docs:read'] },
    { slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read', 'docs:write'] },
    { slug: 'unit-editor', scopeType: 'unit', permissions: ['docs:write'] },
    { slug: 'auditor-senior', scopeType: 'app', rank: 100, permissions: ['billing:read'] },
    { slug: 'scribe', scopeType: 'app', rank: 0, permissions: ['docs:write'] },
    // Mismo slug en dos niveles: `hasRole` con string no debe confundirlos (L0.6).
    { slug: 'owner', scopeType: 'app', permissions: ['billing:read'] },
    { slug: 'owner', scopeType: 'organization', permissions: ['docs:read'] },
  ],
}

function subject(type: string = 'users'): SubjectRef {
  return { type, uuid: uuidv7() }
}

function orgScope(uuid: string = uuidv7()): ScopeRef {
  return { type: 'organization', uuid }
}

function unitScope(uuid: string = uuidv7()): ScopeRef {
  return { type: 'unit', uuid }
}

/** Una organization nueva, ya colgada del padre en el árbol del harness. */
async function orgUnder(tree: ContractScopeTree, parent: ScopeRef): Promise<ScopeRef> {
  const org = orgScope()
  await tree.attach(org, parent)
  return org
}

/** Una unit nueva, ya colgada del padre en el árbol del harness. */
async function unitUnder(tree: ContractScopeTree, parent: ScopeRef): Promise<ScopeRef> {
  const unit = unitScope()
  await tree.attach(unit, parent)
  return unit
}

function scopeKeys(scopes: ScopeRef[]): string[] {
  return scopes.map((s) => `${s.type}:${s.uuid ?? ''}`).sort()
}

const LEVEL_RANK: Record<ContractLevel, number> = { core: 0, '2.0': 1 }

/**
 * La llamada rechaza con el `status` y el `code` esperados. `assert.rejects`
 * a secas aceptaría cualquier error —un `SqliteError` sin status, un 503 por
 * un 422— y el contrato distingue precisamente esos tres estados.
 */
async function rejectsWith(
  assert: Assert,
  fn: () => Promise<unknown>,
  expected: { status: number; code: string }
): Promise<void> {
  try {
    await fn()
  } catch (error: any) {
    assert.equal(error?.status, expected.status, `status de ${error?.message ?? error}`)
    assert.equal(error?.code, expected.code, `code de ${error?.message ?? error}`)
    return
  }
  assert.fail('debería haber rechazado')
}

/**
 * Lo mínimo que el juez necesita del runner. En producción es el `test` de
 * Japa; en `tests/contract_harness.spec.ts` es una API falsa que solo anota
 * títulos, porque Japa no permite registrar grupos desde un test en marcha y
 * la regla de capacidades hay que poder probarla.
 */
export interface ContractTestApi {
  group(
    title: string,
    define: (group: {
      each: { setup(fn: () => Promise<void>): unknown }
      teardown(fn: () => Promise<void>): unknown
    }) => void
  ): unknown
  test(
    title: string,
    fn: (ctx: { assert: Assert }) => Promise<void>
  ): { timeout(ms: number): unknown } | undefined | void
}

export function runAuthorizationDriverContract(harness: DriverContractHarness) {
  return registerAuthorizationDriverContract(harness, {
    group: (title, define) => test.group(title, define as any),
    test: (title, fn) => test(title, fn as any),
  })
}

export function registerAuthorizationDriverContract(
  harness: DriverContractHarness,
  api: ContractTestApi
) {
  const { test } = api
  const level = harness.level ?? 'core'
  /** Capacidades con par registrado en esta ejecución (ver `caseFor`). */
  const covered = new Set<keyof DriverCapabilities>()

  api.group(`authorization contract [${harness.name} · ${level}]`, (group) => {
    let driver: AuthorizationDriver
    let tree: ContractScopeTree

    /** Registra el caso solo si el harness pidió ese nivel o uno superior. */
    let registered = 0
    const test: ContractTestApi['test'] = (title, fn) => {
      registered += 1
      return api.test(title, fn)
    }
    function since(minLevel: ContractLevel, title: string, fn: Parameters<typeof test>[1]) {
      if (LEVEL_RANK[level] >= LEVEL_RANK[minLevel]) return test(title, fn) ?? undefined
    }

    /**
     * Par de casos de una capacidad: se registra la cara que el harness
     * declara y se anota como cubierta. Una capacidad declarada `true` sin
     * cara `whenTrue` queda sin cubrir y la suite lanza al cerrar el grupo.
     */
    function caseFor(
      capability: keyof DriverCapabilities,
      pair: { whenTrue?: () => void; whenFalse?: () => void }
    ) {
      const side = harness.capabilities[capability] ? pair.whenTrue : pair.whenFalse
      if (!side) return
      // Una capacidad solo cuenta como juzgada si su lado registró al menos
      // un caso: un par que se registra bajo un `since` de nivel superior no
      // cubre nada en un harness `core`, y no debe parecer que sí.
      const before = registered
      side()
      if (registered > before) covered.add(capability)
    }

    group.each.setup(async () => {
      await harness.cleanup()
      await harness.seedCatalog(CONTRACT_CATALOG)
      tree = harness.makeTree ? await harness.makeTree() : memoryScopeTree()
      driver = await harness.makeDriver(tree)
      // `tree.detach` es lo que el consumidor hace al borrar un scope, y el
      // contrato exige que los hechos se purguen (N7/N8): el harness purga
      // PRIMERO (el driver demuestra cero) y quita la arista DESPUÉS (S6).
      // Se parchea el objeto en sitio (no se envuelve) para que el driver,
      // que ya lo tiene, y los casos que parchean `ancestorsOf` vean el mismo.
      const detachEdge = tree.detach.bind(tree)
      tree.detach = async (child) => {
        await driver.purgeScope(child)
        await detachEdge(child)
      }
    })

    group.teardown(async () => {
      await harness.cleanup()
    })

    test('grant de un rol concede sus permisos (authorize true)', async ({ assert }) => {
      const alice = subject()
      await driver.grant(alice, 'editor', APP_SCOPE)
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
      assert.isTrue(await driver.authorize(alice, 'docs:write', APP_SCOPE))
    })

    test('sin asignación → authorize false (denegación por defecto)', async ({ assert }) => {
      assert.isFalse(await driver.authorize(subject(), 'docs:read', APP_SCOPE))
    })

    test('permiso fuera del rol → false; permiso desconocido → false sin throw', async ({
      assert,
    }) => {
      const bob = subject()
      await driver.grant(bob, 'viewer', APP_SCOPE)
      assert.isTrue(await driver.authorize(bob, 'docs:read', APP_SCOPE))
      assert.isFalse(await driver.authorize(bob, 'docs:write', APP_SCOPE))
      assert.isFalse(await driver.authorize(bob, 'no:existe', APP_SCOPE))
    })

    test('revoke retira el permiso', async ({ assert }) => {
      const alice = subject()
      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.revoke(alice, 'editor', APP_SCOPE)
      assert.isFalse(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })

    test('grant de rol inexistente para el scope lanza', async ({ assert }) => {
      await assert.rejects(() => driver.grant(subject(), 'no-existe', APP_SCOPE))
      // org-editor existe pero a nivel organization, no app:
      await assert.rejects(() => driver.grant(subject(), 'org-editor', APP_SCOPE))
    })

    test('deny explícito gana sobre el rol; removeDeny lo restaura', async ({ assert }) => {
      const alice = subject()
      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.deny(alice, 'docs:write', APP_SCOPE)

      assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))
      // El deny es quirúrgico: solo bloquea ese permiso.
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))

      await driver.removeDeny(alice, 'docs:write', APP_SCOPE)
      assert.isTrue(await driver.authorize(alice, 'docs:write', APP_SCOPE))
    })

    test('deny de permiso desconocido lanza (error de programación)', async ({ assert }) => {
      await assert.rejects(() => driver.deny(subject(), 'no:existe', APP_SCOPE))
    })

    test('asignación expirada no concede; expiración futura sí', async ({ assert }) => {
      const past = subject()
      await driver.grant(past, 'editor', APP_SCOPE, {
        expiresAt: new Date(Date.now() - 60_000),
      })
      assert.isFalse(await driver.authorize(past, 'docs:read', APP_SCOPE))

      const future = subject()
      await driver.grant(future, 'editor', APP_SCOPE, {
        expiresAt: new Date(Date.now() + 60_000),
      })
      assert.isTrue(await driver.authorize(future, 'docs:read', APP_SCOPE))
    })

    test('scope aislado: grant en una org NO autoriza en app ni en otra org', async ({
      assert,
    }) => {
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const orgB = await orgUnder(tree, APP_SCOPE)
      await driver.grant(alice, 'org-editor', orgA)

      assert.isTrue(await driver.authorize(alice, 'docs:write', orgA))
      // orgB EXISTE en el árbol: el false es por aislamiento, no por scope desconocido.
      assert.isFalse(await driver.authorize(alice, 'docs:write', orgB))
      assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))
    })

    test('herencia hacia abajo: grant a nivel app autoriza dentro de una org', async ({
      assert,
    }) => {
      const alice = subject()
      const org = await orgUnder(tree, APP_SCOPE)
      await driver.grant(alice, 'editor', APP_SCOPE)
      assert.isTrue(await driver.authorize(alice, 'docs:write', org))
    })

    test('deny en el scope cercano bloquea el grant heredado, solo ahí', async ({ assert }) => {
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const orgB = await orgUnder(tree, APP_SCOPE)
      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.deny(alice, 'docs:write', orgA)

      assert.isFalse(await driver.authorize(alice, 'docs:write', orgA))
      assert.isTrue(await driver.authorize(alice, 'docs:write', orgB))
      assert.isTrue(await driver.authorize(alice, 'docs:write', APP_SCOPE))
    })

    test('holder polimórfico: mismo uuid con distinto type no se cruzan', async ({ assert }) => {
      const uuid = uuidv7()
      const asUser: SubjectRef = { type: 'users', uuid }
      const asAdmin: SubjectRef = { type: 'admins', uuid }
      await driver.grant(asUser, 'editor', APP_SCOPE)

      assert.isTrue(await driver.authorize(asUser, 'docs:read', APP_SCOPE))
      assert.isFalse(await driver.authorize(asAdmin, 'docs:read', APP_SCOPE))
    })

    test('grant duplicado es idempotente (y revive una asignación expirada)', async ({ assert }) => {
      const alice = subject()
      // Primera vez expirada, re-grant sin opciones: debe quedar vigente y única.
      await driver.grant(alice, 'editor', APP_SCOPE, {
        expiresAt: new Date(Date.now() - 60_000),
      })
      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.grant(alice, 'editor', APP_SCOPE)

      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
      const holders = await driver.listSubjects('editor', APP_SCOPE)
      assert.lengthOf(
        holders.filter((h) => h.uuid === alice.uuid),
        1
      )
    })

    test('expiresAt en tres estados: omitido preserva la caducidad vigente, null la quita, expirada revive', async ({
      assert,
    }) => {
      // L0.4. "Asegúrate de que tiene el rol" (un seeder, un onboarding) es
      // un grant SIN opciones, y convertía un acceso temporal en permanente:
      // `expiresAt` omitido se guardaba como NULL. Ahora omitido = no tocar
      // una caducidad vigente; `null` = quitarla explícitamente; y sobre una
      // asignación YA expirada el re-grant revive sin caducidad (es un grant
      // nuevo a todos los efectos). El driver devuelve lo que hizo
      // (`GrantOutcome`), pero lo que se juzga es el hecho: la caducidad
      // preservada vence, la quitada no.
      const keep = subject()
      const lift = subject()
      const revive = subject()
      const soon = new Date(Date.now() + 1_500)

      await driver.grant(keep, 'editor', APP_SCOPE, { expiresAt: soon })
      const kept = await driver.grant(keep, 'editor', APP_SCOPE)

      await driver.grant(lift, 'editor', APP_SCOPE, { expiresAt: soon })
      const lifted = await driver.grant(lift, 'editor', APP_SCOPE, { expiresAt: null })

      const past = new Date(Date.now() - 60_000)
      await driver.grant(revive, 'editor', APP_SCOPE, { expiresAt: past })
      assert.isFalse(await driver.authorize(revive, 'docs:read', APP_SCOPE))
      const revived = await driver.grant(revive, 'editor', APP_SCOPE)

      assert.isTrue(kept.existed)
      assert.closeTo(kept.expiresAt!.getTime(), soon.getTime(), 1_000)
      assert.isTrue(lifted.existed)
      assert.isNull(lifted.expiresAt)
      assert.closeTo(lifted.previousExpiresAt!.getTime(), soon.getTime(), 1_000)
      assert.isTrue(revived.existed)
      assert.isNull(revived.expiresAt)
      assert.closeTo(revived.previousExpiresAt!.getTime(), past.getTime(), 1_000)

      assert.isTrue(await driver.authorize(revive, 'docs:read', APP_SCOPE))
      assert.isTrue(await driver.authorize(keep, 'docs:read', APP_SCOPE))
      assert.isTrue(await driver.authorize(lift, 'docs:read', APP_SCOPE))

      await new Promise((resolve) => setTimeout(resolve, Math.max(0, soon.getTime() - Date.now()) + 300))

      // La caducidad preservada venció; la quitada ya no existe.
      assert.isFalse(await driver.authorize(keep, 'docs:read', APP_SCOPE))
      assert.isTrue(await driver.authorize(lift, 'docs:read', APP_SCOPE))
      assert.isTrue(await driver.authorize(revive, 'docs:read', APP_SCOPE))
    })?.timeout(15_000)

    test('hasRole respeta scope, herencia y expiración', async ({ assert }) => {
      const alice = subject()
      const org = await orgUnder(tree, APP_SCOPE)
      await driver.grant(alice, 'editor', APP_SCOPE)

      assert.isTrue(await driver.hasRole(alice, 'editor', APP_SCOPE))
      // Herencia hacia abajo: el rol de app "vale" dentro de una org.
      assert.isTrue(await driver.hasRole(alice, 'editor', org))
      assert.isFalse(await driver.hasRole(alice, 'viewer', APP_SCOPE))

      await driver.revoke(alice, 'editor', APP_SCOPE)
      assert.isFalse(await driver.hasRole(alice, 'editor', APP_SCOPE))

      const expired = subject()
      await driver.grant(expired, 'editor', APP_SCOPE, {
        expiresAt: new Date(Date.now() - 60_000),
      })
      assert.isFalse(await driver.hasRole(expired, 'editor', APP_SCOPE))
    })

    test('hasRole con el mismo slug en dos niveles: string hereda por cadena; { slug, scopeType } acota el nivel', async ({
      assert,
    }) => {
      // L0.6. `owner` existe a nivel app y a nivel organization. Con string,
      // en cada nivel de la cadena solo cuenta el rol de ESE nivel: el owner
      // de app casa en app y hereda hacia abajo; un owner de organization
      // jamás casa en app. Con `{ slug, scopeType }` se pregunta por el rol
      // de un nivel concreto, y el heredado de otro nivel no vale.
      const bob = subject()
      const carol = subject()
      const org = await orgUnder(tree, APP_SCOPE)
      await driver.grant(bob, 'owner', APP_SCOPE)
      await driver.grant(carol, 'owner', org)

      assert.isTrue(await driver.hasRole(bob, 'owner', org))
      assert.isTrue(await driver.hasRole(bob, { slug: 'owner', scopeType: 'app' }, org))
      assert.isFalse(await driver.hasRole(bob, { slug: 'owner', scopeType: 'organization' }, org))

      assert.isTrue(await driver.hasRole(carol, 'owner', org))
      assert.isTrue(await driver.hasRole(carol, { slug: 'owner', scopeType: 'organization' }, org))
      assert.isFalse(await driver.hasRole(carol, { slug: 'owner', scopeType: 'app' }, org))
      assert.isFalse(await driver.hasRole(carol, 'owner', APP_SCOPE))
      assert.isFalse(await driver.hasRole(carol, { slug: 'owner', scopeType: 'organization' }, APP_SCOPE))
    })

    test('un deny NO afecta a hasRole: es membresía, no acceso', async ({ assert }) => {
      // L0.6, fijado a propósito. `hasRole` responde "¿tiene el rol?", un hecho;
      // el deny gobierna `authorize`, la decisión. Por eso ningún PEP del
      // paquete acepta `role`: un middleware sobre `hasRole` sería indenegable.
      const alice = subject()
      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.deny(alice, 'docs:read', APP_SCOPE)
      await driver.deny(alice, 'docs:write', APP_SCOPE)

      assert.isFalse(await driver.authorize(alice, 'docs:read', APP_SCOPE))
      assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))
      assert.isTrue(await driver.hasRole(alice, 'editor', APP_SCOPE))
    })

    test('listSubjects: holders vigentes del rol en el scope exacto', async ({ assert }) => {
      const alice = subject()
      const bob = subject()
      const expired = subject()
      const otherScope = await orgUnder(tree, APP_SCOPE)

      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.grant(bob, 'editor', APP_SCOPE)
      await driver.grant(expired, 'editor', APP_SCOPE, {
        expiresAt: new Date(Date.now() - 60_000),
      })
      await driver.grant(subject(), 'org-editor', otherScope)

      // Igualdad de CONJUNTO, no inclusión: un driver que devolviera de más
      // (el expirado, el holder de la otra org) pasaría con `includeMembers`.
      const holders = await driver.listSubjects('editor', APP_SCOPE)
      assert.deepEqual(holders.map((h) => h.uuid).sort(), [alice.uuid, bob.uuid].sort())
    })

    test('listScopes: scopes directos que conceden el permiso, sin los denegados', async ({
      assert,
    }) => {
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const orgB = await orgUnder(tree, APP_SCOPE)
      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.grant(alice, 'org-editor', orgA)
      await driver.grant(alice, 'org-editor', orgB)
      await driver.deny(alice, 'docs:write', orgB)

      // Conjunto exacto: ni orgB (denegada) ni nada heredado.
      const scopes = await driver.listScopes(alice, 'docs:write')
      assert.deepEqual(scopeKeys(scopes), scopeKeys([APP_SCOPE, orgA]))
    })

    test('revoke/removeDeny inexistentes son no-ops seguros', async ({ assert }) => {
      const ghost = subject()
      await driver.revoke(ghost, 'editor', APP_SCOPE)
      await driver.removeDeny(ghost, 'docs:read', APP_SCOPE)
      assert.isFalse(await driver.authorize(ghost, 'docs:read', APP_SCOPE))
    })

    test('revoke/removeDeny con rol o permiso fuera del catálogo ⇒ 422, como grant/deny', async ({
      assert,
    }) => {
      // D10 (auditor H9/N4). Un rol que no existe para ese nivel no es "nada
      // que quitar": es una pregunta mal formada, igual que en `grant`. El
      // no-op silencioso escondía el caso real (el `scope_type` de un rol
      // cambió en el catálogo y el revoke no quitaba nada) y además
      // divergía entre drivers. El no-op sigue siendo para una ASIGNACIÓN
      // inexistente de un rol válido ("revoke/removeDeny inexistentes son
      // no-ops seguros").
      const alice = subject()
      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.deny(alice, 'docs:read', APP_SCOPE)

      await rejectsWith(assert, () => driver.revoke(alice, 'no-existe', APP_SCOPE), {
        status: 422,
        code: 'E_AUTHZ_UNKNOWN_ROLE',
      })
      // `org-editor` existe, pero no a nivel app.
      await rejectsWith(assert, () => driver.revoke(alice, 'org-editor', APP_SCOPE), {
        status: 422,
        code: 'E_AUTHZ_UNKNOWN_ROLE',
      })
      await rejectsWith(assert, () => driver.removeDeny(alice, 'no:existe', APP_SCOPE), {
        status: 422,
        code: 'E_AUTHZ_UNKNOWN_PERMISSION',
      })
      // Nada de lo anterior tocó los hechos.
      assert.isTrue(await driver.hasRole(alice, 'editor', APP_SCOPE))
      assert.isFalse(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })

    test('listRoles: roles directos vigentes en el scope exacto', async ({ assert }) => {
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.grant(alice, 'viewer', APP_SCOPE, {
        expiresAt: new Date(Date.now() - 60_000), // expirado: no cuenta
      })
      await driver.grant(alice, 'org-editor', orgA)

      const appRoles = await driver.listRoles(alice, APP_SCOPE)
      assert.deepEqual(appRoles.sort(), ['editor'])

      // El scope exacto manda: en la org NO aparece el rol de app (eso es
      // herencia de authorize/hasRole, no membresía directa).
      const orgRoles = await driver.listRoles(alice, orgA)
      assert.deepEqual(orgRoles, ['org-editor'])

      assert.deepEqual(await driver.listRoles(subject(), APP_SCOPE), [])
    })

    test('listRoleScopes: scopes del tipo con algún rol directo vigente', async ({ assert }) => {
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const orgB = await orgUnder(tree, APP_SCOPE)
      await driver.grant(alice, 'org-editor', orgA)
      await driver.grant(alice, 'org-editor', orgB, {
        expiresAt: new Date(Date.now() - 60_000), // expirado: fuera
      })
      await driver.grant(alice, 'editor', APP_SCOPE)

      const orgs = await driver.listRoleScopes(alice, 'organization')
      assert.deepEqual(
        orgs.map((s) => s.uuid),
        [orgA.uuid]
      )
      // El tipo filtra: el grant a nivel app no aparece como organization.
      const apps = await driver.listRoleScopes(alice, 'app')
      assert.lengthOf(apps, 1)
      assert.isNull(apps[0].uuid)
    })

    test('rank es metadata: un rol de rango alto no concede lo que no tiene', async ({
      assert,
    }) => {
      // Invariante 8 (core). La policy "no puedes dar un rol de rango ≥ al
      // tuyo" es del consumidor; el motor jamás usa `rank` para decidir.
      const senior = subject()
      await driver.grant(senior, 'auditor-senior', APP_SCOPE) // rank 100, sin docs:write
      assert.isFalse(await driver.authorize(senior, 'docs:write', APP_SCOPE))

      const junior = subject()
      await driver.grant(junior, 'scribe', APP_SCOPE) // rank 0, con docs:write
      assert.isTrue(await driver.authorize(junior, 'docs:write', APP_SCOPE))
    })

    test('deny repetido no se duplica: un solo removeDeny lo levanta', async ({ assert }) => {
      // Invariante 6 (core). Un deny duplicado que necesitara dos removeDeny
      // dejaría al holder bloqueado "sin motivo" tras levantarlo una vez.
      const alice = subject()
      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.deny(alice, 'docs:write', APP_SCOPE)
      await driver.deny(alice, 'docs:write', APP_SCOPE)
      assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))

      await driver.removeDeny(alice, 'docs:write', APP_SCOPE)

      assert.isTrue(await driver.authorize(alice, 'docs:write', APP_SCOPE))
    })

    test('deny antes del grant también bloquea: el orden de escritura no importa', async ({
      assert,
    }) => {
      const alice = subject()
      await driver.deny(alice, 'docs:write', APP_SCOPE)
      await driver.grant(alice, 'editor', APP_SCOPE)
      assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })

    test('identidad inválida ⇒ 422 E_AUTHZ_INVALID_IDENTITY, en lecturas y escrituras', async ({
      assert,
    }) => {
      // Invariante 5 (core, L0.5). Un uuid ausente, vacío o con sintaxis de
      // otro sistema (`#` fabrica un userset en FGA; la comilla es SQL) no es
      // "un holder sin permisos": es una pregunta mal formada. Se rechaza
      // ANTES de tocar catálogo o backend, con el mismo status en todo driver
      // — hoy openfga escribía `user:undefined` y database persistía la comilla.
      const invalidUuids: unknown[] = ['', undefined, 'x#y', "x' OR '1'='1", 'a b', 'u|v', 'w*']
      for (const uuid of invalidUuids) {
        const holder = { type: 'users', uuid } as SubjectRef
        const expected = { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }
        await rejectsWith(assert, () => driver.grant(holder, 'editor', APP_SCOPE), expected)
        await rejectsWith(assert, () => driver.authorize(holder, 'docs:read', APP_SCOPE), expected)
        await rejectsWith(assert, () => driver.deny(holder, 'docs:read', APP_SCOPE), expected)
      }
      // El tipo también es identidad, y va en minúsculas: en un motor SQL con
      // collation `*_ci` `Users` y `users` serían la misma fila y en FGA dos
      // holders distintos (E4, auditor H14).
      for (const type of ['users#x', 'Users', 'USERS']) {
        await rejectsWith(
          assert,
          () => driver.grant({ type, uuid: uuidv7() }, 'editor', APP_SCOPE),
          { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }
        )
      }
      await rejectsWith(
        assert,
        () => driver.authorize(subject(), 'docs:read', { type: 'Organization', uuid: uuidv7() }),
        { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }
      )
      // Caso negativo: el ':' de un permiso es gramática válida, no identidad rota.
      assert.isFalse(await driver.authorize(subject(), 'docs:read', APP_SCOPE))
    })

    test('expiresAt que no es Date válida, null ni omitido ⇒ 422 E_AUTHZ_INVALID_IDENTITY, sin escribir', async ({
      assert,
    }) => {
      // D7 (CR7). Una cadena ('2026-12-31'), un `Invalid Date` o un número no
      // son una caducidad: un driver lanzaba un TypeError crudo al serializar
      // y el otro persistía basura (una fecha inválida que nunca "vence" o que
      // vence siempre). Es una pregunta mal formada: 422 antes de tocar nada.
      const alice = subject()
      const expected = { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }
      for (const expiresAt of ['2026-12-31', new Date('x'), 123, {}]) {
        await rejectsWith(
          assert,
          () => driver.grant(alice, 'editor', APP_SCOPE, { expiresAt: expiresAt as any }),
          expected
        )
      }
      assert.deepEqual(await driver.listRoles(alice, APP_SCOPE), [])
      assert.isFalse(await driver.authorize(alice, 'docs:read', APP_SCOPE))
      // Los tres estados legales siguen siéndolo.
      await driver.grant(alice, 'editor', APP_SCOPE, { expiresAt: new Date(Date.now() + 60_000) })
      await driver.grant(alice, 'editor', APP_SCOPE, { expiresAt: null })
      await driver.grant(alice, 'editor', APP_SCOPE)
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })

    test('un RoleQuery objeto donde el contrato pide un slug ⇒ 422 E_AUTHZ_INVALID_SLUG', async ({
      assert,
    }) => {
      // D11 (auditor H4). Solo `hasRole` acepta `{ slug, scopeType }`. Pasar
      // el objeto a `grant`/`revoke`/`listSubjects` (un body sin tipar, un
      // job) acababa en un 503 en un driver y en un TypeError crudo en el
      // otro: un bug de programación disfrazado de caída. Es una pregunta mal
      // formada: 422, antes de tocar nada.
      const alice = subject()
      const query = { slug: 'editor', scopeType: 'app' } as unknown as string
      const expected = { status: 422, code: 'E_AUTHZ_INVALID_SLUG' }
      await rejectsWith(assert, () => driver.grant(alice, query, APP_SCOPE), expected)
      await rejectsWith(assert, () => driver.revoke(alice, query, APP_SCOPE), expected)
      await rejectsWith(assert, () => driver.listSubjects(query, APP_SCOPE), expected)
      assert.deepEqual(await driver.listRoles(alice, APP_SCOPE), [])
      // Y donde sí vale, sigue valiendo.
      assert.isFalse(await driver.hasRole(alice, { slug: 'editor', scopeType: 'app' }, APP_SCOPE))
    })

    test('scope app con uuid ⇒ 422; no concede nada ni en la raíz', async ({ assert }) => {
      // L0.10. `app` es la raíz: `{ app, 'X' }` no es "otro app". Un driver lo
      // colapsaba a la raíz global (escalada de tenant a plataforma) y el otro
      // respondía false: la divergencia es peor que cualquiera de las dos.
      const alice = subject()
      const fakeApp = { type: 'app', uuid: uuidv7() }
      const expected = { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }
      await rejectsWith(assert, () => driver.grant(alice, 'editor', fakeApp), expected)
      await rejectsWith(assert, () => driver.authorize(alice, 'docs:read', fakeApp), expected)
      await rejectsWith(assert, () => driver.deny(alice, 'docs:read', fakeApp), expected)
      await rejectsWith(assert, () => driver.listRoles(alice, fakeApp), expected)

      assert.isFalse(await driver.authorize(alice, 'docs:read', APP_SCOPE))
      assert.deepEqual(await driver.listRoles(alice, APP_SCOPE), [])
    })

    test('uuid centinela de la raíz en un scope que no es app ⇒ 422', async ({ assert }) => {
      // L0.15. `00000000-…` es cómo el driver database almacena la raíz; como
      // identidad de una organization colisionaría con ella.
      const alice = subject()
      const sentinel = { type: 'organization', uuid: '00000000-0000-0000-0000-000000000000' }
      const expected = { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }
      await rejectsWith(assert, () => driver.grant(alice, 'org-editor', sentinel), expected)
      await rejectsWith(assert, () => driver.authorize(alice, 'docs:read', sentinel), expected)
    })

    test('uuid centinela en un scope que el árbol SÍ conoce ⇒ 422 E_AUTHZ_INVALID_IDENTITY, y la raíz sigue limpia', async ({
      assert,
    }) => {
      // Tester H1 (E3). El caso anterior no discrimina por sí solo: sin la
      // regla, el árbol del harness no conoce ese scope y B1 lo rechazaría
      // igual con `E_AUTHZ_UNKNOWN_SCOPE`. El peligro real es un centinela
      // que el árbol conoce: en `database` colisionaría con la fila de la
      // raíz (un grant ahí concedería en `app`). Aquí se cuelga del árbol y
      // debe seguir siendo identidad inválida, no un scope válido.
      const alice = subject()
      const sentinel = { type: 'organization', uuid: '00000000-0000-0000-0000-000000000000' }
      await tree.attach(sentinel, APP_SCOPE)
      const expected = { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }
      await rejectsWith(assert, () => driver.grant(alice, 'org-editor', sentinel), expected)
      await rejectsWith(assert, () => driver.deny(alice, 'docs:read', sentinel), expected)
      await rejectsWith(assert, () => driver.authorize(alice, 'docs:read', sentinel), expected)
      await rejectsWith(assert, () => driver.listRoles(alice, sentinel), expected)
      assert.isFalse(await driver.authorize(alice, 'docs:read', APP_SCOPE))
      assert.deepEqual(await driver.listRoles(alice, APP_SCOPE), [])
      assert.deepEqual(await driver.listRoleScopes(alice, 'app'), [])
    })

    test('slug mal formado o reservado ⇒ 422 E_AUTHZ_INVALID_SLUG; nunca alcanza otro permiso', async ({
      assert,
    }) => {
      // L0.8a. En openfga `docs:read` se codifica como `docs~read`: un slug que
      // llegue YA codificado apuntaba al binding del permiso real, y
      // `removeDeny(…, 'docs~read')` levantaba el deny de `docs:read`. Los
      // reservados (`parent`…) y las familias (`can_`…) son nombres del modelo
      // FGA del modo facts: un permiso así invalidaría el modelo entero.
      const alice = subject()
      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.deny(alice, 'docs:read', APP_SCOPE)
      const expected = { status: 422, code: 'E_AUTHZ_INVALID_SLUG' }

      await rejectsWith(assert, () => driver.removeDeny(alice, 'docs~read', APP_SCOPE), expected)
      await rejectsWith(assert, () => driver.deny(alice, 'docs~read', APP_SCOPE), expected)
      // El deny real sigue en pie: nada lo tocó.
      assert.isFalse(await driver.authorize(alice, 'docs:read', APP_SCOPE))

      for (const slug of ['parent', 'assignee', 'can_docs', 'denied_docs', 'permits_x', 'a'.repeat(101), 'Docs', 'x|y', 'x y', '']) {
        await rejectsWith(assert, () => driver.grant(alice, slug, APP_SCOPE), expected)
        await rejectsWith(assert, () => driver.deny(alice, slug, APP_SCOPE), expected)
        await rejectsWith(assert, () => driver.authorize(alice, slug, APP_SCOPE), expected)
      }
      // Un rol no lleva ':'; un permiso sí (una vez).
      await rejectsWith(assert, () => driver.grant(alice, 'org:editor', APP_SCOPE), expected)
      await rejectsWith(assert, () => driver.authorize(alice, 'a:b:c', APP_SCOPE), expected)
    })

    test('scope que el árbol no conoce: authorize/hasRole false; grant/deny 422 E_AUTHZ_UNKNOWN_SCOPE', async ({
      assert,
    }) => {
      // L0.3. Un scope que el consumidor no reconoce (borrado, inventado, o
      // no encontrado por un fallo) no es "un scope que cuelga de app": el
      // fallback plano `[APP_SCOPE]` hacía que un grant de app concediera en
      // un scope inventado y que borrar la unit tirase el deny de su org. Se
      // deniega por defecto y se rechaza escribir sobre él; las operaciones
      // idempotentes (revoke/removeDeny) no lanzan: no hay nada que quitar.
      const alice = subject()
      await driver.grant(alice, 'editor', APP_SCOPE)
      const ghost = orgScope() // nunca colgado del árbol

      assert.isFalse(await driver.authorize(alice, 'docs:read', ghost))
      assert.isFalse(await driver.hasRole(alice, 'editor', ghost))

      const expected = { status: 422, code: 'E_AUTHZ_UNKNOWN_SCOPE' }
      await rejectsWith(assert, () => driver.grant(alice, 'org-editor', ghost), expected)
      await rejectsWith(assert, () => driver.deny(alice, 'docs:read', ghost), expected)

      await driver.revoke(alice, 'org-editor', ghost)
      await driver.removeDeny(alice, 'docs:read', ghost)
      assert.deepEqual(await driver.listRoles(alice, ghost), [])
      // Nada de lo anterior tocó la raíz.
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
    })

    // ── Nivel 2.0 (Fase 0) ──────────────────────────────────────────────
    // Los casos que siguen se registran solo con `level: '2.0'`. Un harness
    // de tercero escrito para 1.x sigue corriendo los 19 de arriba tal cual.
    //
    // N7/N8 (`detach` purga) están abajo; N9 (un ciclo lanza 422 EN EL
    // PAQUETE) vive en el manager (`scopes.attached/moved`) y se prueba en
    // `tests/manager.spec.ts`: el juez habla con el driver, que no ve aristas.
    // Diferido: A1–A6 / B1–B2 — anexo de `hierarchyFacts: true` (Fase 3b).

    since('2.0', 'herencia de dos niveles: grant en app autoriza en una unit bajo una org', async ({
      assert,
    }) => {
      // N1. El resolutor plano de 1.x solo producía cadenas de longitud 2;
      // con el árbol del juez la cadena es unit → org → app.
      const alice = subject()
      const org = await orgUnder(tree, APP_SCOPE)
      const unit = await unitUnder(tree, org)
      await driver.grant(alice, 'editor', APP_SCOPE)

      assert.isTrue(await driver.authorize(alice, 'docs:write', unit))
    })

    since('2.0', 'grant en una org vale en sus units, no en app ni en la org hermana', async ({
      assert,
    }) => {
      // N1b
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const orgB = await orgUnder(tree, APP_SCOPE)
      const unit = await unitUnder(tree, orgA)
      await driver.grant(alice, 'org-editor', orgA)

      assert.isTrue(await driver.authorize(alice, 'docs:write', unit))
      assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))
      assert.isFalse(await driver.authorize(alice, 'docs:write', orgB))
    })

    since('2.0', 'deny en una org hereda a sus units y solo hacia abajo; no toca otros permisos', async ({
      assert,
    }) => {
      // N2
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const orgB = await orgUnder(tree, APP_SCOPE)
      const unit = await unitUnder(tree, orgA)
      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.deny(alice, 'docs:write', orgA)

      assert.isFalse(await driver.authorize(alice, 'docs:write', unit))
      assert.isTrue(await driver.authorize(alice, 'docs:write', orgB))
      assert.isTrue(await driver.authorize(alice, 'docs:write', APP_SCOPE))
      assert.isTrue(await driver.authorize(alice, 'docs:read', unit))
    })

    since('2.0', 'mover una unit fuera de la org donde hay grant le quita el permiso, sin otra escritura', async ({
      assert,
    }) => {
      // N4. Lo único que cambia entre las dos preguntas es el árbol: no hay
      // revoke, ni deny, ni re-grant. Si el driver cacheara la cadena, o
      // dependiera de hechos que `move` no toca, el segundo authorize seguiría
      // en true.
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const orgB = await orgUnder(tree, APP_SCOPE)
      const unit = await unitUnder(tree, orgA)
      await driver.grant(alice, 'org-editor', orgA)
      assert.isTrue(await driver.authorize(alice, 'docs:write', unit))

      await tree.move(unit, orgB)

      assert.isFalse(await driver.authorize(alice, 'docs:write', unit))
      assert.isTrue(await driver.authorize(alice, 'docs:write', orgA))
    })

    since('2.0', 'mover una unit bajo la org donde hay grant le da el permiso', async ({ assert }) => {
      // N5. Sin esta cara positiva, N4 se satisfaría borrándolo todo.
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const orgB = await orgUnder(tree, APP_SCOPE)
      const unit = await unitUnder(tree, orgA)
      await driver.grant(alice, 'org-editor', orgB)
      assert.isFalse(await driver.authorize(alice, 'docs:write', unit))

      await tree.move(unit, orgB)

      assert.isTrue(await driver.authorize(alice, 'docs:write', unit))
    })

    since('2.0', 'mover una unit no afecta a lo heredado de app', async ({ assert }) => {
      // N6
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const orgB = await orgUnder(tree, APP_SCOPE)
      const unit = await unitUnder(tree, orgA)
      await driver.grant(alice, 'editor', APP_SCOPE)
      assert.isTrue(await driver.authorize(alice, 'docs:write', unit))

      await tree.move(unit, orgB)

      assert.isTrue(await driver.authorize(alice, 'docs:write', unit))
    })

    since('2.0', 'con un árbol real los list* siguen sin enumerar descendientes heredados', async ({
      assert,
    }) => {
      // I7set (invariante 7). Con el resolutor plano no había descendientes
      // que enumerar por error; con app → org → unit sí. Igualdad de conjunto:
      // un driver que "ayudara" devolviendo la unit heredada pasaría con
      // `includeMembers`.
      const alice = subject()
      const org = await orgUnder(tree, APP_SCOPE)
      const unit = await unitUnder(tree, org)
      await driver.grant(alice, 'editor', APP_SCOPE)
      assert.isTrue(await driver.authorize(alice, 'docs:write', unit))

      assert.deepEqual(scopeKeys(await driver.listScopes(alice, 'docs:write')), scopeKeys([APP_SCOPE]))
      assert.deepEqual(await driver.listRoles(alice, unit), [])
      assert.deepEqual(await driver.listRoleScopes(alice, 'unit'), [])
      assert.deepEqual(await driver.listRoleScopes(alice, 'organization'), [])
    })

    since('2.0', 'listScopes resta el deny aunque el sujeto tenga más denies de OTROS permisos que el tope del backend (L0.7)', async ({
      assert,
    }) => {
      // L0.7, el único fail-open de L0. El driver openfga pedía TODOS los
      // denies del sujeto con `ListObjects` (tope del servidor, sin señal de
      // corte) y filtraba por permiso en cliente: cuatro denies irrelevantes
      // desplazaban al relevante fuera de la página y `listScopes` devolvía
      // como concedido un scope donde `authorize` responde false. Con el
      // servidor de tope 3 de CI el rojo se ve con cinco denies; contra un
      // servidor por defecto harían falta mil. Los denies de ruido van
      // PRIMERO y en scopes sin grant, para que lo único que pueda fallar
      // sea la resta del deny (no el recuento de bindings). Son 150 (D16):
      // más de una página de `Read` (100), para que un driver que no siga
      // el `continuation_token` también caiga aquí, y no solo en el unitario.
      const alice = subject()
      for (let i = 0; i < 75; i++) {
        const noise = await orgUnder(tree, APP_SCOPE)
        await driver.deny(alice, 'docs:read', noise)
        await driver.deny(alice, 'billing:read', noise)
      }
      const orgA = await orgUnder(tree, APP_SCOPE)
      const orgB = await orgUnder(tree, APP_SCOPE)
      await driver.grant(alice, 'org-editor', orgA)
      await driver.grant(alice, 'org-editor', orgB)
      await driver.deny(alice, 'docs:write', orgB)

      assert.isFalse(await driver.authorize(alice, 'docs:write', orgB))
      const scopes = await driver.listScopes(alice, 'docs:write')
      assert.notInclude(scopeKeys(scopes), scopeKeys([orgB])[0], 'orgB está denegada y se listó como concedida')
      assert.deepEqual(scopeKeys(scopes), scopeKeys([orgA]))
    })?.timeout(60_000)

    since('2.0', 'un scope retirado del árbol deja de responder: deny por defecto, sin herencia implícita de app', async ({
      assert,
    }) => {
      // L0.3, cara del ciclo de vida. Lo único que cambia es el árbol: el
      // grant directo en la org sigue escrito (o purgado, si el harness
      // purga al desconectar — da igual), pero un scope que el árbol ya no
      // conoce no puede resolverse a "cuelga de app" ni a "cuelga de nada":
      // se deniega, y lo heredado de la raíz tampoco llega.
      const alice = subject()
      const bob = subject()
      const org = await orgUnder(tree, APP_SCOPE)
      await driver.grant(alice, 'org-editor', org)
      await driver.grant(bob, 'editor', APP_SCOPE)
      assert.isTrue(await driver.authorize(alice, 'docs:write', org))
      assert.isTrue(await driver.authorize(bob, 'docs:write', org))

      await tree.detach(org)

      assert.isFalse(await driver.authorize(alice, 'docs:write', org))
      assert.isFalse(await driver.hasRole(alice, 'org-editor', org))
      assert.isFalse(await driver.authorize(bob, 'docs:write', org))
      assert.isTrue(await driver.authorize(bob, 'docs:write', APP_SCOPE))
    })

    since('2.0', 'listRoles y listRoleScopes tampoco responden por un scope que el árbol no conoce', async ({
      assert,
    }) => {
      // D8 (CR8). `authorize`/`hasRole` ya aplicaban "scope desconocido ⇒
      // nada" (L0.3); las dos enumeraciones de membresía no: un scope que el
      // consumidor borró sin avisar (sin `scopes.detached`) seguía listando
      // sus roles y apareciendo como scope con membresía. Aquí el árbol deja
      // de conocer la org SIN purgar (el hecho sigue escrito), que es
      // exactamente la situación que L0.3 cierra: lo que el árbol no conoce
      // no existe para el motor.
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const orgB = await orgUnder(tree, APP_SCOPE)
      await driver.grant(alice, 'org-editor', orgA)
      await driver.grant(alice, 'org-editor', orgB)
      assert.deepEqual(await driver.listRoles(alice, orgA), ['org-editor'])
      assert.deepEqual(scopeKeys(await driver.listRoleScopes(alice, 'organization')), scopeKeys([orgA, orgB]))

      const original = tree.ancestorsOf
      const forgotten = `${orgA.type}:${orgA.uuid}`
      tree.ancestorsOf = async (scope) =>
        `${scope.type}:${scope.uuid}` === forgotten ? null : original.call(tree, scope)
      try {
        assert.deepEqual(await driver.listRoles(alice, orgA), [])
        assert.deepEqual(scopeKeys(await driver.listRoleScopes(alice, 'organization')), scopeKeys([orgB]))
        assert.deepEqual(await driver.listRoles(alice, orgB), ['org-editor'])
      } finally {
        tree.ancestorsOf = original
      }
      // El hecho seguía escrito: al volver a conocer el scope, vuelve.
      assert.deepEqual(await driver.listRoles(alice, orgA), ['org-editor'])
    })

    since('2.0', 'quitar un permiso de un rol y re-sincronizar el catálogo lo retira: sin privilegios zombi', async ({
      assert,
    }) => {
      // L0.9 (N1). El sync era solo aditivo: quitar `docs:write` de `editor`
      // en el config no lo quitaba de ningún entorno, para siempre. Ahora el
      // sync poda los vínculos que el spec ya no lista (solo de los roles
      // del spec; nunca borra roles ni permisos). Es un caso del juez porque
      // un driver que proyecte el catálogo (modo facts) tiene que reflejarlo.
      const alice = subject()
      await driver.grant(alice, 'editor', APP_SCOPE)
      assert.isTrue(await driver.authorize(alice, 'docs:write', APP_SCOPE))

      await harness.seedCatalog({
        ...CONTRACT_CATALOG,
        roles: CONTRACT_CATALOG.roles.map((role) =>
          role.slug === 'editor' ? { ...role, permissions: ['docs:read'] } : role
        ),
      })

      assert.isFalse(await driver.authorize(alice, 'docs:write', APP_SCOPE))
      assert.isTrue(await driver.authorize(alice, 'docs:read', APP_SCOPE))
      assert.deepEqual(await driver.listScopes(alice, 'docs:write'), [])
      // El rol sigue asignado: lo que cambió es lo que concede.
      assert.isTrue(await driver.hasRole(alice, 'editor', APP_SCOPE))
    })

    since('2.0', 'detach purga los hechos del scope: nada resucita al volver a colgarlo', async ({
      assert,
    }) => {
      // N7 (N5 del auditor). Borrar un tenant dejaba sus grants y denies
      // vivos para siempre: sin FK (el scope es polimórfico), sin nada en
      // FGA. Con reutilización de uuid, o al re-colgar el nodo, resucitaban.
      // La segunda mitad es la que importa: sin ella "purga" podría ser
      // "desconecta".
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const orgB = await orgUnder(tree, APP_SCOPE)
      const unit = await unitUnder(tree, orgA)
      await driver.grant(alice, 'editor', APP_SCOPE)
      await driver.grant(alice, 'unit-editor', unit)
      await driver.deny(alice, 'docs:read', unit)
      assert.isTrue(await driver.authorize(alice, 'docs:write', unit))
      assert.isFalse(await driver.authorize(alice, 'docs:read', unit))

      await tree.detach(unit)

      assert.deepEqual(await driver.listRoles(alice, unit), [])
      assert.deepEqual(await driver.listRoleScopes(alice, 'unit'), [])
      assert.notInclude(scopeKeys(await driver.listScopes(alice, 'docs:write')), scopeKeys([unit])[0])

      await tree.attach(unit, orgB)

      // Ni el grant ni el deny resucitan: solo queda lo heredado de app.
      assert.deepEqual(await driver.listRoles(alice, unit), [])
      assert.isFalse(await driver.hasRole(alice, 'unit-editor', unit))
      assert.isTrue(await driver.authorize(alice, 'docs:read', unit))
      assert.isTrue(await driver.authorize(alice, 'docs:write', unit))
    })

    since('2.0', 'detach es quirúrgico: los hermanos y el padre conservan sus hechos', async ({
      assert,
    }) => {
      // N8
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const unit1 = await unitUnder(tree, orgA)
      const unit2 = await unitUnder(tree, orgA)
      await driver.grant(alice, 'org-editor', orgA)
      await driver.grant(alice, 'unit-editor', unit1)
      await driver.grant(alice, 'unit-editor', unit2)
      await driver.deny(alice, 'docs:read', unit2)

      await tree.detach(unit1)

      assert.deepEqual(await driver.listRoles(alice, unit2), ['unit-editor'])
      assert.deepEqual(await driver.listRoles(alice, orgA), ['org-editor'])
      assert.deepEqual(scopeKeys(await driver.listRoleScopes(alice, 'unit')), scopeKeys([unit2]))
      assert.isTrue(await driver.authorize(alice, 'docs:write', unit2))
      assert.isFalse(await driver.authorize(alice, 'docs:read', unit2))
      assert.isTrue(await driver.authorize(alice, 'docs:write', orgA))
    })

    // ── Pares de capacidad ──────────────────────────────────────────────
    // `hierarchyFacts: false` → lo observan N1b/N2/N4/N5 (arriba): el driver
    // responde según el árbol que le resuelve el consumidor, y `tree.move`
    // cambia la respuesta sin escritura. `true` llega en Fase 3b.
    // `transactions`, `injectableClock` (Fase 2.5) y `singleCheckAuthorize`
    // (Fase 3b): pares en su fase; hoy solo pueden declararse `false`.

    caseFor('hierarchyFacts', {
      // Con el árbol en manos del consumidor (`resolveAncestors`), el árbol
      // es una dependencia más de cada pregunta: su caída se clasifica como la
      // del backend (503, código propio), nunca como un `false` ni como el
      // error crudo del consumidor. La cara `true` (árbol como hechos del
      // backend, donde el resolutor no participa) llega en Fase 3b.
      whenFalse: () => {
        test('un resolutor de ancestros que lanza ⇒ 503 E_AUTHZ_RESOLVER_FAILED, nunca false', async ({
          assert,
        }) => {
          const alice = subject()
          const org = await orgUnder(tree, APP_SCOPE)
          await driver.grant(alice, 'editor', APP_SCOPE)
          assert.isTrue(await driver.authorize(alice, 'docs:read', org))

          const original = tree.ancestorsOf
          tree.ancestorsOf = async () => {
            throw new Error('el árbol del consumidor está caído')
          }
          try {
            const expected = { status: 503, code: 'E_AUTHZ_RESOLVER_FAILED' }
            await rejectsWith(assert, () => driver.authorize(alice, 'docs:read', org), expected)
            await rejectsWith(assert, () => driver.hasRole(alice, 'editor', org), expected)
          } finally {
            tree.ancestorsOf = original
          }
          assert.isTrue(await driver.authorize(alice, 'docs:read', org))
        })
      },
    })

    caseFor('truncationSignal', {
      // `whenTrue` (el driver señala el truncamiento) no tiene caso: ningún
      // driver del paquete trunca. Declarar `true` deja la capacidad sin
      // cubrir y la suite lanza al cerrar el grupo.
      whenFalse: () =>
        caseFor('exhaustiveLists', {
          // Backend sin tope, o driver que enumera sin tope (`Read` paginado
          // en openfga): la única garantía honesta es que la lista es
          // completa por grande que sea. Contra el OpenFGA de tope 3 de CI
          // este caso es la prueba de que la enumeración no depende del tope.
          whenTrue: () => {
            test('listas exhaustivas: 1.200 asignaciones directas se devuelven enteras', async ({
              assert,
            }) => {
              const alice = subject()
              const orgs: ScopeRef[] = []
              for (let i = 0; i < 1_200; i++) {
                const org = await orgUnder(tree, APP_SCOPE)
                orgs.push(org)
                await driver.grant(alice, 'org-editor', org)
              }

              const scopes = await driver.listScopes(alice, 'docs:write')
              assert.deepEqual(scopeKeys(scopes), scopeKeys(orgs))
              assert.lengthOf(await driver.listRoleScopes(alice, 'organization'), 1_200)
            })?.timeout(60_000)
          },
          // Backend con tope y driver que no lo señala (un driver de
          // terceros): lo único que se puede afirmar es la FRONTERA —
          // exactamente `listMaxResults` asignaciones se devuelven enteras.
          // Con una más el backend truncaría en silencio; eso no se codifica
          // como aceptado, solo se deja de afirmar.
          whenFalse: () => {
            const limit = harness.limits?.listMaxResults
            if (!limit) {
              throw new Error(
                `[contrato ${harness.name}] declara 'exhaustiveLists: false' sin ` +
                  `'limits.listMaxResults': el juez necesita el tope para probar la frontera.`
              )
            }
            test(`frontera del tope: ${limit} asignaciones directas se devuelven enteras`, async ({
              assert,
            }) => {
              const alice = subject()
              const orgs: ScopeRef[] = []
              for (let i = 0; i < limit; i++) {
                const org = await orgUnder(tree, APP_SCOPE)
                orgs.push(org)
                await driver.grant(alice, 'org-editor', org)
              }

              const scopes = await driver.listScopes(alice, 'docs:write')
              assert.deepEqual(scopeKeys(scopes), scopeKeys(orgs))
            })?.timeout(120_000)
          },
        }),
    })
  })

  // Al cerrar el grupo: toda capacidad declarada `true` tiene que haber
  // registrado su par. Es la regla "jamás un skip" hecha ejecutable.
  const uncovered = (Object.keys(harness.capabilities) as (keyof DriverCapabilities)[]).filter(
    (capability) => harness.capabilities[capability] && !covered.has(capability)
  )
  if (uncovered.length) {
    throw new Error(
      `[contrato ${harness.name}] declara ${uncovered.map((c) => `'${c}: true'`).join(', ')} ` +
        `pero el contrato no tiene caso para ese valor todavía. Declara lo observable hoy.`
    )
  }
}
