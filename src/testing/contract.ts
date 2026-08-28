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
 * `truncationSignal` (con `exhaustiveLists`); los demás llegan con su fase, y
 * mientras tanto declararlos `true` hace que la suite lance al registrarse:
 * una promesa sin juez no pasa.
 */
export interface DriverCapabilities {
  /** El driver materializa el árbol como hechos propios (Fase 3b). */
  hierarchyFacts: boolean
  /** Acepta `{ trx }` externa en las escrituras (Fase 2.5). */
  transactions: boolean
  /** Los `list*` lanzan si el backend trunca (L0.7, Fase 1). */
  truncationSignal: boolean
  /** `authorize` = una sola llamada al backend (modo facts, Fase 3b). */
  singleCheckAuthorize: boolean
  /** Acepta `now()` inyectado (Fase 2.5). */
  injectableClock: boolean
  /**
   * Los `list*` devuelven TODO sin tope (backend sin límite de resultados:
   * `database`). Con `false` el harness debe dar `limits.listMaxResults` y
   * el juez prueba la frontera exacta; "más allá del tope" es L0.7 (Fase 1).
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
    { slug: 'auditor-senior', scopeType: 'app', rank: 100, permissions: ['billing:read'] },
    { slug: 'scribe', scopeType: 'app', rank: 0, permissions: ['docs:write'] },
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

    test('grant duplicado es idempotente (y refresca expiresAt)', async ({ assert }) => {
      const alice = subject()
      // Primera vez expirada, re-grant sin expiración: debe quedar vigente y única.
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

    // ── Nivel 2.0 (Fase 0) ──────────────────────────────────────────────
    // Los casos que siguen se registran solo con `level: '2.0'`. Un harness
    // de tercero escrito para 1.x sigue corriendo los 19 de arriba tal cual.
    //
    // Diferidos con su porqué (no hay caso vacío, se añaden en su fase):
    //   N7/N8 — `detach` purga los hechos del subárbol y solo los suyos:
    //           necesita `purgeScope` (Fase 1).
    //   N9    — un ciclo lanza 422 EN EL PAQUETE, sin dejar arista: hoy solo
    //           lo garantiza `memoryScopeTree` (Fase 1).
    //   A1–A6 / B1–B2 — anexo de `hierarchyFacts: true` (Fase 3b).

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

    // ── Pares de capacidad ──────────────────────────────────────────────
    // `hierarchyFacts: false` → lo observan N1b/N2/N4/N5 (arriba): el driver
    // responde según el árbol que le resuelve el consumidor, y `tree.move`
    // cambia la respuesta sin escritura. `true` llega en Fase 3b.
    // `transactions`, `injectableClock` (Fase 2.5) y `singleCheckAuthorize`
    // (Fase 3b): pares en su fase; hoy solo pueden declararse `false`.

    caseFor('truncationSignal', {
      // `whenTrue` (el driver señala el truncamiento) es L0.7, Fase 1. Sin
      // esa cara, declarar `true` deja la capacidad sin cubrir y la suite
      // lanza al cerrar el grupo.
      whenFalse: () =>
        caseFor('exhaustiveLists', {
          // Backend sin tope: la única garantía honesta es que la lista es
          // completa por grande que sea.
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
          // Backend con tope y driver que no lo señala: lo único que se puede
          // afirmar hoy es la FRONTERA — exactamente `listMaxResults`
          // asignaciones se devuelven enteras. Con una más el backend
          // truncaría en silencio: ese es el defecto L0.7 y su par
          // rojo→verde llega en Fase 1; no se codifica como aceptado.
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
