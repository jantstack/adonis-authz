import '@japa/assert'
import type { Assert } from '@japa/assert'
import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import type {
  AuthorizationDriver,
  CatalogRole,
  CatalogSpec,
  ExcludedSubtree,
  GrantOutcome,
  ScopeRef,
  SubjectRef,
} from '../types.js'
import { APP_SCOPE } from '../types.js'
import { AuthorizationManager } from '../manager.js'
import db from '@adonisjs/lucid/services/db'
import { CatalogCache, GLOBAL_OWNER_KEY, withAuthzCatalogWrite } from '../catalog_cache.js'
import { scopeKey } from '../identity.js'
import type { AuthorizationConfig } from '../define_config.js'
import { descendantsFrom, memoryScopeTree, resolveChainFrom } from './scope_tree.js'
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
 *     makeDriver: (tree) => new MiDriver({ resolveChain: ... }), // recibe el árbol
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
 * `resolveChain` que lo camina, o hechos en el backend). Así el
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
  /**
   * El driver acepta un reloj inyectado (2.5 · J1): `withClock(now)` en el
   * puerto devuelve una vista que evalúa la caducidad con ESE `now` (SQL,
   * `current_time` de FGA, filtros en cliente y los tres estados del
   * re-grant). Con `true` el juez fija el instante y observa la caducidad
   * exacta (T−1 ms concede, T no) sin dormir; con `false` solo puede
   * observarla en tiempo real (el caso de los tres estados espera 1,5 s).
   */
  injectableClock: boolean
  /**
   * Los `list*` devuelven TODO sin tope. Es la verdad de los dos drivers del
   * paquete: `database` (SQL sin límite) y `openfga` (enumeración por `Read`
   * paginado, L0.7). Con `false` el harness debe dar `limits.listMaxResults`
   * y el juez prueba solo la frontera exacta: es la declaración honesta de
   * un driver de terceros cuyo backend trunca y que no lo señala.
   */
  exhaustiveLists: boolean
  /**
   * El driver implementa el método opcional `listDenies` (2.1). Solo tiene
   * casos en `level: '2.1'` (2E · I5): con `true` se juzgan `listDenies`,
   * `effectivePermissions`, `authorizedScopes` y la versión compartida del
   * catálogo; con `false` se juzga que esas primitivas lo digan (500
   * `E_AUTHZ_UNSUPPORTED` nombrándolo) en vez de simular «sin denies». En un
   * harness `core`/`'2.0'` no hay caso que lo observe: declara `false`.
   */
  listDenies: boolean
  /**
   * `purgeRole(roleUuid)` está implementado de verdad (3B · B4): revoca
   * todas las asignaciones del rol en todos los scopes, borra sus vínculos
   * y el rol, atómicamente, y recrear el slug no revive nada. Solo tiene
   * casos en `level: '2.2'`: con `true` se juzga la purga; con `false` se
   * juzga que el driver lo DIGA (500 `E_AUTHZ_UNSUPPORTED`) y que no deje
   * nada a medias — el driver `openfga` del paquete hasta 3b (`facts` +
   * `reconcile`): sus bindings no son enumerables por rol sin leer el
   * store entero. En un harness por debajo de `'2.2'` declara `false`.
   */
  purgeRole: boolean
  /**
   * Las escrituras del CATÁLOGO se serializan de verdad en el motor (3E ·
   * R2, tester): dos `defineScopedRole` del mismo `(slug, nivel)` en
   * paralelo terminan con EXACTAMENTE uno confirmado y el otro con 422
   * `E_AUTHZ_CATALOG_CONFLICT` — nunca un fallo de backend. Es lo que da el
   * cerrojo sobre la fila de `authz_catalog_version` (3D · M2) en PostgreSQL
   * y MySQL, y es la promesa que el README hace.
   *
   * Con `false` (SQLite, que serializa bloqueando la BASE ENTERA) el juez
   * solo puede exigir lo innegociable: nunca dos ganadores y el perdedor no
   * escribe — su transacción puede morir con `SQLITE_BUSY`, que es un 503
   * legítimo. Declararlo `true` en un motor así convierte un flake en un
   * fallo; declararlo `false` en PG/MySQL deja pasar un mutante que
   * convierte la colisión en 503. Solo tiene casos en `level: '2.2'`.
   */
  serializedCatalogWrites: boolean
}

export type ContractLevel = 'core' | '2.0' | '2.1' | '2.2'

export interface DriverContractHarness {
  name: string
  /** `core` (default): los casos de 1.x. `'2.0'`: además los de la Fase 0/1. `'2.1'`: además las primitivas de la Fase 2. `'2.2'`: además los roles locales a un scope (Fase 3). */
  level?: ContractLevel
  capabilities: DriverCapabilities
  /** Tope de resultados del backend de test. Obligatorio con `exhaustiveLists: false`. */
  limits?: { listMaxResults?: number }
  /**
   * Materializa el catálogo del juez. Devuelve lo que quiera (3E: el
   * `syncAuthzCatalog` del paquete devuelve su reporte): el juez no lo mira.
   */
  seedCatalog(catalog: CatalogSpec): Promise<unknown>
  /** Árbol que usará la suite. Default: `memoryScopeTree()`. */
  makeTree?(): Promise<ContractScopeTree>
  makeDriver(tree: ContractScopeTree): AuthorizationDriver | Promise<AuthorizationDriver>
  /**
   * OTRA instancia del driver sobre el MISMO backend de hechos y con su
   * propio memo del catálogo — lo que sería el mismo driver en otro proceso
   * (2D · F1). Default: si el driver expone `catalog` (`CatalogCache`, los
   * dos del paquete), una vista por prototipo con un memo nuevo; si no, el
   * mismo driver (un driver que lea el catálogo en vivo pasa igual).
   */
  makeTwin?(driver: AuthorizationDriver, tree: ContractScopeTree): AuthorizationDriver | Promise<AuthorizationDriver>
  cleanup(): Promise<void>
}

/**
 * Catálogo de prueba: roles a nivel app y a nivel organization. Los dos
 * últimos existen solo para el invariante 8: `rank` es metadata y el motor no
 * lo evalúa (un rol de rango alto no concede lo que no tiene).
 */
const CONTRACT_CATALOG: CatalogSpec = {
  permissions: [
    { slug: 'docs:read' },
    { slug: 'docs:write' },
    { slug: 'billing:read' },
    // 3B · B5: solo los roles de app y organization pueden llevarlo (composición).
    { slug: 'org:settings', assignableAt: ['app', 'organization'] },
  ],
  roles: [
    { slug: 'editor', scopeType: 'app', permissions: ['docs:read', 'docs:write'] },
    // 3B: el administrador de una organization (rank 50) es quien delega roles locales.
    { slug: 'org-admin', scopeType: 'organization', rank: 50, permissions: ['docs:read', 'docs:write', 'billing:read', 'org:settings'] },
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

/**
 * El mismo driver con OTRO memo del catálogo (2D · F1): una vista por
 * prototipo cuyo `catalog` es un `CatalogCache` nuevo. Todo lo demás
 * (cliente, conexión, resolutor) es el del original. Para un driver sin
 * `catalog` no hay memo que separar: se devuelve tal cual.
 */
function twinOf(driver: AuthorizationDriver): AuthorizationDriver {
  const catalog = (driver as { catalog?: unknown }).catalog
  if (!(catalog instanceof CatalogCache)) return driver
  const twin = Object.create(driver)
  Object.defineProperty(twin, 'catalog', { value: new CatalogCache(), enumerable: true })
  return twin
}

/**
 * Lo que un sync de otro proceso deja en la base al quitar un permiso de un
 * rol: el vínculo ya no está y la versión compartida subió, en UNA
 * transacción con el bump como última sentencia (`withAuthzCatalogWrite`, 2E
 * · H2). Ninguna señal en memoria: es exactamente lo que cruza procesos.
 */
async function withoutLink(role: string, scopeType: string, permission: string): Promise<void> {
  await withAuthzCatalogWrite(async (trx) => {
    const roleRow: any = (
      await trx.from('authz_roles').where('slug', role).where('scope_type', scopeType).where('owner_scope_key', GLOBAL_OWNER_KEY).select('uuid')
    )[0]
    const permRow: any = (await trx.from('authz_permissions').where('slug', permission).select('uuid'))[0]
    await trx.from('authz_role_permissions').where('role_uuid', roleRow.uuid).where('permission_uuid', permRow.uuid).delete()
  })
}

/**
 * Un rol LOCAL a `owner` escrito directamente en `authz_*` (3B · B2), como
 * lo dejaría `defineScopedRole` en otro proceso: fila con
 * `owner_scope_key = scopeKey(owner)` y sus vínculos, en una transacción con
 * la versión subida al final. Sirve para juzgar al DRIVER (visibilidad por
 * owner) sin pasar por la policy del manager (que se juzga aparte, con
 * `defineScopedRole`). Devuelve el uuid del rol.
 */
async function localRole(
  owner: ScopeRef,
  spec: { slug: string; scopeType: string; permissions: string[]; rank?: number }
): Promise<string> {
  const uuid = uuidv7()
  await withAuthzCatalogWrite(async (trx) => {
    const now = new Date()
    await trx.table('authz_roles').insert({
      uuid,
      slug: spec.slug,
      name: spec.slug,
      scope_type: spec.scopeType,
      rank: spec.rank ?? 0,
      owner_scope_key: scopeKey(owner),
      created_at: now,
      updated_at: now,
    })
    for (const permission of spec.permissions) {
      const permRow: any = (await trx.from('authz_permissions').where('slug', permission).select('uuid'))[0]
      await trx.table('authz_role_permissions').insert({ uuid: uuidv7(), role_uuid: uuid, permission_uuid: permRow.uuid, created_at: now })
    }
  })
  return uuid
}

/**
 * Cambia a mano el NIVEL declarado de un rol (`authz_roles.scope_type`), con
 * la versión subida (3D · N1). Es la forma de observar en LOS DOS drivers la
 * paridad «una asignación cuenta si su rol está declarado para el nivel de
 * ESE scope»: el catálogo siempre es SQL, así que una asignación creada
 * legalmente queda apuntando a un rol de otro nivel sin escribir hechos a
 * mano (que en `openfga` no serían escribibles por el puerto).
 */
async function retypeRole(roleUuid: string, scopeType: string): Promise<void> {
  await withAuthzCatalogWrite(async (trx) => {
    await trx.from('authz_roles').where('uuid', roleUuid).update({ scope_type: scopeType, updated_at: new Date() })
  })
}

/**
 * Los vínculos rol→permiso que quedan en `authz_role_permissions` para ese
 * rol (3E · R7, tester): el «todo o nada» de `purgeRole` lo demostraba el
 * `CASCADE` del ESQUEMA, no el código —un driver que borra la fila del rol y
 * se olvida de los vínculos pasaba el juez—. El catálogo siempre es SQL, en
 * los dos drivers, así que mirarlo aquí no acopla a ninguno.
 */
async function linksOf(roleUuid: string): Promise<number> {
  const rows = await db.from('authz_role_permissions').where('role_uuid', roleUuid).select('uuid')
  return rows.length
}

/**
 * Un rol local escrito SIN subir la versión del catálogo (3E · R2): es lo que
 * ve un escritor cuya foto del memo se tomó antes de que otro proceso
 * confirmara el suyo. Solo la relectura de la BASE dentro de la transacción
 * serializada (3D · M2 b) puede pararlo; el chequeo barato contra el memo no.
 */
async function insertRoleUnseen(spec: { slug: string; scopeType: string; owner: string }): Promise<string> {
  const uuid = uuidv7()
  const now = new Date()
  await db.table('authz_roles').insert({
    uuid,
    slug: spec.slug,
    name: spec.slug,
    scope_type: spec.scopeType,
    rank: 1,
    owner_scope_key: spec.owner,
    created_at: now,
    updated_at: now,
  })
  return uuid
}

/** Las filas de `authz_roles` con ese `(slug, nivel)`, leídas de la base (sin pasar por el memo). */
async function rowsNamed(slug: string, scopeType: string): Promise<unknown[]> {
  return db.from('authz_roles').where('slug', slug).where('scope_type', scopeType).select('uuid')
}

/** El rol local `roleUuid` borrado A MANO (lo que la plataforma tiene que hacer sin `purgeRole`), con la versión subida. */
async function forgetRoleByHand(roleUuid: string): Promise<void> {
  await withAuthzCatalogWrite(async (trx) => {
    await trx.from('authz_role_permissions').where('role_uuid', roleUuid).delete()
    await trx.from('authz_roles').where('uuid', roleUuid).delete()
  })
}

/** Un vínculo rol→permiso escrito a mano (lo que un sync rechazaría), con la versión subida. */
async function linkByHand(roleUuid: string, permission: string): Promise<void> {
  await withAuthzCatalogWrite(async (trx) => {
    const permRow: any = (await trx.from('authz_permissions').where('slug', permission).select('uuid'))[0]
    await trx.table('authz_role_permissions').insert({ uuid: uuidv7(), role_uuid: roleUuid, permission_uuid: permRow.uuid, created_at: new Date() })
  })
}

function subject(type: string = 'users'): SubjectRef {
  return { type, uuid: uuidv7() }
}

/**
 * Reloj controlado del juez (2.5 · J1): un instante fijo que solo se mueve
 * cuando el caso lo dice. Es lo que se inyecta con `driver.withClock(now)` y
 * en `config.clock`: cada pregunta ve exactamente este `Date`.
 */
function fixedClock(start: Date): { now: () => Date; set(at: Date): void; advance(ms: number): void } {
  let current = new Date(start.getTime())
  return {
    now: () => new Date(current.getTime()),
    set: (at) => {
      current = new Date(at.getTime())
    },
    advance: (ms) => {
      current = new Date(current.getTime() + ms)
    },
  }
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

const LEVEL_RANK: Record<ContractLevel, number> = { core: 0, '2.0': 1, '2.1': 2, '2.2': 3 }

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
      // que ya lo tiene, y los casos que parchean `chainOf` vean el mismo.
      const detachEdge = tree.detach.bind(tree)
      tree.detach = async (child) => {
        await driver.purgeScope(child)
        await detachEdge(child)
      }
    })

    group.teardown(async () => {
      await harness.cleanup()
    })

    /**
     * Las primitivas de 2.1 (`within`, `authorizedScopes`, `effectivePermissions`,
     * `authorizeMany`) son COMPOSICIÓN del manager sobre el puerto: el juez
     * las observa a través de un manager construido sobre el driver del
     * harness y el árbol del juez. Un driver que solo implemente el puerto
     * 2.0 pasa por aquí igual; lo que le falte (`listDenies`) se ve como
     * 500 `E_AUTHZ_UNSUPPORTED` en el caso que lo necesita, nunca como skip.
     */
    function managerOver(overrides: Partial<AuthorizationConfig> = {}, over: AuthorizationDriver = driver): AuthorizationManager {
      return new AuthorizationManager({
        default: harness.name,
        drivers: { [harness.name]: () => over },
        scopes: {
          resolveChain: resolveChainFrom(tree),
          descendantsOf: descendantsFrom(tree),
          ...overrides.scopes,
        },
        warnOnOptInSecurity: false,
        ...overrides,
      })
    }

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

    // ── Par de capacidad `injectableClock` (2.5 · J1) ────────────────────
    // L0.4, los tres estados de `expiresAt`: "asegúrate de que tiene el rol"
    // (un seeder, un onboarding) es un grant SIN opciones, y convertía un
    // acceso temporal en permanente: `expiresAt` omitido se guardaba como
    // NULL. Ahora omitido = no tocar una caducidad vigente; `null` = quitarla
    // explícitamente; y sobre una asignación YA expirada el re-grant revive
    // sin caducidad (es un grant nuevo a todos los efectos). El driver
    // devuelve lo que hizo (`GrantOutcome`), pero lo que se juzga es el
    // hecho: la caducidad preservada vence, la quitada no. La cara `true`
    // lo observa con el reloj inyectado (sin dormir y con igualdad EXACTA de
    // instantes); la cara `false` solo puede observarlo en tiempo real.
    caseFor('injectableClock', {
      whenTrue: () => {
        test('expiresAt en tres estados con el reloj inyectado: omitido preserva la caducidad vigente, null la quita, expirada revive; el instante que vence es exacto', async ({
          assert,
        }) => {
          assert.typeOf(driver.withClock, 'function', 'injectableClock: true exige withClock en el puerto')
          // Relativo a hoy (2.5-B · K7): al final se observa el driver SIN
          // reloj, para el que `soon` tiene que seguir siendo futuro — un
          // instante fijo (2030) sería una bomba de relojería en el juez.
          const clock = fixedClock(new Date(Date.now() + 365 * 24 * 3_600_000))
          const clocked = driver.withClock!(clock.now)
          const keep = subject()
          const lift = subject()
          const revive = subject()
          const soon = new Date(clock.now().getTime() + 1_500)

          await clocked.grant(keep, 'editor', APP_SCOPE, { expiresAt: soon })
          const kept = await clocked.grant(keep, 'editor', APP_SCOPE)

          await clocked.grant(lift, 'editor', APP_SCOPE, { expiresAt: soon })
          const lifted = await clocked.grant(lift, 'editor', APP_SCOPE, { expiresAt: null })

          const past = new Date(clock.now().getTime() - 60_000)
          await clocked.grant(revive, 'editor', APP_SCOPE, { expiresAt: past })
          assert.isFalse(await clocked.authorize(revive, 'docs:read', APP_SCOPE))
          const revived = await clocked.grant(revive, 'editor', APP_SCOPE)

          assert.isTrue(kept.existed)
          assert.equal(kept.expiresAt!.getTime(), soon.getTime())
          assert.isTrue(lifted.existed)
          assert.isNull(lifted.expiresAt)
          assert.equal(lifted.previousExpiresAt!.getTime(), soon.getTime())
          assert.isTrue(revived.existed)
          assert.isNull(revived.expiresAt)
          assert.equal(revived.previousExpiresAt!.getTime(), past.getTime())

          assert.isTrue(await clocked.authorize(revive, 'docs:read', APP_SCOPE))
          assert.isTrue(await clocked.authorize(keep, 'docs:read', APP_SCOPE))
          assert.isTrue(await clocked.authorize(lift, 'docs:read', APP_SCOPE))

          // Un milisegundo antes de vencer sigue vigente; en el instante exacto, no.
          clock.set(new Date(soon.getTime() - 1))
          assert.isTrue(await clocked.authorize(keep, 'docs:read', APP_SCOPE))
          clock.set(soon)
          assert.isFalse(await clocked.authorize(keep, 'docs:read', APP_SCOPE))
          assert.isTrue(await clocked.authorize(lift, 'docs:read', APP_SCOPE))
          assert.isTrue(await clocked.authorize(revive, 'docs:read', APP_SCOPE))
          // El driver sin reloj inyectado no se ha tocado: para él (hoy) `soon` —dentro de un año— es futuro.
          assert.isTrue(await driver.authorize(keep, 'docs:read', APP_SCOPE))
        })

        since('2.1', 'caducidad exacta con el reloj inyectado: en T−1 ms concede, en T no, en T+1 ms no —authorize, hasRole y los list*—; la renovación y el revivir se observan sin dormir', async ({
          assert,
        }) => {
          // 2.5 · J1. Antes `whereActive` (SQL) y `checkContext` (FGA) leían
          // `new Date()`: la frontera exacta de la caducidad no era observable
          // sin una ventana de tiempo real. `T` lleva milisegundos a propósito
          // (J3): un motor que trunque a segundos falla aquí.
          const T = new Date('2030-06-15T12:34:56.789Z')
          const clock = fixedClock(new Date(T.getTime() - 60_000))
          const clocked = driver.withClock!(clock.now)
          const alice = subject()
          const org = await orgUnder(tree, APP_SCOPE)
          await clocked.grant(alice, 'editor', APP_SCOPE, { expiresAt: T })

          const observe = async () => ({
            authorize: await clocked.authorize(alice, 'docs:read', org),
            hasRole: await clocked.hasRole(alice, 'editor', org),
            listSubjects: (await clocked.listSubjects('editor', APP_SCOPE)).some((h) => h.uuid === alice.uuid),
            listRoles: await clocked.listRoles(alice, APP_SCOPE),
            listRoleScopes: (await clocked.listRoleScopes(alice, 'app')).length,
            listScopes: (await clocked.listScopes(alice, 'docs:read')).length,
          })
          const alive = { authorize: true, hasRole: true, listSubjects: true, listRoles: ['editor'], listRoleScopes: 1, listScopes: 1 }
          const gone = { authorize: false, hasRole: false, listSubjects: false, listRoles: [], listRoleScopes: 0, listScopes: 0 }

          clock.set(new Date(T.getTime() - 1))
          assert.deepEqual(await observe(), alive, 'T−1 ms')
          clock.set(T)
          assert.deepEqual(await observe(), gone, 'T: el que expira ahora ya no cuenta')
          clock.set(new Date(T.getTime() + 1))
          assert.deepEqual(await observe(), gone, 'T+1 ms')

          // Renovación: un re-grant con caducidad posterior vuelve a conceder hasta ESE instante.
          const T2 = new Date(T.getTime() + 1_000)
          const renewed = await clocked.grant(alice, 'editor', APP_SCOPE, { expiresAt: T2 })
          assert.isTrue(renewed.existed)
          assert.equal(renewed.previousExpiresAt!.getTime(), T.getTime())
          assert.equal(renewed.expiresAt!.getTime(), T2.getTime())
          assert.deepEqual(await observe(), alive, 'renovada en T+1 ms')
          clock.set(new Date(T2.getTime() - 1))
          assert.deepEqual(await observe(), alive, 'T2−1 ms')
          clock.set(T2)
          assert.deepEqual(await observe(), gone, 'T2')
          // Revivir: el re-grant sin opciones sobre una asignación expirada queda sin caducidad.
          const revived = await clocked.grant(alice, 'editor', APP_SCOPE)
          assert.isTrue(revived.existed)
          assert.isNull(revived.expiresAt)
          clock.set(new Date('2099-12-31T23:59:59.999Z'))
          assert.deepEqual(await observe(), alive, 'revivida, sin caducidad')
        })

        since('2.1', 'la caducidad guarda milisegundos: una que vence dentro de 600 ms no se redondea al segundo y lo que se lee es lo que se escribió, al milisegundo', async ({
          assert,
        }) => {
          // 2.5 · J3 (`subSecondExpiry`). En MySQL la columna `timestamp` de
          // knex es TIMESTAMP(0): REDONDEA al segundo (una caducidad de
          // +600 ms se guardaba como +1 s y concedía medio segundo de más).
          // `DATETIME(3)` en el stub y el espejo. Un caso, una afirmación
          // (2.5-B · K15): la de 2040 va aparte para que un motor que falle
          // aquí no la enmascare.
          const T0 = new Date('2030-01-01T00:00:00.000Z')
          const clock = fixedClock(T0)
          const clocked = driver.withClock!(clock.now)
          const alice = subject()
          const soon = new Date(T0.getTime() + 600)

          const first = await clocked.grant(alice, 'editor', APP_SCOPE, { expiresAt: soon })
          assert.equal(first.expiresAt!.getTime(), soon.getTime())
          const reread = await clocked.grant(alice, 'editor', APP_SCOPE)
          assert.equal(reread.previousExpiresAt!.getTime(), soon.getTime(), 'lo que se lee es lo que se escribió, al milisegundo')
          assert.equal(reread.expiresAt!.getTime(), soon.getTime())

          clock.set(new Date(soon.getTime() - 1))
          assert.isTrue(await clocked.authorize(alice, 'docs:read', APP_SCOPE))
          clock.set(soon)
          assert.isFalse(await clocked.authorize(alice, 'docs:read', APP_SCOPE), 'vence a los 600 ms, no al segundo')
          clock.set(new Date(T0.getTime() + 999))
          assert.isFalse(await clocked.authorize(alice, 'docs:read', APP_SCOPE))
          assert.deepEqual(await clocked.listSubjects('editor', APP_SCOPE), [])
        })

        since('2.1', 'la caducidad admite fechas más allá de 2038 (2040) y se escribe estando el reloj en 2040: los sellos de auditoría no son decisiones y no llevan el reloj inyectado', async ({
          assert,
        }) => {
          // 2.5 · J3: MySQL `TIMESTAMP` no admite fechas más allá de
          // 2038-01-19 (un grant hasta 2040 era un 503) ⇒ `expires_at` es
          // `DATETIME(3)`. Y 2.5-B · K5 (CR#4): `created_at` se sellaba con
          // el reloj INYECTADO, así que un `grant` con el reloj en 2040
          // reventaba igual (`TIMESTAMP` sigue siendo `TIMESTAMP` para los
          // sellos). Los sellos son auditoría, no decisiones: llevan el reloj
          // del sistema; lo que decide (`expires_at`) lleva el inyectado.
          const T0 = new Date('2030-01-01T00:00:00.000Z')
          const clock = fixedClock(T0)
          const clocked = driver.withClock!(clock.now)
          const bob = subject()
          const carol = subject()
          const far = new Date('2040-01-01T00:00:00.000Z')

          const long = await clocked.grant(bob, 'editor', APP_SCOPE, { expiresAt: far })
          assert.equal(long.expiresAt!.getTime(), far.getTime())
          assert.isTrue(await clocked.authorize(bob, 'docs:read', APP_SCOPE))
          assert.equal((await clocked.grant(bob, 'editor', APP_SCOPE)).previousExpiresAt!.getTime(), far.getTime())
          clock.set(new Date('2039-12-31T23:59:59.999Z'))
          assert.isTrue(await clocked.authorize(bob, 'docs:read', APP_SCOPE))
          clock.set(far)
          assert.isFalse(await clocked.authorize(bob, 'docs:read', APP_SCOPE))

          // Escribir con el reloj más allá de 2038: grant y deny se sellan igual.
          const later = new Date('2041-06-01T00:00:00.000Z')
          const written = await clocked.grant(carol, 'editor', APP_SCOPE, { expiresAt: later })
          assert.equal(written.expiresAt!.getTime(), later.getTime())
          await clocked.deny(carol, 'docs:write', APP_SCOPE)
          assert.isTrue(await clocked.authorize(carol, 'docs:read', APP_SCOPE))
          assert.isFalse(await clocked.authorize(carol, 'docs:write', APP_SCOPE))
          assert.deepEqual(await clocked.listRoles(carol, APP_SCOPE), ['editor'])
          clock.set(later)
          assert.isFalse(await clocked.authorize(carol, 'docs:read', APP_SCOPE))
        })

        since('2.1', 'el manager expone el reloj (config.clock) y lo comparten sus vistas de forRequest: la misma pregunta cambia de respuesta al mover el reloj, sin escribir nada', async ({
          assert,
        }) => {
          // 2.5 · J1. El consumidor fija el reloj UNA vez (config) y todo lo
          // que pasa por el manager —lecturas directas, vistas por request,
          // `effectivePermissions`, `authorizeMany`— lo usa. El memo de la
          // vista es de ANCESTROS, nunca de decisiones: mover el reloj cambia
          // la respuesta de la misma vista.
          // Relativo a hoy (K7): al final se observa el driver del harness (reloj real), para el que T es futuro.
          const T = new Date(Date.now() + 400 * 24 * 3_600_000 + 3_003)
          const clock = fixedClock(new Date(T.getTime() - 60_000))
          const authz = managerOver({ clock: clock.now })
          const alice = subject()
          const org = await orgUnder(tree, APP_SCOPE)
          await authz.grant(alice, 'editor', APP_SCOPE, { expiresAt: T })
          const view = authz.forRequest()

          clock.set(new Date(T.getTime() - 1))
          assert.isTrue(await authz.authorize(alice, 'docs:read', org))
          assert.isTrue(await view.authorize(alice, 'docs:read', org))
          assert.isTrue(await view.hasRole(alice, 'editor', org))
          assert.deepEqual(await view.listRoles(alice, APP_SCOPE), ['editor'])
          assert.deepEqual(await view.authorizeMany(alice, 'docs:read', [org, APP_SCOPE]), [true, true])
          assert.lengthOf(await view.listSubjects('editor', APP_SCOPE), 1)

          clock.set(T)
          assert.isFalse(await authz.authorize(alice, 'docs:read', org))
          assert.isFalse(await view.authorize(alice, 'docs:read', org))
          assert.isFalse(await view.hasRole(alice, 'editor', org))
          assert.deepEqual(await view.listRoles(alice, APP_SCOPE), [])
          assert.deepEqual(await view.authorizeMany(alice, 'docs:read', [org, APP_SCOPE]), [false, false])
          assert.deepEqual(await view.listSubjects('editor', APP_SCOPE), [])
          // El driver del harness (reloj real) no se ve afectado: para él T es futuro.
          assert.isTrue(await driver.authorize(alice, 'docs:read', org))
        })
      },
      whenFalse: () => {
        test('expiresAt en tres estados: omitido preserva la caducidad vigente, null la quita, expirada revive (observado en tiempo real: sin reloj inyectable)', async ({
          assert,
        }) => {
          assert.notTypeOf((driver as { withClock?: unknown }).withClock, 'function', 'el harness declara injectableClock: false y el driver trae withClock: declara lo observable')
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
      },
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

    test('un RoleQuery mal formado ⇒ 422 antes de tocar nada; las tres formas legales (slug, {slug,scopeType}, {uuid}) valen en grant/revoke/hasRole/listSubjects', async ({
      assert,
    }) => {
      // D11 (auditor H4) reescrito en 3D · M1: desde que `RoleQuery` admite
      // `{ uuid }` en las cuatro rutas, el objeto ya no es «lo que no va
      // aquí» — lo que sigue sin ir es un objeto MAL FORMADO (un body sin
      // tipar, un job). Antes acababa en un 503 en un driver y en un
      // TypeError crudo en el otro; sigue siendo 422, antes de tocar nada.
      const alice = subject()
      const slugError = { status: 422, code: 'E_AUTHZ_INVALID_SLUG' }
      const identityError = { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }
      const malformed: Array<[unknown, { status: number; code: string }]> = [
        [{}, slugError],
        [{ slug: 'Editor', scopeType: 'app' }, slugError],
        [{ slug: 'editor' }, identityError],
        [{ uuid: 'no-es-un-uuid' }, identityError],
        [{ uuid: '01a04dd8-095b-7208-827b-cb90aeee2936', slug: 'editor' }, identityError],
        [42, identityError],
        [null, identityError],
      ]
      for (const [query, expected] of malformed) {
        await rejectsWith(assert, () => driver.grant(alice, query as never, APP_SCOPE), expected)
        await rejectsWith(assert, () => driver.revoke(alice, query as never, APP_SCOPE), expected)
        await rejectsWith(assert, () => driver.listSubjects(query as never, APP_SCOPE), expected)
        await rejectsWith(assert, () => driver.hasRole(alice, query as never, APP_SCOPE), expected)
      }
      assert.deepEqual(await driver.listRoles(alice, APP_SCOPE), [])

      // Y las tres formas legales apuntan al MISMO rol.
      const editor = (await new CatalogCache().view()).role('editor', 'app')!
      await driver.grant(alice, { uuid: editor.uuid }, APP_SCOPE)
      assert.isTrue(await driver.hasRole(alice, 'editor', APP_SCOPE))
      assert.isTrue(await driver.hasRole(alice, { slug: 'editor', scopeType: 'app' }, APP_SCOPE))
      assert.isTrue(await driver.hasRole(alice, { uuid: editor.uuid }, APP_SCOPE))
      assert.deepEqual((await driver.listSubjects({ uuid: editor.uuid }, APP_SCOPE)).map((h) => h.uuid), [alice.uuid])
      assert.deepEqual((await driver.listSubjects({ slug: 'editor', scopeType: 'app' }, APP_SCOPE)).map((h) => h.uuid), [alice.uuid])
      // Un uuid del catálogo que no es de un rol de ESE nivel no existe ahí.
      const orgEditor = (await new CatalogCache().view()).role('org-editor', 'organization')!
      await rejectsWith(assert, () => driver.grant(alice, { uuid: orgEditor.uuid }, APP_SCOPE), {
        status: 422,
        code: 'E_AUTHZ_ROLE_NOT_VISIBLE',
      })
      assert.deepEqual(await driver.listSubjects({ uuid: orgEditor.uuid }, APP_SCOPE), [])
      await driver.revoke(alice, { uuid: editor.uuid }, APP_SCOPE)
      assert.isFalse(await driver.hasRole(alice, 'editor', APP_SCOPE))
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
      // L0.8a. Hasta 2.1 openfga codificaba `docs:read` como `docs~read` en el
      // id del binding: un slug que llegara YA codificado apuntaba al binding
      // del permiso real, y `removeDeny(…, 'docs~read')` levantaba el deny de
      // `docs:read`. Desde 3A (2.2) los ids llevan el uuid del catálogo y no
      // hay escape, pero la gramática sigue rechazando `~`: el caso fija que
      // un slug así nunca alcanza otro permiso, en ningún driver. Los
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

    since('2.1', 'la identidad es una cadena validada por la gramática, no un UUID del motor: ids que no son UUID se aceptan; un uuid con MAYÚSCULAS (holder o scope) es 422 E_AUTHZ_INVALID_IDENTITY antes de tocar nada', async ({
      assert,
    }) => {
      // 2.5 · J3 + 2.5-B · K1. La gramática admite `[a-z0-9._-]{1,36}` y el
      // uuid es del consumidor. PostgreSQL con columnas `uuid` rechazaba
      // 'user-42' con un error de tipo (503) ⇒ columnas `varchar(64)`. MySQL
      // con la collation por defecto (`*_ci`) fundía 'abc' y 'ABC' en la
      // MISMA fila ⇒ `utf8mb4_bin`; y el árbol del consumidor (tipo `uuid`,
      // `*_ci`) seguía fundiéndolos (auditor 🔴 1) ⇒ las mayúsculas en un
      // uuid ya no son identidad: 422 en la puerta, en lecturas y escrituras,
      // para holders y scopes. Un alias por mayúsculas no llega al árbol.
      const lower: SubjectRef = { type: 'users', uuid: 'abc.def_42' }
      const upper: SubjectRef = { type: 'users', uuid: 'ABC.DEF_42' }
      const longest: SubjectRef = { type: 'users', uuid: 'x'.repeat(36) }
      const org = await orgUnder(tree, APP_SCOPE)
      const orgUpper: ScopeRef = { type: 'organization', uuid: org.uuid!.toUpperCase() }
      const invalid = { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }

      await driver.grant(lower, 'viewer', APP_SCOPE)
      await driver.grant(longest, 'editor', APP_SCOPE)
      await driver.grant(lower, 'org-editor', org)
      await driver.deny(lower, 'docs:read', org)
      assert.isTrue(await driver.authorize(lower, 'docs:read', APP_SCOPE))
      assert.isFalse(await driver.authorize(lower, 'docs:read', org), 'el deny en la org gana')
      assert.isTrue(await driver.authorize(lower, 'docs:write', org))
      assert.isTrue(await driver.authorize(longest, 'docs:write', APP_SCOPE))
      assert.deepEqual((await driver.listSubjects('viewer', APP_SCOPE)).map((h) => h.uuid), [lower.uuid], 'el holder, con su uuid exacto')
      assert.deepEqual(await driver.listRoles(lower, org), ['org-editor'])
      assert.deepEqual(scopeKeys(await driver.listRoleScopes(lower, 'organization')), scopeKeys([org]))

      // Mayúsculas en el uuid del HOLDER: 422 en lecturas y escrituras, y nada escrito.
      await rejectsWith(assert, () => driver.grant(upper, 'viewer', APP_SCOPE), invalid)
      await rejectsWith(assert, () => driver.authorize(upper, 'docs:read', APP_SCOPE), invalid)
      await rejectsWith(assert, () => driver.deny(upper, 'docs:read', APP_SCOPE), invalid)
      await rejectsWith(assert, () => driver.hasRole(upper, 'viewer', APP_SCOPE), invalid)
      await rejectsWith(assert, () => driver.listRoles(upper, APP_SCOPE), invalid)
      await rejectsWith(assert, () => driver.revoke(upper, 'viewer', APP_SCOPE), invalid)
      // Mayúsculas en el uuid del SCOPE: lo mismo, aunque el árbol fundiera el alias con la fila.
      await rejectsWith(assert, () => driver.authorize(lower, 'docs:write', orgUpper), invalid)
      await rejectsWith(assert, () => driver.grant(lower, 'org-editor', orgUpper), invalid)
      await rejectsWith(assert, () => driver.deny(lower, 'docs:write', orgUpper), invalid)
      await rejectsWith(assert, () => driver.removeDeny(lower, 'docs:read', orgUpper), invalid)
      await rejectsWith(assert, () => driver.listRoles(lower, orgUpper), invalid)
      await rejectsWith(assert, () => driver.listSubjects('org-editor', orgUpper), invalid)
      await rejectsWith(assert, () => driver.purgeScope(orgUpper), invalid)
      // Nada de lo anterior tocó los hechos.
      assert.isFalse(await driver.authorize(lower, 'docs:read', org))
      assert.deepEqual(await driver.listRoles(lower, org), ['org-editor'])
      assert.deepEqual((await driver.listSubjects('viewer', APP_SCOPE)).map((h) => h.uuid), [lower.uuid])
    })

    since('2.1', 'un alias del uuid del scope (mayúsculas, guiones quitados) jamás evade un deny: o el árbol no lo conoce (false, nada, 422 al escribir) o resuelve al scope canónico (el deny casa y los hechos se escriben bajo la forma canónica)', async ({
      assert,
    }) => {
      // 2.5-B · K1 (auditor 🔴 1). El árbol del consumidor puede fundir formas
      // distintas del mismo id (tipo `uuid` de PG: `BBBB…` = `bbbb…` =
      // `bbbb…` sin guiones; `char(36) *_ci` de MySQL: mayúsculas), pero
      // `authz_*` compara por bytes (J3): la cadena resolvía con el alias, el
      // grant del ancestro aplicaba y el deny —escrito canónico— no casaba.
      // Con el árbol en memoria el alias es simplemente desconocido; con el
      // árbol SQL del harness (`sqlScopeTree`, PG/MySQL) es donde estaba el
      // agujero. Lo que NUNCA puede pasar, con cualquier árbol: `true`.
      const mallory = subject()
      const eve = subject()
      const org = await orgUnder(tree, APP_SCOPE)
      const unit = await unitUnder(tree, org)
      await driver.grant(mallory, 'org-editor', org)
      await driver.deny(mallory, 'docs:read', unit)
      assert.isFalse(await driver.authorize(mallory, 'docs:read', unit), 'precondición: el deny gana con la forma canónica')
      assert.isTrue(await driver.authorize(mallory, 'docs:write', unit))

      // Mayúsculas: identidad inválida en la puerta (K1, defensa en profundidad): ni árbol ni hechos.
      const invalid = { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' }
      for (const uuid of [unit.uuid!.toUpperCase(), unit.uuid!.replaceAll('-', '').toUpperCase()]) {
        const alias: ScopeRef = { type: 'unit', uuid }
        await rejectsWith(assert, () => driver.authorize(mallory, 'docs:read', alias), invalid)
        await rejectsWith(assert, () => driver.grant(eve, 'unit-editor', alias), invalid)
        await rejectsWith(assert, () => driver.deny(eve, 'docs:read', alias), invalid)
      }
      // Sin guiones: gramática válida. O el árbol no lo conoce, o resuelve a
      // la fila canónica (tipo `uuid` de PG); nunca una cadena con el alias.
      const alias: ScopeRef = { type: 'unit', uuid: unit.uuid!.replaceAll('-', '') }
      assert.isFalse(await driver.authorize(mallory, 'docs:read', alias), 'sin guiones: el deny se evade')
      const known = (await tree.chainOf(alias)) !== null
      if (known) {
        // El árbol lo funde con la fila real: la cadena es la canónica y los
        // hechos casan (`docs:write` concede ⇒ el `false` de arriba es el
        // deny canónico, no un scope desconocido).
        assert.isTrue(await driver.authorize(mallory, 'docs:write', alias), 'sin guiones: lo concedido sigue concedido')
        assert.deepEqual(await driver.listRoles(mallory, alias), [], 'sin guiones: los roles directos se leen bajo la forma canónica')
        await driver.grant(eve, 'unit-editor', alias)
        assert.deepEqual(await driver.listRoles(eve, unit), ['unit-editor'], 'sin guiones: el grant sobre el alias queda bajo la forma canónica')
        assert.deepEqual(scopeKeys(await driver.listRoleScopes(eve, 'unit')), scopeKeys([unit]), 'sin guiones: ningún hecho con la forma del alias')
        await driver.revoke(eve, 'unit-editor', alias)
        assert.deepEqual(await driver.listRoles(eve, unit), [], 'sin guiones: revoke sobre el alias quita el hecho canónico')
      } else {
        assert.isFalse(await driver.authorize(mallory, 'docs:write', alias), 'sin guiones: desconocido: nada concede')
        assert.deepEqual(await driver.listRoles(mallory, alias), [], 'sin guiones: desconocido')
        await rejectsWith(assert, () => driver.grant(eve, 'unit-editor', alias), { status: 422, code: 'E_AUTHZ_UNKNOWN_SCOPE' })
      }
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

      const original = tree.chainOf
      const forgotten = `${orgA.type}:${orgA.uuid}`
      tree.chainOf = async (scope) =>
        `${scope.type}:${scope.uuid}` === forgotten ? null : original.call(tree, scope)
      try {
        assert.deepEqual(await driver.listRoles(alice, orgA), [])
        assert.deepEqual(scopeKeys(await driver.listRoleScopes(alice, 'organization')), scopeKeys([orgB]))
        assert.deepEqual(await driver.listRoles(alice, orgB), ['org-editor'])
      } finally {
        tree.chainOf = original
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


    // ── Nivel 2.1 (Fase 2 · Lote 2B: primitivas) ────────────────────────
    // Composición del manager sobre el puerto (ver `managerOver`). Los
    // drivers no cambian de firma; lo que se juzga es que la primitiva
    // responda igual sobre cualquier driver que pase 2.0.

    since('2.1', 'within: grant/deny dentro de la cadena escriben; fuera ⇒ 422 E_AUTHZ_NOT_WITHIN sin escribir; app y el propio scope contienen', async ({
      assert,
    }) => {
      // B1 (tester §5 E · within 1-4). El administrador de la org A concede
      // en una unit: el call-site declara `within: orgA` y el motor comprueba
      // `orgA ∈ chain(unit)` contra el árbol en fresco. Con la unit de B, el
      // uuid es válido y existe: sin `within` el grant habría pasado.
      const authz = managerOver()
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const orgB = await orgUnder(tree, APP_SCOPE)
      const unitA1 = await unitUnder(tree, orgA)
      const unitB1 = await unitUnder(tree, orgB)

      await authz.grant(alice, 'unit-editor', unitA1, { within: orgA })
      await authz.grant(alice, 'unit-editor', unitA1, { within: APP_SCOPE })
      await authz.grant(alice, 'unit-editor', unitA1, { within: unitA1 })
      await authz.deny(alice, 'docs:read', unitA1, { within: orgA })
      assert.isTrue(await driver.authorize(alice, 'docs:write', unitA1))
      assert.isFalse(await driver.authorize(alice, 'docs:read', unitA1))

      const expected = { status: 422, code: 'E_AUTHZ_NOT_WITHIN' }
      await rejectsWith(assert, () => authz.grant(alice, 'unit-editor', unitB1, { within: orgA }), expected)
      await rejectsWith(assert, () => authz.deny(alice, 'docs:write', unitB1, { within: orgA }), expected)
      // Un hermano ni un descendiente contienen: la contención es hacia arriba.
      await rejectsWith(assert, () => authz.grant(alice, 'org-editor', orgA, { within: orgB }), expected)
      await rejectsWith(assert, () => authz.grant(alice, 'org-editor', orgA, { within: unitA1 }), expected)
      await rejectsWith(assert, () => authz.grant(alice, 'editor', APP_SCOPE, { within: orgA }), expected)
      // Nada de lo anterior escribió.
      assert.deepEqual(await driver.listRoles(alice, unitB1), [])
      assert.deepEqual(await driver.listRoles(alice, orgA), [])
      assert.deepEqual(await driver.listRoles(alice, APP_SCOPE), [])
      assert.isFalse(await driver.authorize(alice, 'docs:write', unitB1))
      // Un `within` que el árbol no conoce no contiene nada (422, no false).
      await rejectsWith(assert, () => authz.grant(alice, 'unit-editor', unitA1, { within: orgScope() }), expected)
      // Un scope desconocido sigue siendo E_AUTHZ_UNKNOWN_SCOPE, antes que la contención.
      await rejectsWith(assert, () => authz.grant(alice, 'unit-editor', unitScope(), { within: orgA }), {
        status: 422,
        code: 'E_AUTHZ_UNKNOWN_SCOPE',
      })

      // `isWithin` es la misma pregunta, suelta.
      assert.isTrue(await authz.isWithin(unitA1, orgA))
      assert.isTrue(await authz.isWithin(unitA1, APP_SCOPE))
      assert.isTrue(await authz.isWithin(unitA1, unitA1))
      assert.isTrue(await authz.isWithin(APP_SCOPE, APP_SCOPE))
      assert.isFalse(await authz.isWithin(unitB1, orgA))
      assert.isFalse(await authz.isWithin(orgA, unitA1))
      assert.isFalse(await authz.isWithin(APP_SCOPE, orgA))
      assert.isFalse(await authz.isWithin(unitScope(), orgA))
    })

    since('2.1', 'within en las otras cuatro escrituras: revoke/removeDeny contra el scope, scopes.attached/moved contra el padre, scopes.detached contra el hijo; fuera ⇒ 422 sin escribir', async ({
      assert,
    }) => {
      // 2D · F2 (auditor 2, CR1). `within` solo cubría grant/deny; las demás
      // lo aceptaban en JS y lo ignoraban. Quitar un deny ajeno es conceder;
      // revocar un rol ajeno es sabotear; purgar o recolgar un scope ajeno,
      // lo mismo. Las seis escrituras pasan por la misma barrera.
      const authz = managerOver()
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const orgB = await orgUnder(tree, APP_SCOPE)
      const unitB1 = await unitUnder(tree, orgB)
      await driver.grant(alice, 'unit-editor', unitB1)
      await driver.deny(alice, 'docs:read', unitB1)
      const expected = { status: 422, code: 'E_AUTHZ_NOT_WITHIN' }

      // El "admin de A" apunta a hechos de B.
      await rejectsWith(assert, () => authz.removeDeny(alice, 'docs:read', unitB1, { within: orgA }), expected)
      await rejectsWith(assert, () => authz.revoke(alice, 'unit-editor', unitB1, { within: orgA }), expected)
      assert.isFalse(await driver.authorize(alice, 'docs:read', unitB1), 'el deny sigue')
      assert.deepEqual(await driver.listRoles(alice, unitB1), ['unit-editor'], 'el rol sigue')
      // Dentro de B (o de la raíz, o del propio scope) sí.
      await authz.removeDeny(alice, 'docs:read', unitB1, { within: orgB })
      await authz.revoke(alice, 'unit-editor', unitB1, { within: unitB1 })
      assert.deepEqual(await driver.listRoles(alice, unitB1), [])
      await driver.grant(alice, 'unit-editor', unitB1)
      await authz.revoke(alice, 'unit-editor', unitB1, { within: APP_SCOPE })
      assert.deepEqual(await driver.listRoles(alice, unitB1), [])

      // scopes.attached / moved: el PADRE (nuevo) tiene que estar dentro.
      const unitNew = unitScope()
      const unitB2 = await unitUnder(tree, orgB)
      const unitA1 = await unitUnder(tree, orgA)
      await rejectsWith(assert, () => authz.scopes.attached(unitNew, orgB, { within: orgA }), expected)
      await rejectsWith(assert, () => authz.scopes.attached(unitNew, unitB2, { within: orgA }), expected)
      await rejectsWith(assert, () => authz.scopes.moved(unitB2, orgA, { within: orgB }), expected)
      await authz.scopes.attached(unitNew, unitB2, { within: orgB })
      await authz.scopes.moved(unitA1, orgA, { within: orgA })
      await authz.scopes.moved(unitB2, orgA, { within: APP_SCOPE })

      // scopes.detached: el HIJO tiene que estar dentro; y purga solo si lo está.
      await driver.grant(alice, 'unit-editor', unitB1)
      await rejectsWith(assert, () => authz.scopes.detached(unitB1, { within: orgA }), expected)
      assert.deepEqual(await driver.listRoles(alice, unitB1), ['unit-editor'], 'nada purgado')
      await authz.scopes.detached(unitB1, { within: orgB })
      assert.deepEqual(await driver.listRoles(alice, unitB1), [])
      // Un `within` desconocido no contiene nada; un scope que ya no está en el árbol no se puede contrastar.
      await rejectsWith(assert, () => authz.revoke(alice, 'unit-editor', unitB2, { within: orgScope() }), expected)
      await rejectsWith(assert, () => authz.scopes.detached(unitScope(), { within: orgB }), { status: 422, code: 'E_AUTHZ_UNKNOWN_SCOPE' })
    })

    since('2.1', 'within contrasta también el ORIGEN de scopes.moved/attached: una unit de B no se lleva a A con within: orgA ⇒ 422 E_AUTHZ_NOT_WITHIN sin llamar al driver, y la herencia no cruza', async ({
      assert,
    }) => {
      // 2E · H1 (auditor 1). Solo se contrastaba el DESTINO: el admin de A
      // podía anexionarse `unit:B1` con el `within` de su sesión y, movida,
      // `authorize` pasaba de false a true (heredaba todo el subárbol robado;
      // peor que purgarlo). Ahora la cadena ACTUAL del hijo, resuelta en
      // fresco, también tiene que contener `within` — por eso el consumidor
      // notifica ANTES de recolgar su fila. Espía: cero llamadas al driver.
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const orgB = await orgUnder(tree, APP_SCOPE)
      const unitA1 = await unitUnder(tree, orgA)
      const unitA2 = await unitUnder(tree, orgA)
      const unitB1 = await unitUnder(tree, orgB)
      await driver.grant(alice, 'org-editor', orgA)
      assert.isFalse(await driver.authorize(alice, 'docs:read', unitB1), 'precondición: la unit de B no hereda de A')

      const touched: string[] = []
      const spied: AuthorizationDriver = new Proxy(driver, {
        get: (target, prop, receiver) => {
          const value = Reflect.get(target, prop, receiver)
          if (typeof value === 'function' && typeof prop === 'string') {
            return (...args: unknown[]) => {
              touched.push(prop)
              return value.apply(receiver, args)
            }
          }
          return value
        },
      })
      const authz = managerOver({ requireWithin: 'non-root' }, spied)
      const expected = { status: 422, code: 'E_AUTHZ_NOT_WITHIN' }
      await rejectsWith(assert, () => authz.scopes.moved(unitB1, orgA, { within: orgA }), expected)
      await rejectsWith(assert, () => authz.scopes.attached(unitB1, orgA, { within: orgA }), expected)
      await rejectsWith(assert, () => authz.scopes.attached(unitB1, unitA1, { within: orgA }), expected)
      // Origen dentro y destino fuera sigue siendo 422 (F2): las dos caras.
      await rejectsWith(assert, () => authz.scopes.moved(unitA1, orgB, { within: orgA }), expected)
      // Un hijo que el árbol no conoce no tiene origen que contrastar.
      await rejectsWith(assert, () => authz.scopes.moved(unitScope(), orgA, { within: orgA }), { status: 422, code: 'E_AUTHZ_UNKNOWN_SCOPE' })
      assert.deepEqual(touched, [], 'el driver no se toca cuando la contención falla')
      // El consumidor no movió nada (el paquete rechazó): la herencia sigue sin cruzar.
      assert.isFalse(await driver.authorize(alice, 'docs:read', unitB1))
      assert.deepEqual(await tree.chainOf(unitB1), [unitB1, orgB, APP_SCOPE])

      // Dentro del mismo tenant sí: nodo nuevo bajo A, y una unit de A bajo otra unit de A.
      const unitA3 = unitScope()
      await authz.scopes.attached(unitA3, orgA, { within: orgA })
      await tree.attach(unitA3, orgA)
      await authz.scopes.moved(unitA1, unitA2, { within: orgA })
      await tree.move(unitA1, unitA2)
      assert.isTrue(await driver.authorize(alice, 'docs:read', unitA1))
      // Y la plataforma (sin 'non-root') cruza tenants declarando la raíz: es un movimiento legítimo.
      await managerOver({}, spied).scopes.moved(unitB1, orgA, { within: APP_SCOPE })
      await tree.move(unitB1, orgA)
      assert.isTrue(await driver.authorize(alice, 'docs:read', unitB1))
    })

    since('2.1', "requireWithin: true ⇒ las seis escrituras sin within ⇒ 422 E_AUTHZ_WITHIN_REQUIRED sin escribir; 'non-root' rechaza además within: app; con el default (false) siguen escribiendo", async ({
      assert,
    }) => {
      // B1 (tester 5-6, auditor E2) + 2D · F2 (auditor 2 y 9). La cara
      // negativa prueba que el flag hace algo: con `false` la escritura sin
      // `within` pasa, y ESO es lo que el aviso del manager nombra como
      // opt-in. `'non-root'` cierra el comodín `within: APP_SCOPE`, que
      // satisfacía la regla sin acotar nada.
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const unitA1 = await unitUnder(tree, orgA)
      const strict = managerOver({ requireWithin: true })
      const expected = { status: 422, code: 'E_AUTHZ_WITHIN_REQUIRED' }
      await rejectsWith(assert, () => strict.grant(alice, 'org-editor', orgA), expected)
      await rejectsWith(assert, () => strict.deny(alice, 'docs:read', orgA), expected)
      await rejectsWith(assert, () => strict.grant(alice, 'editor', APP_SCOPE), expected)
      await rejectsWith(assert, () => strict.revoke(alice, 'org-editor', orgA), expected)
      await rejectsWith(assert, () => strict.removeDeny(alice, 'docs:read', orgA), expected)
      await rejectsWith(assert, () => strict.scopes.attached(unitScope(), orgA), expected)
      await rejectsWith(assert, () => strict.scopes.moved(unitA1, orgA), expected)
      await rejectsWith(assert, () => strict.scopes.detached(unitA1), expected)
      assert.deepEqual(await driver.listRoles(alice, orgA), [])
      assert.isFalse(await driver.authorize(alice, 'docs:read', orgA))
      // Con `within` las seis escriben (`APP_SCOPE` vale con `true`).
      await strict.grant(alice, 'org-editor', orgA, { within: orgA })
      await strict.deny(alice, 'docs:write', orgA, { within: APP_SCOPE })
      assert.isTrue(await driver.authorize(alice, 'docs:read', orgA))
      assert.isFalse(await driver.authorize(alice, 'docs:write', orgA))
      await strict.removeDeny(alice, 'docs:write', orgA, { within: orgA })
      assert.isTrue(await driver.authorize(alice, 'docs:write', orgA))
      await strict.revoke(alice, 'org-editor', orgA, { within: orgA })
      assert.isFalse(await driver.authorize(alice, 'docs:read', orgA))
      const unitA2 = unitScope()
      await strict.scopes.attached(unitA2, orgA, { within: orgA })
      await strict.scopes.moved(unitA1, orgA, { within: orgA })
      await driver.grant(alice, 'unit-editor', unitA1)
      await strict.scopes.detached(unitA1, { within: orgA })
      assert.deepEqual(await driver.listRoles(alice, unitA1), [])

      // 'non-root': la raíz como `within` no acota nada ⇒ 422 en las seis.
      const nonRoot = managerOver({ requireWithin: 'non-root' })
      const root = { status: 422, code: 'E_AUTHZ_WITHIN_ROOT_FORBIDDEN' }
      await rejectsWith(assert, () => nonRoot.grant(alice, 'org-editor', orgA, { within: APP_SCOPE }), root)
      await rejectsWith(assert, () => nonRoot.deny(alice, 'docs:read', orgA, { within: APP_SCOPE }), root)
      await rejectsWith(assert, () => nonRoot.revoke(alice, 'org-editor', orgA, { within: APP_SCOPE }), root)
      await rejectsWith(assert, () => nonRoot.removeDeny(alice, 'docs:read', orgA, { within: APP_SCOPE }), root)
      await rejectsWith(assert, () => nonRoot.scopes.attached(unitScope(), orgA, { within: APP_SCOPE }), root)
      await rejectsWith(assert, () => nonRoot.scopes.moved(unitA2, orgA, { within: APP_SCOPE }), root)
      await rejectsWith(assert, () => nonRoot.scopes.detached(unitA2, { within: APP_SCOPE }), root)
      await rejectsWith(assert, () => nonRoot.grant(alice, 'org-editor', orgA), expected)
      assert.deepEqual(await driver.listRoles(alice, orgA), [])
      // Con un tenant declarado, escribe; y en la raíz no se puede escribir por aquí (el driver o una config sin flag).
      await nonRoot.grant(alice, 'org-editor', orgA, { within: orgA })
      assert.isTrue(await driver.authorize(alice, 'docs:read', orgA))
      await rejectsWith(assert, () => nonRoot.grant(alice, 'editor', APP_SCOPE, { within: APP_SCOPE }), root)
      await rejectsWith(assert, () => nonRoot.grant(alice, 'editor', APP_SCOPE, { within: orgA }), { status: 422, code: 'E_AUTHZ_NOT_WITHIN' })
      assert.deepEqual(await driver.listRoles(alice, APP_SCOPE), [])

      const lax = managerOver()
      await lax.revoke(alice, 'org-editor', orgA)
      await lax.grant(alice, 'org-editor', orgA)
      assert.isTrue(await driver.authorize(alice, 'docs:read', orgA))
    })


    since('2.1', 'authorizeMany: idéntico a N authorize por posición (duplicados, desconocidos, denegados); vacío ⇒ [] sin backend ni árbol; un scope que lanza ⇒ lanza entero', async ({
      assert,
    }) => {
      // B6 (tester §5 E · authorizeMany 1-4). Composición por defecto
      // (`Promise.all` de `authorize` sobre una vista memoizada) o el método
      // opcional del driver (openfga: un solo batchCheck correlacionado por
      // id, L0.14): la respuesta tiene que ser la misma. Nunca parcial: si
      // una posición no se puede responder, no se responde ninguna.
      const authz = managerOver()
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const orgB = await orgUnder(tree, APP_SCOPE)
      const unitA1 = await unitUnder(tree, orgA)
      const unitB1 = await unitUnder(tree, orgB)
      const ghost = orgScope()
      await driver.grant(alice, 'org-editor', orgA)
      await driver.grant(alice, 'unit-editor', unitB1)
      await driver.deny(alice, 'docs:write', unitA1)

      const scopes = [APP_SCOPE, orgA, unitA1, orgB, unitB1, ghost, orgA, unitB1]
      const expected = await Promise.all(scopes.map((s) => driver.authorize(alice, 'docs:write', s)))
      assert.deepEqual(expected, [false, true, false, false, true, false, true, true], 'precondición del caso')
      assert.deepEqual(await authz.authorizeMany(alice, 'docs:write', scopes), expected)
      assert.deepEqual(await authz.authorizeMany(alice, 'docs:read', scopes), await Promise.all(scopes.map((s) => driver.authorize(alice, 'docs:read', s))))
      assert.deepEqual(await authz.authorizeMany(alice, 'no:existe', [orgA, unitB1]), [false, false])
      assert.deepEqual(await authz.authorizeMany(subject(), 'docs:write', [orgA, unitB1]), [false, false])

      // Vacío: [] sin tocar el driver ni el árbol.
      const original = tree.chainOf
      let asked = 0
      tree.chainOf = async (scope) => {
        asked += 1
        return original.call(tree, scope)
      }
      // Espía que sobrevive a `withChainResolver` (2D · F7, CR5): con
      // `value.apply(target)` la vista `Object.create(this)` heredaba del
      // driver real, no del Proxy, y la aserción "0 llamadas" era vacía.
      // Con `receiver` la vista hereda del Proxy y sus llamadas se ven.
      const touched: string[] = []
      const spied: AuthorizationDriver = new Proxy(driver, {
        get: (target, prop, receiver) => {
          const value = Reflect.get(target, prop, receiver)
          if (typeof value === 'function' && typeof prop === 'string') {
            return (...args: unknown[]) => {
              touched.push(prop)
              return value.apply(receiver, args)
            }
          }
          return value
        },
      })
      const watched = new AuthorizationManager({
        default: harness.name,
        drivers: { [harness.name]: () => spied },
        scopes: { resolveChain: resolveChainFrom(tree), descendantsOf: descendantsFrom(tree) },
        warnOnOptInSecurity: false,
      })
      try {
        assert.deepEqual(await watched.authorizeMany(alice, 'docs:write', []), [])
        assert.deepEqual(touched, [])
        assert.equal(asked, 0)

        // Un scope cuyo árbol falla: lanza entero (503), no un array parcial.
        tree.chainOf = async (scope) => {
          if (`${scope.type}:${scope.uuid}` === `${unitB1.type}:${unitB1.uuid}`) throw new Error('árbol caído')
          return original.call(tree, scope)
        }
        await rejectsWith(assert, () => watched.authorizeMany(alice, 'docs:write', [orgA, unitB1, orgB]), {
          status: 503,
          code: 'E_AUTHZ_RESOLVER_FAILED',
        })
        // Identidad inválida en cualquier posición: 422 antes de tocar nada.
        touched.length = 0
        await rejectsWith(assert, () => watched.authorizeMany(alice, 'docs:write', [orgA, { type: 'app', uuid: 'X' }]), {
          status: 422,
          code: 'E_AUTHZ_INVALID_IDENTITY',
        })
        assert.deepEqual(touched, [], 'ni withChainResolver ni authorize antes del 422')
        // Y el espía VE lo que pasa por la vista: una llamada válida se cuenta.
        touched.length = 0
        assert.deepEqual(await watched.authorizeMany(alice, 'docs:write', [orgA]), [true])
        assert.isTrue(touched.includes('authorize') || touched.includes('authorizeMany'), `el espía no vio nada: ${touched.join(',')}`)
      } finally {
        tree.chainOf = original
      }
    })


    // ── Concurrencia (2.5 · J4) ──────────────────────────────────────────
    // Sin `{trx}` en el puerto (`transactions: false` sigue; es el diferido
    // 2.6): lo que se fija es que dos escrituras solapadas nunca dejan un
    // estado que ninguna de las dos habría dejado sola. Con el harness en
    // memoria (pool 1) se solapan a nivel de consulta; con `sqlite-file`, PG
    // y MySQL (pool ≥ 2) a nivel de conexión.

    since('2.1', 'dos grant concurrentes con caducidades distintas ⇒ UNA sola asignación y la caducidad final es una de las dos; ninguno falla (o falla con 409, nunca con 500/503)', async ({
      assert,
    }) => {
      // J4 (a). Carrera check-then-insert: ambos ven «no hay nada» y ambos
      // insertan; el unique (centinela incluido) o el «tuple already exists»
      // de FGA detecta al perdedor, que degrada a re-grant sobre lo del
      // ganador. Un duplicado (dos filas), una caducidad inventada o un 503
      // por la carrera romperían el invariante 6.
      const base = Date.now()
      const e1 = new Date(base + 3_600_000)
      const e2 = new Date(base + 7_200_000)
      for (let round = 0; round < 6; round++) {
        const holder = subject()
        const [first, second] = round % 2 === 0 ? [e1, e2] : [e2, e1]
        const settled = await Promise.allSettled([
          driver.grant(holder, 'editor', APP_SCOPE, { expiresAt: first }),
          driver.grant(holder, 'editor', APP_SCOPE, { expiresAt: second }),
        ])
        for (const outcome of settled) {
          if (outcome.status === 'rejected') {
            const error: any = outcome.reason
            assert.equal(error?.status, 409, `ronda ${round}: ${error?.message}`)
            assert.match(String(error?.code), /^E_AUTHZ_/)
          }
        }
        assert.isTrue(settled.some((o) => o.status === 'fulfilled'), `ronda ${round}: al menos un grant escribió`)
        const holders = await driver.listSubjects('editor', APP_SCOPE)
        assert.lengthOf(holders.filter((h) => h.uuid === holder.uuid), 1, `ronda ${round}: una sola asignación`)
        // La caducidad que quedó es una de las dos pedidas, nunca otra ni ninguna.
        const state = await driver.grant(holder, 'editor', APP_SCOPE)
        assert.isTrue(state.existed)
        assert.oneOf(state.previousExpiresAt?.getTime(), [e1.getTime(), e2.getTime()], `ronda ${round}: caducidad final`)
        assert.equal(state.expiresAt?.getTime(), state.previousExpiresAt?.getTime(), 'el re-grant sin opciones no la toca')
        assert.isTrue(await driver.authorize(holder, 'docs:read', APP_SCOPE))
      }
    })?.timeout(60_000)

    since('2.1', 'purgeScope concurrente con grant en el mismo scope ⇒ nunca un estado a medias: o la asignación está entera y concede, o no está; y la purga siguiente demuestra cero', async ({
      assert,
    }) => {
      // J4 (b). La purga borra en transacción (SQL) o borra y relee (FGA);
      // un grant que aterriza en medio queda ENTERO (y el scope sigue en el
      // árbol: es legítimo) o no queda. Lo que no puede pasar: una fila que
      // `listRoles` ve y `authorize` no (o al revés), dos filas, o un error
      // que no sea el «no pude demostrar cero» (500 E_AUTHZ_PURGE_INCOMPLETE)
      // que la purga tiene derecho a lanzar cuando alguien escribe debajo.
      const alice = subject()
      const later = new Date(Date.now() + 3_600_000)
      for (let round = 0; round < 6; round++) {
        const org = await orgUnder(tree, APP_SCOPE)
        await driver.grant(alice, 'org-editor', org)
        await driver.deny(alice, 'docs:read', org)
        const settled = await Promise.allSettled([
          driver.purgeScope(org),
          driver.grant(alice, 'org-editor', org, { expiresAt: later }),
        ])
        const [purge, grant] = settled
        if (purge.status === 'rejected') {
          const error: any = purge.reason
          assert.equal(error?.code, 'E_AUTHZ_PURGE_INCOMPLETE', `ronda ${round}: ${error?.message}`)
        }
        assert.equal(grant.status, 'fulfilled', `ronda ${round}: el grant no falla por la purga (${(grant as any).reason?.message ?? ''})`)
        // Lo que el grant DICE que dejó (K4): la caducidad pedida, siempre;
        // `existed: true` solo si de verdad refrescó una fila que seguía ahí.
        const outcome = (grant as PromiseFulfilledResult<GrantOutcome>).value
        assert.equal(outcome.expiresAt?.getTime(), later.getTime(), `ronda ${round}: el outcome lleva la caducidad pedida`)

        const roles = await driver.listRoles(alice, org)
        assert.include([0, 1], roles.length, `ronda ${round}: cero o una asignación`)
        const present = roles.length === 1
        assert.equal(await driver.hasRole(alice, 'org-editor', org), present, `ronda ${round}: hasRole coherente`)
        assert.equal(await driver.authorize(alice, 'docs:write', org), present, `ronda ${round}: authorize coherente`)
        assert.lengthOf((await driver.listSubjects('org-editor', org)).filter((h) => h.uuid === alice.uuid), roles.length)
        if (present) {
          const state = await driver.grant(alice, 'org-editor', org)
          assert.equal(state.previousExpiresAt?.getTime(), later.getTime(), `ronda ${round}: la que quedó es la del grant concurrente, entera`)
        }
        // Demostrar cero: una purga sin nadie escribiendo debajo deja el scope vacío.
        await driver.purgeScope(org)
        assert.deepEqual(await driver.listRoles(alice, org), [])
        assert.isFalse(await driver.authorize(alice, 'docs:write', org))
        // El deny purgado ya no bloquea, pero tampoco queda grant: denegación por defecto.
        assert.isFalse(await driver.authorize(alice, 'docs:read', org))
      }
    })?.timeout(60_000)

    since('2.1', 'syncAuthzCatalog concurrente con authorize ⇒ nunca una foto mixta permisiva: en cuanto una respuesta ve el permiso retirado, ninguna posterior lo concede (aquí y en otro memo)', async ({
      assert,
    }) => {
      // J4 (c). El memo captura la versión ANTES de leer las tres tablas; un
      // sync que aterriza a mitad de carga deja la foto marcada como vieja y
      // la siguiente pregunta recarga. Una foto mixta solo puede ser MÁS
      // restrictiva (permisos → roles → vínculos), nunca conceder lo que el
      // catálogo nuevo retira. Lo observable: la secuencia de respuestas es
      // monótona (true… false…), la última es false, y el otro memo (otro
      // proceso) también deniega en su siguiente pregunta.
      const twin = harness.makeTwin ? await harness.makeTwin(driver, tree) : twinOf(driver)
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      await driver.grant(alice, 'org-editor', orgA)
      assert.isTrue(await driver.authorize(alice, 'docs:write', orgA))
      assert.isTrue(await twin.authorize(alice, 'docs:write', orgA))

      const answers: boolean[] = []
      let synced = false
      const sync = harness
        .seedCatalog({
          ...CONTRACT_CATALOG,
          roles: CONTRACT_CATALOG.roles.map((role) =>
            role.slug === 'org-editor' ? { ...role, permissions: ['docs:read'] } : role
          ),
        })
        .finally(() => {
          synced = true
        })
      while (!synced) answers.push(await driver.authorize(alice, 'docs:write', orgA))
      await sync
      answers.push(await driver.authorize(alice, 'docs:write', orgA))

      assert.isFalse(answers[answers.length - 1], 'tras el sync, denegado')
      const firstDenied = answers.indexOf(false)
      assert.isTrue(answers.slice(firstDenied).every((a) => a === false), `no vuelve a conceder tras denegar: ${answers.join(',')}`)
      assert.isFalse(await twin.authorize(alice, 'docs:write', orgA), 'el otro memo lo ve en su siguiente pregunta')
      assert.isTrue(await driver.authorize(alice, 'docs:read', orgA), 'lo que sigue en el catálogo sigue concediendo')
      // Y el catálogo del juez se restaura para el resto (el setup lo re-siembra igualmente).
      await harness.seedCatalog(CONTRACT_CATALOG)
      assert.isTrue(await driver.authorize(alice, 'docs:write', orgA))
      assert.isTrue(await twin.authorize(alice, 'docs:write', orgA))
    })?.timeout(60_000)

    // ── Nivel 2.2 (Fase 3 · Lote 3B: roles locales a un scope) ───────────
    // Un rol tiene un OWNER (`authz_roles.owner_scope_key`): `global` (el
    // catálogo del config) o la clave del scope que lo define. Regla única:
    // una asignación en el scope S de un rol R cuenta si y solo si R es
    // global o su owner está en chain(S) (S inclusive). `assignableAt`,
    // `rank` y `delegablePermissions` son controles de COMPOSICIÓN y de
    // ESCRITURA; `authorize` sigue siendo «¿hay un grant vigente en mi
    // cadena sin deny?» (invariantes 1, 2 y 8 intactos). Los casos de aquí
    // juzgan al DRIVER con roles locales escritos como los dejaría otro
    // proceso (`localRole`); la policy de `defineScopedRole` se juzga bajo
    // el par `listDenies` (necesita `effectivePermissions`).

    since('2.2', 'un rol local de la organization A concede en A y sus units (también anidadas), no en B ni en app; hasRole/listRoles/listSubjects/listScopes/listRoleScopes respetan el owner; grant fuera del owner ⇒ 422 E_AUTHZ_ROLE_NOT_VISIBLE sin escribir; mover la unit fuera de A retira lo concedido, y volverla lo restaura', async ({
      assert,
    }) => {
      // 3B · B2. El owner es el CONTENEDOR del rol: fuera de él el rol no
      // existe (ni concede, ni es membresía, ni se puede asignar). Un rol
      // global con el mismo slug NO existe aquí (`lead`, `org-lead`): lo que
      // se observa es el owner, no una colisión.
      const alice = subject()
      const bob = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const orgB = await orgUnder(tree, APP_SCOPE)
      const unitA1 = await unitUnder(tree, orgA)
      const unitA1x = await unitUnder(tree, unitA1)
      const unitB1 = await unitUnder(tree, orgB)
      const leadA = await localRole(orgA, { slug: 'lead', scopeType: 'unit', permissions: ['docs:write'] })
      await localRole(orgA, { slug: 'org-lead', scopeType: 'organization', permissions: ['billing:read'] })
      // Un rol local de nivel `app` no es asignable en ningún sitio: la raíz
      // no cuelga de ningún owner. Existe (es una fila) pero no es visible.
      await localRole(orgA, { slug: 'phantom', scopeType: 'app', permissions: ['docs:read'] })

      await driver.grant(alice, 'lead', unitA1)
      await driver.grant(alice, 'org-lead', orgA)
      assert.isTrue(await driver.authorize(alice, 'docs:write', unitA1))
      assert.isTrue(await driver.authorize(alice, 'docs:write', unitA1x), 'hereda hacia abajo dentro del owner')
      assert.isTrue(await driver.authorize(alice, 'billing:read', unitA1))
      assert.isTrue(await driver.authorize(alice, 'billing:read', orgA))
      assert.isFalse(await driver.authorize(alice, 'docs:write', orgA), 'el rol de unit no vale en la org (no es herencia hacia arriba)')
      assert.isFalse(await driver.authorize(alice, 'docs:write', unitB1))
      assert.isFalse(await driver.authorize(alice, 'billing:read', orgB))
      assert.isFalse(await driver.authorize(alice, 'billing:read', APP_SCOPE))
      assert.isFalse(await driver.authorize(alice, 'docs:read', APP_SCOPE))

      const notVisible = { status: 422, code: 'E_AUTHZ_ROLE_NOT_VISIBLE' }
      await rejectsWith(assert, () => driver.grant(bob, 'lead', unitB1), notVisible)
      await rejectsWith(assert, () => driver.grant(bob, 'org-lead', orgB), notVisible)
      await rejectsWith(assert, () => driver.grant(bob, 'phantom', APP_SCOPE), notVisible)
      // Un rol que no existe en ningún owner sigue siendo E_AUTHZ_UNKNOWN_ROLE.
      await rejectsWith(assert, () => driver.grant(bob, 'no-existe', unitB1), { status: 422, code: 'E_AUTHZ_UNKNOWN_ROLE' })
      assert.deepEqual(await driver.listRoles(bob, unitB1), [])
      assert.deepEqual(await driver.listRoles(bob, orgB), [])
      assert.isFalse(await driver.authorize(bob, 'docs:write', unitB1))

      // Membresía y enumeraciones: solo dentro del owner.
      assert.isTrue(await driver.hasRole(alice, 'lead', unitA1))
      assert.isTrue(await driver.hasRole(alice, 'lead', unitA1x))
      assert.isTrue(await driver.hasRole(alice, { slug: 'lead', scopeType: 'unit' }, unitA1x))
      assert.isFalse(await driver.hasRole(alice, 'lead', unitB1))
      assert.isTrue(await driver.hasRole(alice, 'org-lead', unitA1))
      assert.isFalse(await driver.hasRole(alice, 'org-lead', orgB))
      assert.deepEqual(await driver.listRoles(alice, unitA1), ['lead'])
      assert.deepEqual(await driver.listRoles(alice, orgA), ['org-lead'])
      assert.deepEqual((await driver.listSubjects('lead', unitA1)).map((h) => h.uuid), [alice.uuid])
      assert.deepEqual(await driver.listSubjects('lead', unitB1), [], 'el rol no existe en B: nadie lo tiene')
      // Y lo mismo preguntando por `{ uuid }` (3D · M1 c, tester): la
      // resolución exacta no exime de la regla de owner — dentro responde…
      assert.isTrue(await driver.hasRole(alice, { uuid: leadA }, unitA1x))
      assert.deepEqual((await driver.listSubjects({ uuid: leadA }, unitA1)).map((h) => h.uuid), [alice.uuid])
      assert.deepEqual(scopeKeys(await driver.listScopes(alice, 'docs:write')), scopeKeys([unitA1]))
      assert.deepEqual(scopeKeys(await driver.listScopes(alice, 'billing:read')), scopeKeys([orgA]))
      assert.deepEqual(scopeKeys(await driver.listRoleScopes(alice, 'unit')), scopeKeys([unitA1]))
      assert.deepEqual(scopeKeys(await driver.listRoleScopes(alice, 'organization')), scopeKeys([orgA]))

      // La visibilidad se decide con el árbol de HOY: la unit sale de A y el
      // rol de A deja de existir para ella (sin escribir nada); vuelve, y vuelve.
      await tree.move(unitA1, orgB)
      assert.isFalse(await driver.authorize(alice, 'docs:write', unitA1))
      assert.isFalse(await driver.authorize(alice, 'docs:write', unitA1x))
      assert.isFalse(await driver.hasRole(alice, 'lead', unitA1))
      assert.deepEqual(await driver.listRoles(alice, unitA1), [], 'una asignación cuyo rol ya no es visible no es membresía')
      assert.deepEqual(await driver.listSubjects('lead', unitA1), [])
      // …y fuera, no: el uuid del rol de A no resucita la asignación que el
      // árbol de HOY dejó fuera de su owner (misma regla que por slug).
      assert.isFalse(await driver.hasRole(alice, { uuid: leadA }, unitA1))
      assert.deepEqual(await driver.listSubjects({ uuid: leadA }, unitA1), [])
      assert.deepEqual(await driver.listScopes(alice, 'docs:write'), [])
      assert.deepEqual(await driver.listRoleScopes(alice, 'unit'), [])
      await tree.move(unitA1, orgA)
      assert.isTrue(await driver.authorize(alice, 'docs:write', unitA1x))
      assert.deepEqual(await driver.listRoles(alice, unitA1), ['lead'])
      // revoke fuera del owner es un no-op (no hay nada que quitar); dentro, quita.
      await driver.revoke(alice, 'lead', unitB1)
      assert.isTrue(await driver.authorize(alice, 'docs:write', unitA1))
      await driver.revoke(alice, 'lead', unitA1)
      assert.isFalse(await driver.authorize(alice, 'docs:write', unitA1))
    })

    since('2.2', 'la visibilidad se decide POR NIVEL, no por el conjunto de la cadena: si el árbol se recuelga y el owner queda POR DEBAJO del scope de la asignación, esa asignación deja de contar aunque el owner siga en la cadena de la pregunta', async ({
      assert,
    }) => {
      // 3B · B2 (desviación 2 del lote, sin caso hasta aquí). La regla es
      // «una asignación en el scope S cuenta si su rol EXISTE EN S»: el owner
      // tiene que ser ancestro-o-igual de S, no de la pregunta. Con la lectura
      // por CONJUNTO («owner ∈ chain(scope preguntado)») este caso concedería:
      // orgA sigue estando en la cadena de unitA2. El mutante que sustituye
      // `keys.slice(i)` por `keys` en `chainKeysFrom` pasa toda la suite sin
      // este caso, en los dos drivers y en los tres motores.
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const unitA1 = await unitUnder(tree, orgA)
      await localRole(orgA, { slug: 'lead', scopeType: 'unit', permissions: ['docs:write'] })
      await driver.grant(alice, 'lead', unitA1)
      assert.isTrue(await driver.authorize(alice, 'docs:write', unitA1))

      // El consumidor recuelga su árbol: unitA1 pasa a la raíz y orgA cuelga
      // de ella. Ninguna escritura de hechos: solo cambia el árbol.
      await tree.move(unitA1, APP_SCOPE)
      await tree.move(orgA, unitA1)
      const unitA2 = await unitUnder(tree, orgA)

      // chain(unitA2) = [unitA2, orgA, unitA1, app]: el owner está en la
      // cadena, pero POR DEBAJO de la asignación (unitA1) — no cuenta.
      assert.isFalse(await driver.authorize(alice, 'docs:write', unitA2), 'por conjunto concedería; por nivel no')
      assert.isFalse(await driver.authorize(alice, 'docs:write', unitA1))
      assert.isFalse(await driver.hasRole(alice, 'lead', unitA2))
      assert.isFalse(await driver.hasRole(alice, 'lead', unitA1))
      assert.deepEqual(await driver.listRoles(alice, unitA1), [])
      assert.deepEqual(await driver.listRoles(alice, unitA2), [])
      assert.deepEqual(await driver.listScopes(alice, 'docs:write'), [])
      assert.deepEqual(await driver.listRoleScopes(alice, 'unit'), [])

      // El inverso, que es lo que hace significativo al caso: con el árbol
      // nuevo, una asignación DENTRO del owner sigue concediendo hacia abajo.
      const unitA2x = await unitUnder(tree, unitA2)
      await driver.grant(alice, 'lead', unitA2)
      assert.isTrue(await driver.authorize(alice, 'docs:write', unitA2))
      assert.isTrue(await driver.authorize(alice, 'docs:write', unitA2x))
      assert.deepEqual(await driver.listRoles(alice, unitA2), ['lead'])
      // Y la de unitA1 sigue sin contar: no ha revivido por el camino.
      assert.isFalse(await driver.authorize(alice, 'docs:write', unitA1))
    })

    since('2.2', 'dos tenants definen el mismo slug (lead@unit) con permisos distintos: cada uno concede lo suyo y listRoles/listSubjects/hasRole/revoke no cruzan tenants — el slug ya no identifica al rol, el uuid sí', async ({
      assert,
    }) => {
      // 3B · B2 (tester §4: el pin de regresión de `listSubjects` promovido).
      // Con `unique(slug, scope_type, owner_scope_key)` hay DOS roles `lead@unit`
      // con uuids distintos; todo resuelve por uuid dentro del owner.
      const alice = subject()
      const bob = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const orgB = await orgUnder(tree, APP_SCOPE)
      const unitA1 = await unitUnder(tree, orgA)
      const unitB1 = await unitUnder(tree, orgB)
      const leadA = await localRole(orgA, { slug: 'lead', scopeType: 'unit', permissions: ['docs:write'] })
      const leadB = await localRole(orgB, { slug: 'lead', scopeType: 'unit', permissions: ['docs:read'] })
      await driver.grant(alice, 'lead', unitA1)
      await driver.grant(bob, 'lead', unitB1)

      assert.isTrue(await driver.authorize(alice, 'docs:write', unitA1))
      assert.isFalse(await driver.authorize(alice, 'docs:read', unitA1), 'el lead de A no lleva docs:read')
      assert.isTrue(await driver.authorize(bob, 'docs:read', unitB1))
      assert.isFalse(await driver.authorize(bob, 'docs:write', unitB1), 'el lead de B no lleva docs:write')
      assert.deepEqual((await driver.listSubjects('lead', unitA1)).map((h) => h.uuid), [alice.uuid])
      assert.deepEqual((await driver.listSubjects('lead', unitB1)).map((h) => h.uuid), [bob.uuid])
      assert.deepEqual(await driver.listRoles(alice, unitA1), ['lead'])
      assert.deepEqual(await driver.listRoles(alice, unitB1), [])
      assert.isTrue(await driver.hasRole(bob, 'lead', unitB1))
      assert.isFalse(await driver.hasRole(alice, 'lead', unitB1))
      assert.deepEqual(scopeKeys(await driver.listScopes(bob, 'docs:read')), scopeKeys([unitB1]))
      assert.deepEqual(await driver.listScopes(bob, 'docs:write'), [])

      // Y el uuid tampoco cruza tenants (3D · M1 c, tester): `{ uuid }` es
      // resolución EXACTA, no un permiso para saltarse al owner. El uuid del
      // rol de B es público (sale en `rolesInChain`, en el evento
      // `role_defined` y en el 422 de ambigüedad), así que si la ruta por
      // uuid no comprobara la visibilidad bastaría con pasarlo para asignar
      // dentro de A el rol de otro tenant. Hasta aquí solo había caso para
      // «el uuid es de otro NIVEL»; esta es la otra mitad de la regla.
      await rejectsWith(assert, () => driver.grant(alice, { uuid: leadB }, unitA1), {
        status: 422,
        code: 'E_AUTHZ_ROLE_NOT_VISIBLE',
      })
      assert.deepEqual(await driver.listRoles(alice, unitA1), ['lead'], 'y no escribió nada')
      assert.isFalse(await driver.authorize(alice, 'docs:read', unitA1))
      // Membresía: fuera del owner el rol no existe (false y [], nunca throw).
      assert.isFalse(await driver.hasRole(bob, { uuid: leadB }, unitA1))
      assert.isFalse(await driver.hasRole(alice, { uuid: leadA }, unitB1))
      assert.deepEqual(await driver.listSubjects({ uuid: leadB }, unitA1), [])
      assert.deepEqual(await driver.listSubjects({ uuid: leadA }, unitB1), [])
      // Donde el owner SÍ está en la cadena, el mismo uuid responde.
      assert.isTrue(await driver.hasRole(bob, { uuid: leadB }, unitB1))
      assert.deepEqual((await driver.listSubjects({ uuid: leadB }, unitB1)).map((h) => h.uuid), [bob.uuid])
      assert.deepEqual((await driver.listSubjects({ uuid: leadA }, unitA1)).map((h) => h.uuid), [alice.uuid])

      // Revocar «lead» en B no toca al lead de A.
      await driver.revoke(alice, 'lead', unitB1)
      assert.isTrue(await driver.authorize(alice, 'docs:write', unitA1))
      await driver.revoke(bob, 'lead', unitB1)
      assert.isFalse(await driver.authorize(bob, 'docs:read', unitB1))
      assert.isTrue(await driver.authorize(alice, 'docs:write', unitA1))
    })

    since('2.2', 'un scopes.moved legítimo junta dos homónimos en la misma cadena: TODA ruta por slug falla cerrada con 422 E_AUTHZ_AMBIGUOUS_ROLE (grant, revoke, hasRole, listSubjects), { uuid } resuelve el correcto y authorize —que no direcciona por slug— sigue respondiendo', async ({
      assert,
    }) => {
      // 3D · M1 (auditor V3, reproducido en PG). U1 nace en el tenant B, que
      // define ahí su `lead@unit`; A define el suyo en su organization
      // (subárboles disjuntos: ninguna colisión). La plataforma transfiere U1
      // a A —operación legítima— y de repente los dos son visibles en la
      // misma cadena. Hasta 3C ganaba «el owner más cercano» y el admin de A
      // concedía SIN SABERLO el rol de B (`billing`/`docs:write` de otro
      // tenant). Ahora la ambigüedad es un error: nadie elige por él.
      const victima = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const orgB = await orgUnder(tree, APP_SCOPE)
      const unitU1 = await unitUnder(tree, orgB)
      const leadB = await localRole(unitU1, { slug: 'lead', scopeType: 'unit', permissions: ['docs:read'] })
      const leadA = await localRole(orgA, { slug: 'lead', scopeType: 'unit', permissions: ['docs:write'] })
      // Antes del move cada uno es el único visible en su subárbol.
      await driver.grant(victima, 'lead', unitU1)
      assert.isTrue(await driver.authorize(victima, 'docs:read', unitU1), 'el de B, que es el único visible ahí')
      await driver.revoke(victima, 'lead', unitU1)

      await tree.move(unitU1, orgA)
      const ambiguo = { status: 422, code: 'E_AUTHZ_AMBIGUOUS_ROLE' }
      await rejectsWith(assert, () => driver.grant(victima, 'lead', unitU1), ambiguo)
      await rejectsWith(assert, () => driver.grant(victima, { slug: 'lead', scopeType: 'unit' }, unitU1), ambiguo)
      await rejectsWith(assert, () => driver.hasRole(victima, 'lead', unitU1), ambiguo)
      await rejectsWith(assert, () => driver.listSubjects('lead', unitU1), ambiguo)
      assert.deepEqual(await driver.listRoles(victima, unitU1), [], 'nada escrito: el 422 fue antes del backend')

      // `{ uuid }` es la forma exacta: concede EL rol que se pidió.
      await driver.grant(victima, { uuid: leadA }, unitU1)
      assert.isTrue(await driver.authorize(victima, 'docs:write', unitU1), 'authorize no direcciona por slug: responde')
      assert.isFalse(await driver.authorize(victima, 'docs:read', unitU1), 'el rol de B no se le ha dado')
      assert.isTrue(await driver.hasRole(victima, { uuid: leadA }, unitU1))
      assert.isFalse(await driver.hasRole(victima, { uuid: leadB }, unitU1))
      assert.deepEqual((await driver.listSubjects({ uuid: leadA }, unitU1)).map((h) => h.uuid), [victima.uuid])
      assert.deepEqual(await driver.listSubjects({ uuid: leadB }, unitU1), [])
      // La membresía habla en slugs y por eso puede tener homónimos: el
      // puerto lo documenta y la forma sin ambigüedad es `{ uuid }`.
      assert.deepEqual(await driver.listRoles(victima, unitU1), ['lead'])
      // Y el slug sigue siendo 422 aunque haya una asignación de por medio.
      await rejectsWith(assert, () => driver.hasRole(victima, 'lead', unitU1), ambiguo)

      // `revoke` por slug NO elige: quita los hechos de todos los homónimos
      // del scope exacto (quitar nunca concede). Por uuid, solo el suyo.
      await driver.grant(victima, { uuid: leadB }, unitU1)
      assert.isTrue(await driver.authorize(victima, 'docs:read', unitU1))
      await driver.revoke(victima, { uuid: leadB }, unitU1)
      assert.isFalse(await driver.authorize(victima, 'docs:read', unitU1))
      assert.isTrue(await driver.authorize(victima, 'docs:write', unitU1))
      await driver.grant(victima, { uuid: leadB }, unitU1)
      await driver.revoke(victima, 'lead', unitU1)
      assert.isFalse(await driver.authorize(victima, 'docs:write', unitU1))
      assert.isFalse(await driver.authorize(victima, 'docs:read', unitU1))

      // Deshecho el cruce, el slug vuelve a responder — y responde al de B.
      await tree.move(unitU1, orgB)
      await driver.grant(victima, 'lead', unitU1)
      assert.isTrue(await driver.authorize(victima, 'docs:read', unitU1))
      assert.isFalse(await driver.authorize(victima, 'docs:write', unitU1), 'el rol de A ya no existe aquí')
      assert.isTrue(await driver.hasRole(victima, 'lead', unitU1))
    })

    since('2.2', 'paridad entre drivers (3D · N1): una asignación cuyo rol está declarado para OTRO nivel no cuenta en ninguno de los dos — ni concede, ni es membresía, ni se enumera — y vuelve a contar en cuanto el nivel del rol coincide otra vez', async ({
      assert,
    }) => {
      // Desviación 3 del lote 3B («`database.authorize` exige además
      // `r.scope_type = a.scope_type`, como ya hacía `openfga`») era una
      // promesa de PARIDAD sin juez: el mutante que la revertía pasaba las
      // suites enteras (tester H4). Solo es alcanzable retocando el catálogo
      // —`grant` lo impide—, y el catálogo es SQL en los dos drivers.
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const unitA1 = await unitUnder(tree, orgA)
      const lead = await localRole(orgA, { slug: 'lead', scopeType: 'unit', permissions: ['docs:write'] })
      await driver.grant(alice, 'lead', unitA1)
      assert.isTrue(await driver.authorize(alice, 'docs:write', unitA1))

      // El rol pasa a estar declarado para `organization`: la asignación
      // sigue en un scope `unit` y deja de contar.
      await retypeRole(lead, 'organization')
      assert.isFalse(await driver.authorize(alice, 'docs:write', unitA1), 'el rol ya no existe en ese nivel')
      assert.isFalse(await driver.hasRole(alice, 'lead', unitA1))
      assert.isFalse(await driver.hasRole(alice, { slug: 'lead', scopeType: 'unit' }, unitA1))
      assert.deepEqual(await driver.listRoles(alice, unitA1), [])
      assert.deepEqual(await driver.listSubjects('lead', unitA1), [])
      assert.deepEqual(await driver.listScopes(alice, 'docs:write'), [])
      assert.deepEqual(await driver.listRoleScopes(alice, 'unit'), [])
      // Y tampoco cuenta «hacia arriba»: no hay asignación en orgA.
      assert.isFalse(await driver.authorize(alice, 'docs:write', orgA))
      await rejectsWith(assert, () => driver.grant(alice, 'lead', unitA1), { status: 422, code: 'E_AUTHZ_UNKNOWN_ROLE' })

      await retypeRole(lead, 'unit')
      assert.isTrue(await driver.authorize(alice, 'docs:write', unitA1), 'vuelve a coincidir el nivel: vuelve a contar')
      assert.deepEqual(await driver.listRoles(alice, unitA1), ['lead'])
    })

    since('2.2', "la clave de owner 'global' está reservada: un scope de TIPO 'global' produce la clave 'global|<uuid>' y sus roles son locales a él, nunca globales", async ({
      assert,
    }) => {
      // 3B · B1/B2 (tester §4, mismo patrón que el centinela de la raíz). Un
      // tenant cuyo tipo de scope se llame `global` no se hace pasar por el
      // catálogo global: la clave de owner lleva siempre `<tipo>|<uuid>` (la
      // raíz no es owner), así que `global` a secas no la produce ningún scope.
      const alice = subject()
      const bob = subject()
      const weird: ScopeRef = { type: 'global', uuid: uuidv7() }
      await tree.attach(weird, APP_SCOPE)
      const unitW = await unitUnder(tree, weird)
      const orgA = await orgUnder(tree, APP_SCOPE)
      const unitA1 = await unitUnder(tree, orgA)
      await localRole(weird, { slug: 'lead', scopeType: 'unit', permissions: ['docs:write'] })

      await driver.grant(alice, 'lead', unitW)
      assert.isTrue(await driver.authorize(alice, 'docs:write', unitW))
      await rejectsWith(assert, () => driver.grant(bob, 'lead', unitA1), { status: 422, code: 'E_AUTHZ_ROLE_NOT_VISIBLE' })
      assert.isFalse(await driver.authorize(alice, 'docs:write', unitA1))
      assert.deepEqual(await driver.listSubjects('lead', unitA1), [])
    })

    since('2.2', 'deny × rol local: un deny en cualquier punto de la cadena gana sobre un rol local; quitarlo restaura (invariante 2 en el módulo nuevo)', async ({
      assert,
    }) => {
      // 3B · B2 (tester §4). El owner no es una excepción al deny: `authorize`
      // sigue siendo «sin deny en la cadena Y un grant vigente y visible».
      const alice = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const unitA1 = await unitUnder(tree, orgA)
      const unitA1x = await unitUnder(tree, unitA1)
      await localRole(orgA, { slug: 'lead', scopeType: 'unit', permissions: ['docs:write', 'docs:read'] })
      await driver.grant(alice, 'lead', unitA1)
      assert.isTrue(await driver.authorize(alice, 'docs:write', unitA1x))

      await driver.deny(alice, 'docs:write', orgA) // por encima del grant
      assert.isFalse(await driver.authorize(alice, 'docs:write', unitA1))
      assert.isFalse(await driver.authorize(alice, 'docs:write', unitA1x))
      assert.isTrue(await driver.authorize(alice, 'docs:read', unitA1x), 'el deny es quirúrgico')
      assert.isTrue(await driver.hasRole(alice, 'lead', unitA1x), 'membresía intacta: el deny no la gobierna')
      await driver.deny(alice, 'docs:read', unitA1x) // por debajo del grant
      assert.isFalse(await driver.authorize(alice, 'docs:read', unitA1x))
      assert.isTrue(await driver.authorize(alice, 'docs:read', unitA1))
      assert.deepEqual(scopeKeys(await driver.listScopes(alice, 'docs:write')), [], 'listScopes resta el deny heredado')

      await driver.removeDeny(alice, 'docs:write', orgA)
      await driver.removeDeny(alice, 'docs:read', unitA1x)
      assert.isTrue(await driver.authorize(alice, 'docs:write', unitA1x))
      assert.isTrue(await driver.authorize(alice, 'docs:read', unitA1x))
    })

    since('2.2', 'assignableAt es control de COMPOSICIÓN, jamás de evaluación: un rol que lleva (a mano) un permiso no asignable en su nivel sigue concediendo lo ya asignado; un grant NUEVO de ese rol ⇒ 422 E_AUTHZ_ROLE_NOT_ASSIGNABLE_AT sin escribir', async ({
      assert,
    }) => {
      // 3B · B5 (tester H). `org:settings` solo pueden llevarlo roles de
      // app/organization. `unit-editor@unit` no lo lleva (el sync lo
      // rechazaría); se le vincula A MANO después de conceder. Lo que fija
      // el caso: `authorize` NO mira `assignableAt` (invariante 1: un grant
      // vigente concede lo que su rol concede), y la barrera está en la
      // escritura (`grant`), donde el rol «no es asignable en ese nivel».
      const alice = subject()
      const bob = subject()
      const orgA = await orgUnder(tree, APP_SCOPE)
      const unitA1 = await unitUnder(tree, orgA)
      const unitA2 = await unitUnder(tree, orgA)
      await driver.grant(alice, 'unit-editor', unitA1)
      assert.isFalse(await driver.authorize(alice, 'org:settings', unitA1))
      const unitEditor = (await new CatalogCache().view()).role('unit-editor', 'unit')!.uuid
      await linkByHand(unitEditor, 'org:settings')

      assert.isTrue(await driver.authorize(alice, 'org:settings', unitA1), 'lo ya asignado sigue concediendo: no se evalúa')
      assert.isTrue(await driver.hasRole(alice, 'unit-editor', unitA1))
      await rejectsWith(assert, () => driver.grant(bob, 'unit-editor', unitA2), { status: 422, code: 'E_AUTHZ_ROLE_NOT_ASSIGNABLE_AT' })
      assert.deepEqual(await driver.listRoles(bob, unitA2), [])
      assert.isFalse(await driver.authorize(bob, 'org:settings', unitA2))
      // Un rol de organization sí puede llevarlo: se asigna con normalidad.
      await driver.grant(bob, 'org-admin', orgA)
      assert.isTrue(await driver.authorize(bob, 'org:settings', unitA2))
    })

    // ── Par de capacidad `purgeRole` (3B · B4) ───────────────────────────
    caseFor('purgeRole', {
      whenTrue: () => {
        since('2.2', 'purgeRole(uuid) revoca todas las asignaciones del rol en TODOS los scopes (owner y descendientes), borra sus vínculos y el rol; recrear el slug (otro uuid) no revive nada; un uuid desconocido o mal formado ⇒ 422', async ({
          assert,
        }) => {
          // 3B · B4 (tester §4: con asignaciones en descendientes y con denies
          // del permiso del rol). Es lo que `deleteScopedRole` necesita del
          // puerto: borrar el rol sin dejar asignaciones huérfanas que
          // resuciten si el slug vuelve a existir.
          assert.typeOf(driver.purgeRole, 'function', 'purgeRole: true exige purgeRole en el puerto')
          const alice = subject()
          const bob = subject()
          const orgA = await orgUnder(tree, APP_SCOPE)
          const unitA1 = await unitUnder(tree, orgA)
          const unitA1x = await unitUnder(tree, unitA1)
          const lead = await localRole(orgA, { slug: 'lead', scopeType: 'unit', permissions: ['docs:write'] })
          await driver.grant(alice, 'lead', unitA1)
          await driver.grant(bob, 'lead', unitA1x)
          await driver.grant(alice, 'unit-editor', unitA1) // otro rol: intacto
          await driver.deny(bob, 'docs:read', unitA1x) // un deny: intacto
          assert.isTrue(await driver.authorize(alice, 'docs:write', unitA1))
          assert.isTrue(await driver.authorize(bob, 'docs:write', unitA1x))

          assert.equal(await linksOf(lead), 1, 'el rol tenía su vínculo')
          await driver.purgeRole!(lead)

          // 3E · R7 (tester): el «todo o nada» se afirma, no se hereda del
          // `CASCADE` del esquema — un driver que borra la fila del rol y se
          // deja los vínculos pasaba el juez entero.
          assert.equal(await linksOf(lead), 0, 'purgeRole borra también los vínculos rol→permiso')
          assert.isNull((await new CatalogCache().view()).roleByUuid(lead), 'y la fila del rol')
          assert.isFalse(await driver.hasRole(alice, 'lead', unitA1))
          assert.deepEqual(await driver.listRoles(alice, unitA1), ['unit-editor'], 'solo cae el rol purgado')
          assert.deepEqual(await driver.listRoles(bob, unitA1x), [])
          assert.isFalse(await driver.authorize(bob, 'docs:write', unitA1x))
          assert.isTrue(await driver.authorize(alice, 'docs:write', unitA1), 'unit-editor sigue concediendo')
          assert.isFalse(await driver.authorize(bob, 'docs:read', unitA1x), 'el deny sigue')
          await rejectsWith(assert, () => driver.grant(bob, 'lead', unitA1), { status: 422, code: 'E_AUTHZ_UNKNOWN_ROLE' })
          await rejectsWith(assert, () => driver.purgeRole!(lead), { status: 422, code: 'E_AUTHZ_UNKNOWN_ROLE' })
          await rejectsWith(assert, () => driver.purgeRole!('lead'), { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' })

          // El slug vuelve a existir (otro uuid): nada resucita.
          await localRole(orgA, { slug: 'lead', scopeType: 'unit', permissions: ['docs:write'] })
          assert.isFalse(await driver.hasRole(alice, 'lead', unitA1))
          assert.isFalse(await driver.authorize(bob, 'docs:write', unitA1x))
          assert.deepEqual(await driver.listSubjects('lead', unitA1), [])
          assert.deepEqual(await driver.listSubjects('lead', unitA1x), [])
          await driver.grant(bob, 'lead', unitA1x)
          assert.isTrue(await driver.authorize(bob, 'docs:write', unitA1x))
          assert.deepEqual((await driver.listSubjects('lead', unitA1x)).map((h) => h.uuid), [bob.uuid])
          // El cero, por el PUERTO PÚBLICO y en CADA scope donde había una
          // asignación (3D · M6 c, tester H3): hasta aquí a los mutantes de
          // `purgeRole` los mataba una FK del espejo de tests que ni siquiera
          // coincidía con el stub publicado, no una aserción.
          const carol = subject()
          await driver.grant(carol, 'lead', unitA1)
          assert.deepEqual((await driver.listSubjects('lead', unitA1)).map((h) => h.uuid), [carol.uuid], 'alice no resucita con el slug')
          assert.isFalse(await driver.hasRole(alice, 'lead', unitA1))
          assert.isFalse(await driver.hasRole(alice, 'lead', unitA1x))
        })

        since('2.2', 'scopes.detached purga también los roles LOCALES cuyo owner es ese scope (3D · M4): la fila no sobrevive, ese (slug, nivel) vuelve a estar libre para el catálogo global y nada de lo que concedía queda en pie', async ({
          assert,
        }) => {
          // Auditor V5 (reproducido en PG): `deleteScopedRole` respondía 422
          // `E_AUTHZ_UNKNOWN_SCOPE` en cuanto el owner salía del árbol (lo
          // resuelve en fresco) y la fila del rol sobrevivía bloqueando ese
          // `(slug, nivel)` para `syncAuthzCatalog` PARA SIEMPRE. Un rol sin
          // owner no es visible en ninguna parte: purgarlo no pierde nada.
          const authz = managerOver()
          const alice = subject()
          const orgA = await orgUnder(tree, APP_SCOPE)
          const unitA1 = await unitUnder(tree, orgA)
          const unitA1x = await unitUnder(tree, unitA1)
          const huerfano = await localRole(unitA1, { slug: 'huerfano', scopeType: 'unit', permissions: ['docs:write'] })
          const deOrg = await localRole(orgA, { slug: 'lead', scopeType: 'unit', permissions: ['docs:read'] })
          // 3E · P2 (auditor A4) / R7: un rol cuyo owner es un DESCENDIENTE
          // del scope notificado. El consumidor notifica el nodo que borró —
          // no uno por hoja—, y estos quedaban huérfanos e indeleteables,
          // bloqueando su (slug, nivel) global para siempre.
          const delNieto = await localRole(unitA1x, { slug: 'nieto', scopeType: 'unit', permissions: ['docs:read'] })
          await driver.grant(alice, 'huerfano', unitA1)
          await driver.grant(alice, 'huerfano', unitA1x)
          await driver.grant(alice, 'nieto', unitA1x)
          await driver.grant(alice, 'lead', unitA1)
          assert.isTrue(await driver.authorize(alice, 'docs:write', unitA1x))

          await authz.scopes.detached(unitA1)
          await tree.detach(unitA1)

          const view = await new CatalogCache().view()
          assert.isNull(view.roleByUuid(huerfano), 'la fila del rol cuyo owner desapareció no sobrevive')
          assert.deepEqual(view.rolesNamed('huerfano', 'unit'), [], 'el (slug, nivel) vuelve a estar libre')
          assert.isNull(view.roleByUuid(delNieto), 'ni la del rol de un descendiente del scope notificado')
          assert.deepEqual(view.rolesNamed('nieto', 'unit'), [])
          assert.equal(await linksOf(huerfano), 0, 'sin vínculos huérfanos')
          assert.equal(await linksOf(delNieto), 0)
          assert.isNotNull(view.roleByUuid(deOrg), 'el rol de la organization, que sigue en el árbol, no se toca')
          assert.deepEqual(await driver.listSubjects({ uuid: huerfano }, unitA1x), [])
          // El subárbol lo purga el consumidor nodo a nodo (invariante 7): lo
          // que aquí se fija es que el ROL no deja rastro que resucite.
          const orgB = await orgUnder(tree, APP_SCOPE)
          const unitB1 = await unitUnder(tree, orgB)
          await localRole(orgB, { slug: 'huerfano', scopeType: 'unit', permissions: ['docs:read'] })
          await driver.grant(alice, 'huerfano', unitB1)
          assert.isTrue(await driver.authorize(alice, 'docs:read', unitB1))
          assert.isFalse(await driver.authorize(alice, 'docs:write', unitB1), 'el rol viejo no revive por el slug')
        })
      },
      whenFalse: () => {
        since('2.2', 'sin purgeRole: el puerto NO lo trae (opcional desde 3E · Q4) y el manager lo dice con 500 E_AUTHZ_UNSUPPORTED ANTES de escribir — defineScopedRole no crea el rol, deleteScopedRole y scopes.detached de un scope con roles locales no tocan nada; y el callejón tiene salida: borrada la fila del rol, el scope se purga con normalidad', async ({
          assert,
        }) => {
          // 3B · B4 + 3E · P4. Hasta 3E este caso FIJABA UN CALLEJÓN SIN
          // SALIDA como comportamiento esperado: `defineScopedRole` creaba el
          // rol contra un driver que jamás podría borrarlo y aquí se afirmaba
          // que `scopes.detached` de ese scope respondía 500 «sin tocar
          // nada» — para siempre, hechos incluidos. Lo que se juzga ahora es
          // lo contrario: ese estado NO SE CREA (el 500 llega antes de
          // escribir) y, si llega por otra vía (catálogo escrito a mano, una
          // migración), la salida existe y está aquí demostrada.
          const authz = managerOver({ delegablePermissions: ['docs:read', 'docs:write'] })
          const alice = subject()
          const admin = subject()
          const orgA = await orgUnder(tree, APP_SCOPE)
          const unitA1 = await unitUnder(tree, orgA)
          assert.isUndefined(
            driver.purgeRole,
            'purgeRole: false ⇒ el puerto no lo trae; un método que solo lanza al llamarlo no deja al manager protegerte'
          )
          await driver.grant(admin, 'org-admin', orgA)

          // (1) La API de delegación se niega ANTES de escribir nada.
          const spec = { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'] }
          await rejectsWith(assert, () => authz.defineScopedRole(admin, orgA, spec), { status: 500, code: 'E_AUTHZ_UNSUPPORTED' })
          assert.deepEqual((await new CatalogCache().view()).rolesNamed('lead', 'unit'), [], 'nada escrito')

          // (2) Los roles locales que existan por otra vía se LEEN con
          //     normalidad (el catálogo es SQL en los dos drivers) y lo que
          //     no se puede deshacer se dice, sin dejar nada a medias.
          const lead = await localRole(orgA, { slug: 'lead', scopeType: 'unit', permissions: ['docs:write'], rank: 20 })
          await driver.grant(alice, 'lead', unitA1)
          assert.isTrue(await driver.authorize(alice, 'docs:write', unitA1))
          await rejectsWith(assert, () => authz.deleteScopedRole(admin, lead), { status: 500, code: 'E_AUTHZ_UNSUPPORTED' })
          await rejectsWith(assert, () => authz.deleteScopedRole(admin, 'lead'), { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' })
          assert.isTrue(await driver.authorize(alice, 'docs:write', unitA1), 'el rol sigue concediendo')
          assert.deepEqual(await driver.listRoles(alice, unitA1), ['lead'])
          assert.isNotNull((await new CatalogCache().view()).roleByUuid(lead), 'el rol sigue en el catálogo')
          assert.equal(await linksOf(lead), 1, 'y sus vínculos')

          // (3) 3D · M4: `scopes.detached` de un scope que ES owner de roles
          //     locales necesita purgarlos; sin `purgeRole` lo dice con 500
          //     ANTES de tocar los hechos (nada purgado a medias).
          const owner = await unitUnder(tree, orgA)
          const propio = await localRole(owner, { slug: 'propio', scopeType: 'unit', permissions: ['docs:write'] })
          await driver.grant(alice, 'propio', owner)
          await rejectsWith(assert, () => authz.scopes.detached(owner), { status: 500, code: 'E_AUTHZ_UNSUPPORTED' })
          assert.isTrue(await driver.authorize(alice, 'docs:write', owner), 'los hechos del scope siguen: no se purgó nada')
          assert.deepEqual(await driver.listRoles(alice, owner), ['propio'])

          // (4) LA SALIDA: la plataforma borra la fila del rol (el catálogo
          //     es suyo y es SQL) y el scope se purga con normalidad. Nadie
          //     queda encerrado.
          await forgetRoleByHand(propio)
          await authz.scopes.detached(owner)
          assert.deepEqual(await driver.listRoles(alice, owner), [], 'los hechos del scope, purgados')
          assert.isFalse(await driver.authorize(alice, 'docs:write', owner))

          // (5) Un scope SIN roles locales propios se purga siempre.
          const simple = await unitUnder(tree, orgA)
          await driver.grant(alice, 'unit-editor', simple)
          await authz.scopes.detached(simple)
          assert.deepEqual(await driver.listRoles(alice, simple), [])
        })
      },
    })

    // ── Par de capacidad `listDenies` (2E · I5) ──────────────────────────
    // Todo lo que RESTA denies (`listDenies`, `effectivePermissions`,
    // `authorizedScopes`, y F1, que observa el catálogo a través de
    // `effectivePermissions`) necesita el método opcional del puerto. Un
    // driver que lo trae declara `listDenies: true` y se le juzgan estos
    // casos; uno que no lo trae declara `false` y se le juzga que las tres
    // primitivas lo DIGAN (500 `E_AUTHZ_UNSUPPORTED` nombrándolo) en vez de
    // simular «sin denies», que sería fail-open. Nunca un skip.
    caseFor('listDenies', {
      whenTrue: () => {
      since('2.1', 'el catálogo que decide es el de la base: un sync en otro proceso (otro memo) retira el permiso en la siguiente pregunta, en el driver y en effectivePermissions', async ({
        assert,
      }) => {
        // 2D · F1 (auditor 1 y 4). Dos managers sobre dos instancias del
        // driver con memos DISTINTOS y sin señal en memoria entre ellas: lo
        // único que cruza procesos es la base (`authz_catalog_version`). Un
        // vínculo retirado por "otro proceso" tiene que dejar de conceder en
        // la siguiente pregunta de este, sin reiniciar y sin TTL.
        const twin = harness.makeTwin ? await harness.makeTwin(driver, tree) : twinOf(driver)
        const here = managerOver()
        const there = managerOver({}, twin)
        const alice = subject()
        const orgA = await orgUnder(tree, APP_SCOPE)
        await here.grant(alice, 'org-editor', orgA) // docs:read, docs:write
        assert.isTrue(await here.authorize(alice, 'docs:write', orgA))
        assert.isTrue(await there.authorize(alice, 'docs:write', orgA))
        assert.include(await there.effectivePermissions(alice, orgA), 'docs:write')

        // "Otro proceso" sincroniza `org-editor` sin `docs:write`: cambia la
        // base y sube la versión en su transacción. Ni `here` ni `there`
        // reciben llamada alguna.
        await withoutLink('org-editor', 'organization', 'docs:write')
        assert.isFalse(await there.authorize(alice, 'docs:write', orgA), 'el otro memo recarga por la versión')
        assert.isFalse(await here.authorize(alice, 'docs:write', orgA))
        assert.notInclude(await there.effectivePermissions(alice, orgA), 'docs:write')
        assert.notInclude(await here.effectivePermissions(alice, orgA), 'docs:write')
        assert.isTrue(await there.authorize(alice, 'docs:read', orgA), 'lo que sigue en el catálogo sigue concediendo')
        assert.deepEqual(await there.authorizeMany(alice, 'docs:write', [orgA, APP_SCOPE]), [false, false])

        // Y un sync real (el del harness) lo devuelve en ambos.
        await harness.seedCatalog(CONTRACT_CATALOG)
        assert.isTrue(await there.authorize(alice, 'docs:write', orgA))
        assert.isTrue(await here.authorize(alice, 'docs:write', orgA))
        assert.include(await there.effectivePermissions(alice, orgA), 'docs:write')
      })

      since('2.1', 'listDenies: denies directos vigentes del scope exacto (sin herencia) o todos los del sujeto; fuera del catálogo no cuenta', async ({
        assert,
      }) => {
        // B5 (tester §5 E · listDenies 1-3). Método OPCIONAL del puerto que
        // ambos drivers del paquete implementan; es lo que `effectivePermissions`
        // y `authorizedScopes` necesitan para restar. Invariante 7: directo y
        // exacto, como los demás `list*`.
        const alice = subject()
        const bob = subject()
        const orgA = await orgUnder(tree, APP_SCOPE)
        const unit = await unitUnder(tree, orgA)
        await driver.deny(alice, 'docs:read', orgA)
        await driver.deny(alice, 'docs:write', orgA)
        await driver.deny(alice, 'billing:read', unit)
        await driver.deny(alice, 'docs:read', APP_SCOPE)
        await driver.deny(bob, 'docs:read', orgA)

        const perms = (denies: Array<{ permission: string }>) => denies.map((d) => d.permission).sort()
        assert.deepEqual(perms(await driver.listDenies!(alice, orgA)), ['docs:read', 'docs:write'])
        assert.deepEqual(perms(await driver.listDenies!(alice, unit)), ['billing:read'])
        assert.deepEqual(perms(await driver.listDenies!(alice, APP_SCOPE)), ['docs:read'])
        assert.deepEqual(await driver.listDenies!(bob, unit), [])
        assert.deepEqual(await driver.listDenies!(subject(), orgA), [])
        assert.deepEqual(await driver.listDenies!(alice, orgScope()), [], 'scope desconocido: nada')
        // Sin scope: todos los denies directos del sujeto, con su scope.
        const all = await driver.listDenies!(alice)
        assert.deepEqual(
          all.map((d) => `${d.permission}@${d.scope.type}:${d.scope.uuid ?? ''}`).sort(),
          [
            `billing:read@unit:${unit.uuid}`,
            `docs:read@app:`,
            `docs:read@organization:${orgA.uuid}`,
            `docs:write@organization:${orgA.uuid}`,
          ]
        )
        await driver.removeDeny(alice, 'docs:write', orgA)
        assert.deepEqual(perms(await driver.listDenies!(alice, orgA)), ['docs:read'])
        assert.lengthOf(await driver.listDenies!(alice), 3)
      })

      since('2.1', 'effectivePermissions: unión de los roles vigentes de la cadena menos lo denegado en ella; el orden de escritura no importa', async ({
        assert,
      }) => {
        // B5 (tester §5 E · effectivePermissions 1-4). Composición del manager:
        // `listRoles` por nivel + catálogo memo, menos `listDenies` por nivel.
        // Prerrequisito de `catalog/` (3): es lo que un PEP por permiso ve.
        const authz = managerOver()
        const alice = subject()
        const bob = subject()
        const orgA = await orgUnder(tree, APP_SCOPE)
        const unit = await unitUnder(tree, orgA)
        await driver.grant(alice, 'owner', APP_SCOPE) // billing:read (app)
        await driver.grant(alice, 'viewer', APP_SCOPE, { expiresAt: new Date(Date.now() - 60_000) }) // expirado: nada
        await driver.grant(alice, 'org-editor', orgA) // docs:read, docs:write
        await driver.grant(alice, 'unit-editor', unit) // docs:write
        await driver.deny(alice, 'docs:write', orgA)

        assert.deepEqual((await authz.effectivePermissions(alice, APP_SCOPE)).sort(), ['billing:read'])
        assert.deepEqual((await authz.effectivePermissions(alice, orgA)).sort(), ['billing:read', 'docs:read'])
        assert.deepEqual((await authz.effectivePermissions(alice, unit)).sort(), ['billing:read', 'docs:read'])
        assert.deepEqual(await authz.effectivePermissions(subject(), unit), [])
        assert.deepEqual(await authz.effectivePermissions(alice, orgScope()), [], 'scope desconocido: nada')
        // Coherente con `authorize`, permiso a permiso.
        for (const permission of ['docs:read', 'docs:write', 'billing:read']) {
          assert.equal(
            (await authz.effectivePermissions(alice, unit)).includes(permission),
            await driver.authorize(alice, permission, unit),
            permission
          )
        }
        // Mismo conjunto con las escrituras en orden inverso.
        await driver.deny(bob, 'docs:write', orgA)
        await driver.grant(bob, 'unit-editor', unit)
        await driver.grant(bob, 'org-editor', orgA)
        await driver.grant(bob, 'owner', APP_SCOPE)
        assert.deepEqual((await authz.effectivePermissions(bob, unit)).sort(), ['billing:read', 'docs:read'])
        // Quitar el deny restaura.
        await driver.removeDeny(alice, 'docs:write', orgA)
        assert.deepEqual((await authz.effectivePermissions(alice, unit)).sort(), ['billing:read', 'docs:read', 'docs:write'])
      })


      since('2.1', 'authorizedScopes: all SOLO con excludedSubtrees (un deny vivo nunca da un all silencioso); deny en app ⇒ none; sin grants ⇒ none', async ({
        assert,
      }) => {
        // B3 (juez cruce 5, auditor E1; tester §5 E · authorizedScopes 1 y 3).
        // `all` = hay un grant vigente en la raíz (ancestro común de todo el
        // tipo). Los denies del permiso NO desaparecen dentro de `all`: van en
        // `excludedSubtrees` para que el consumidor los reste en su listado —
        // sin eso, la org B aparecería listada aunque `authorize` dijera false.
        const authz = managerOver()
        const alice = subject()
        const orgA = await orgUnder(tree, APP_SCOPE)
        const orgB = await orgUnder(tree, APP_SCOPE)
        const unitA1 = await unitUnder(tree, orgA)
        await driver.grant(alice, 'editor', APP_SCOPE)

        assert.deepEqual(await authz.authorizedScopes(alice, 'docs:write', 'organization'), { kind: 'all', excludedSubtrees: [] })
        assert.deepEqual(await authz.authorizedScopes(alice, 'docs:write', 'unit'), { kind: 'all', excludedSubtrees: [] })

        await driver.deny(alice, 'docs:write', orgB)
        await driver.deny(alice, 'docs:write', unitA1)
        await driver.deny(alice, 'docs:read', orgA) // otro permiso: no cuenta
        const result = await authz.authorizedScopes(alice, 'docs:write', 'organization')
        assert.equal(result.kind, 'all')
        const excluded = (result as { excludedSubtrees: ExcludedSubtree[] }).excludedSubtrees
        assert.deepEqual(scopeKeys(excluded.map((e) => e.scope)), scopeKeys([orgB, unitA1]))
        assert.isTrue(excluded.every((e) => e.includesDescendants === true), 'un subárbol, no un scope (F10)')
        assert.isFalse(await driver.authorize(alice, 'docs:write', orgB))
        assert.isTrue(await driver.authorize(alice, 'docs:write', orgA))
        // Expandido (F10): lo que hay que restar es cada deny Y su subárbol —
        // exactamente los scopes donde `authorize` es false.
        const unitB1 = await unitUnder(tree, orgB)
        const unitB1x = await unitUnder(tree, unitB1)
        const unitA1y = await unitUnder(tree, unitA1)
        const expanded = await authz.expandExcludedSubtrees(excluded)
        assert.deepEqual(scopeKeys(expanded), scopeKeys([orgB, unitA1, unitB1, unitB1x, unitA1y]))
        for (const s of [orgA, orgB, unitA1, unitB1, unitB1x, unitA1y]) {
          assert.equal(!scopeKeys(expanded).includes(scopeKeys([s])[0]), await driver.authorize(alice, 'docs:write', s), scopeKeys([s])[0])
        }
        // Y para el otro permiso, solo orgA está excluida.
        assert.deepEqual(await authz.authorizedScopes(alice, 'docs:read', 'organization'), {
          kind: 'all',
          excludedSubtrees: [{ scope: orgA, includesDescendants: true }],
        })

        // Deny en la raíz: el grant de app está bloqueado ⇒ nada, no `all`.
        await driver.deny(alice, 'docs:write', APP_SCOPE)
        assert.deepEqual(await authz.authorizedScopes(alice, 'docs:write', 'organization'), { kind: 'none' })
        await driver.removeDeny(alice, 'docs:write', APP_SCOPE)
        assert.equal((await authz.authorizedScopes(alice, 'docs:write', 'organization')).kind, 'all')

        assert.deepEqual(await authz.authorizedScopes(subject(), 'docs:write', 'organization'), { kind: 'none' })
        assert.deepEqual(await authz.authorizedScopes(alice, 'no:existe', 'organization'), { kind: 'none' })
      })

      since('2.1', 'authorizedScopes: some = directos del tipo ∪ descendientes vía descendantsOf, menos subárboles denegados; listScopes sigue sin enumerar (invariante 7)', async ({
        assert,
      }) => {
        // B3 (tester §5 E · 2 y 4). La ÚNICA API del paquete que enumera
        // descendientes, y lo hace con el `descendantsOf` del consumidor —
        // nunca con N+1 llamadas a `resolveChain`. Un deny excluye su
        // subárbol entero, igual que `authorize` lo deniega.
        const authz = managerOver()
        const alice = subject()
        const orgA = await orgUnder(tree, APP_SCOPE)
        const orgB = await orgUnder(tree, APP_SCOPE)
        const orgC = await orgUnder(tree, APP_SCOPE)
        const unitA1 = await unitUnder(tree, orgA)
        const unitA2 = await unitUnder(tree, orgA)
        const unitA1x = await unitUnder(tree, unitA1) // unit bajo unit: profundidad 2
        const unitB1 = await unitUnder(tree, orgB)
        const unitC1 = await unitUnder(tree, orgC)
        await driver.grant(alice, 'org-editor', orgA)
        await driver.grant(alice, 'org-editor', orgB)
        await driver.grant(alice, 'unit-editor', unitC1) // directo de tipo unit, en una org sin grant

        const orgs = await authz.authorizedScopes(alice, 'docs:write', 'organization')
        assert.equal(orgs.kind, 'some')
        assert.deepEqual(scopeKeys((orgs as any).scopes), scopeKeys([orgA, orgB]))
        const units = await authz.authorizedScopes(alice, 'docs:write', 'unit')
        assert.equal(units.kind, 'some')
        assert.deepEqual(scopeKeys((units as any).scopes), scopeKeys([unitA1, unitA2, unitA1x, unitB1, unitC1]))
        // Invariante 7: los list* siguen siendo directos.
        assert.deepEqual(scopeKeys(await driver.listScopes(alice, 'docs:write')), scopeKeys([orgA, orgB, unitC1]))
        assert.deepEqual(await driver.listRoleScopes(alice, 'unit'), [unitC1])

        // Denies: un subárbol entero fuera; un grant directo dentro de un
        // subárbol denegado tampoco cuenta (authorize lo deniega).
        await driver.deny(alice, 'docs:write', unitA1)
        await driver.deny(alice, 'docs:write', orgB)
        await driver.grant(alice, 'unit-editor', unitB1)
        assert.isFalse(await driver.authorize(alice, 'docs:write', unitB1))
        const afterDeny = await authz.authorizedScopes(alice, 'docs:write', 'unit')
        assert.equal(afterDeny.kind, 'some')
        assert.deepEqual(scopeKeys((afterDeny as any).scopes), scopeKeys([unitA2, unitC1]))
        assert.deepEqual(scopeKeys(((await authz.authorizedScopes(alice, 'docs:write', 'organization')) as any).scopes), scopeKeys([orgA]))
        // Coherente con authorize, scope a scope.
        for (const s of [unitA1, unitA2, unitA1x, unitB1, unitC1]) {
          assert.equal(scopeKeys((afterDeny as any).scopes).includes(scopeKeys([s])[0]), await driver.authorize(alice, 'docs:write', s), scopeKeys([s])[0])
        }
        // Quitar los denies restaura; un tipo sin nodos ⇒ none.
        await driver.removeDeny(alice, 'docs:write', unitA1)
        await driver.removeDeny(alice, 'docs:write', orgB)
        assert.lengthOf(((await authz.authorizedScopes(alice, 'docs:write', 'unit')) as any).scopes, 5)
        assert.deepEqual(await authz.authorizedScopes(alice, 'docs:write', 'team'), { kind: 'none' })
      })

      since('2.1', 'authorizedScopes ≡ { s | authorize(s) } scope a scope, con deny intermedio y tres niveles; si descendantsOf y resolveChain discrepan (nodo ajeno, o subárbol denegado que no sabe enumerar) ⇒ 503, nunca una lista con cruces', async ({
        assert,
      }) => {
        // 2D · F3 (auditor 3). Antes, `descendantsOf(deny) === null` valía `[]`
        // y el subárbol denegado se listaba como concedido; y un descendiente
        // ajeno devuelto por un `descendantsOf` roto se aceptaba (cruce de
        // tenant). Ahora cada candidato se contrasta con `resolveChain`:
        // su cadena decide (deny en la cadena ⇒ fuera, igual que `authorize`)
        // y si no cuelga del scope concedente se lanza.
        const authz = managerOver()
        const alice = subject()
        const orgA = await orgUnder(tree, APP_SCOPE)
        const orgB = await orgUnder(tree, APP_SCOPE)
        const unitA1 = await unitUnder(tree, orgA)
        const unitA2 = await unitUnder(tree, orgA)
        const teamA1a = await unitUnder(tree, unitA1)
        const teamA1b = await unitUnder(tree, unitA1)
        const teamA2a = await unitUnder(tree, unitA2)
        const unitB1 = await unitUnder(tree, orgB)
        await driver.grant(alice, 'org-editor', orgA)
        await driver.deny(alice, 'docs:write', unitA1) // deny intermedio: fuera teamA1a y teamA1b
        await driver.grant(alice, 'unit-editor', teamA1b) // un grant DENTRO del subárbol denegado no lo salva

        const all = [orgA, orgB, unitA1, unitA2, teamA1a, teamA1b, teamA2a, unitB1]
        const listed = (await authz.authorizedScopes(alice, 'docs:write', 'unit')) as { kind: string; scopes: ScopeRef[] }
        assert.equal(listed.kind, 'some')
        assert.deepEqual(scopeKeys(listed.scopes), scopeKeys([unitA2, teamA2a]))
        for (const s of all) {
          assert.equal(
            scopeKeys(listed.scopes).includes(scopeKeys([s])[0]),
            s.type === 'unit' && (await driver.authorize(alice, 'docs:write', s)),
            scopeKeys([s])[0]
          )
        }
        assert.deepEqual(scopeKeys(((await authz.authorizedScopes(alice, 'docs:write', 'organization')) as any).scopes), scopeKeys([orgA]))

        // Un `descendantsOf` que no sabe enumerar el subárbol denegado (null)
        // ya no importa: el deny se aplica por la cadena del candidato.
        const full = descendantsFrom(tree)
        const blind = managerOver({
          scopes: {
            resolveChain: resolveChainFrom(tree),
            descendantsOf: (scope, o) => (scopeKeys([scope])[0] === scopeKeys([unitA1])[0] ? Promise.resolve(null) : full(scope, o)),
          },
        })
        assert.deepEqual(scopeKeys(((await blind.authorizedScopes(alice, 'docs:write', 'unit')) as any).scopes), scopeKeys([unitA2, teamA2a]))

        // Un `descendantsOf` que devuelve un nodo de OTRO tenant: 503, no una lista con la unit de B.
        const expected = { status: 503, code: 'E_AUTHZ_RESOLVER_FAILED' }
        const crossed = managerOver({
          scopes: {
            resolveChain: resolveChainFrom(tree),
            descendantsOf: async (scope, o) => {
              const own = (await full(scope, o)) ?? []
              return scopeKeys([scope])[0] === scopeKeys([orgA])[0] ? [...own, unitB1] : own
            },
          },
        })
        await rejectsWith(assert, () => crossed.authorizedScopes(alice, 'docs:write', 'unit'), expected)
        // Y uno que devuelve un nodo que `resolveChain` no conoce, lo mismo.
        const ghost = managerOver({
          scopes: {
            resolveChain: resolveChainFrom(tree),
            descendantsOf: async (scope, o) => [...((await full(scope, o)) ?? []), unitScope()],
          },
        })
        await rejectsWith(assert, () => ghost.authorizedScopes(alice, 'docs:write', 'unit'), expected)
        // La pertenencia se contrasta con el memo por request: una llamada al árbol por candidato como mucho.
        let asked = 0
        const original = tree.chainOf
        tree.chainOf = async (scope) => {
          asked += 1
          return original.call(tree, scope)
        }
        try {
          await authz.authorizedScopes(alice, 'docs:write', 'unit')
          assert.isAtMost(asked, all.length + 1)
        } finally {
          tree.chainOf = original
        }
      })

      since('2.1', 'authorizedScopes: maxScopes superado ⇒ 422 E_AUTHZ_TOO_MANY_SCOPES (nunca parcial), la frontera exacta responde; sin descendantsOf ⇒ 500 aunque no haya grants; descendantsOf jamás se llama desde authorize/list*', async ({
        assert,
      }) => {
        // B3/B2 (tester §5 E · 5, 6, 7 y el test de arquitectura). Una lista
        // truncada en silencio es el peor resultado posible: se lanza. Sin
        // `descendantsOf` no hay `none` (sería un fail-closed mentiroso: el
        // sujeto puede tener scopes). Y `descendantsOf` es abierto: prohibido
        // en el camino de decisión.
        let descendantsCalls = 0
        const descendantsOf = descendantsFrom(tree)
        const authz = managerOver({
          scopes: {
            resolveChain: resolveChainFrom(tree),
            descendantsOf: (scope, options) => {
              descendantsCalls += 1
              return descendantsOf(scope, options)
            },
          },
        })
        const alice = subject()
        const orgs: ScopeRef[] = []
        for (let i = 0; i < 3; i++) {
          const org = await orgUnder(tree, APP_SCOPE)
          await unitUnder(tree, org)
          orgs.push(org)
          await driver.grant(alice, 'org-editor', org)
        }

        await rejectsWith(assert, () => authz.authorizedScopes(alice, 'docs:write', 'organization', { maxScopes: 2 }), {
          status: 422,
          code: 'E_AUTHZ_TOO_MANY_SCOPES',
        })
        const exact = await authz.authorizedScopes(alice, 'docs:write', 'organization', { maxScopes: 3 })
        assert.equal(exact.kind, 'some')
        assert.lengthOf((exact as any).scopes, 3)
        // La cota es sobre la RESPUESTA: 3 units bajo esas orgs con maxScopes 3.
        assert.lengthOf(((await authz.authorizedScopes(alice, 'docs:write', 'unit', { maxScopes: 3 })) as any).scopes, 3)
        const capped = managerOver({ scopes: { resolveChain: resolveChainFrom(tree), descendantsOf, maxScopes: 2 } })
        await rejectsWith(assert, () => capped.authorizedScopes(alice, 'docs:write', 'organization'), { status: 422, code: 'E_AUTHZ_TOO_MANY_SCOPES' })
        // F8: la cota por llamada solo puede BAJAR la del config, nunca subirla.
        await rejectsWith(assert, () => capped.authorizedScopes(alice, 'docs:write', 'organization', { maxScopes: 100 }), { status: 422, code: 'E_AUTHZ_TOO_MANY_SCOPES' })
        // F8: se corta antes de bajar (3 orgs directas > 2: ni una llamada a descendantsOf).
        descendantsCalls = 0
        await rejectsWith(assert, () => authz.authorizedScopes(alice, 'docs:write', 'organization', { maxScopes: 2 }), { status: 422, code: 'E_AUTHZ_TOO_MANY_SCOPES' })
        assert.equal(descendantsCalls, 0)

        const noDescendants = managerOver({ scopes: { resolveChain: resolveChainFrom(tree) } })
        const expected = { status: 500, code: 'E_AUTHZ_NO_DESCENDANTS_RESOLVER' }
        await rejectsWith(assert, () => noDescendants.authorizedScopes(alice, 'docs:write', 'organization'), expected)
        await rejectsWith(assert, () => noDescendants.authorizedScopes(subject(), 'docs:write', 'organization'), expected)

        // Arquitectura: el camino de decisión y los list* no tocan descendantsOf.
        descendantsCalls = 0
        const unit = (await descendantsOf(orgs[0], { maxNodes: 10 }))![0]
        await authz.authorize(alice, 'docs:write', unit)
        await authz.authorizeMany(alice, 'docs:write', [unit, orgs[1]])
        await authz.hasRole(alice, 'org-editor', unit)
        await authz.listScopes(alice, 'docs:write')
        await authz.listRoles(alice, orgs[0])
        await authz.listRoleScopes(alice, 'organization')
        await authz.listSubjects('org-editor', orgs[0])
        await authz.effectivePermissions(alice, unit)
        await authz.listDenies(alice)
        await authz.isWithin(unit, orgs[0])
        await authz.grant(alice, 'unit-editor', unit, { within: orgs[0] })
        await authz.deny(alice, 'docs:read', unit)
        assert.equal(descendantsCalls, 0)
        await authz.authorizedScopes(alice, 'docs:write', 'unit')
        assert.isAbove(descendantsCalls, 0)
      })

      // 3E · P4: la API de DELEGACIÓN entera cuelga de `purgeRole`. Un rol
      // local en un driver que no sabe purgarlo es estado que nada puede
      // borrar: ni `deleteScopedRole` ni `scopes.detached` de ese scope
      // volverían a funcionar NUNCA. Por eso su policy solo se juzga con la
      // capacidad, y la cara `false` juzga que se diga ANTES de escribir.
      caseFor('purgeRole', {
        whenTrue: () => {
        since('2.2', 'defineScopedRole: el rol que el administrador de A delega concede en A y sus descendientes y no fuera; effectivePermissions y authorizedScopes respetan el owner; otro proceso (otro memo) lo ve en su siguiente pregunta; updateScopedRole cambia lo que concede; fuera de la policy ⇒ 422 sin escribir', async ({
          assert,
        }) => {
          // 3B · B3 (+ B7: la versión compartida sube en la misma transacción).
          // La policy completa se juzga en `manager.spec`; aquí, que el rol
          // definido por la API es un rol del DRIVER como cualquier otro, en
          // ambos drivers, y que la delegación tiene barreras.
          const delegable = ['docs:read', 'docs:write', 'billing:read', 'org:settings']
          const twin = harness.makeTwin ? await harness.makeTwin(driver, tree) : twinOf(driver)
          const here = managerOver({ delegablePermissions: delegable })
          const there = managerOver({ delegablePermissions: delegable }, twin)
          const admin = subject()
          const adminB = subject()
          const bob = subject()
          const orgA = await orgUnder(tree, APP_SCOPE)
          const orgB = await orgUnder(tree, APP_SCOPE)
          const unitA1 = await unitUnder(tree, orgA)
          const unitA1x = await unitUnder(tree, unitA1)
          const unitA2 = await unitUnder(tree, orgA)
          const unitB1 = await unitUnder(tree, orgB)
          await driver.grant(admin, 'org-admin', orgA)
          await driver.grant(adminB, 'org-admin', orgB)

          const lead = await here.defineScopedRole(admin, orgA, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'] })
          assert.deepEqual(lead, { uuid: lead.uuid, slug: 'lead', scopeType: 'unit', owner: `organization|${orgA.uuid}`, rank: 20 })
          await here.grant(bob, 'lead', unitA1, { within: orgA })
          assert.isTrue(await driver.authorize(bob, 'docs:write', unitA1))
          assert.isTrue(await driver.authorize(bob, 'docs:write', unitA1x))
          assert.isFalse(await driver.authorize(bob, 'docs:write', unitA2), 'la asignación es en unitA1: no en la hermana')
          assert.isFalse(await driver.authorize(bob, 'docs:write', unitB1))
          assert.isFalse(await driver.authorize(bob, 'docs:read', unitA1))
          // Otro proceso: sin señal en memoria, por la versión compartida.
          assert.isTrue(await there.authorize(bob, 'docs:write', unitA1x))
          assert.isTrue(await there.hasRole(bob, 'lead', unitA1x))
          assert.deepEqual(await there.listRoles(bob, unitA1), ['lead'])
          assert.deepEqual(await there.effectivePermissions(bob, unitA1x), ['docs:write'])
          assert.deepEqual(await here.effectivePermissions(bob, unitB1), [])
          const listed = await here.authorizedScopes(bob, 'docs:write', 'unit')
          assert.equal(listed.kind, 'some')
          assert.deepEqual(scopeKeys((listed as { scopes: ScopeRef[] }).scopes), scopeKeys([unitA1, unitA1x]))
          await rejectsWith(assert, () => here.grant(bob, 'lead', unitB1, { within: orgB }), { status: 422, code: 'E_AUTHZ_ROLE_NOT_VISIBLE' })
          await rejectsWith(assert, () => there.grant(bob, 'lead', unitB1), { status: 422, code: 'E_AUTHZ_ROLE_NOT_VISIBLE' })

          // updateScopedRole: lo que concede cambia en el acto, en los dos memos.
          await here.updateScopedRole(admin, lead.uuid, { permissions: ['docs:read'] })
          assert.isFalse(await driver.authorize(bob, 'docs:write', unitA1x))
          assert.isTrue(await driver.authorize(bob, 'docs:read', unitA1x))
          assert.isFalse(await there.authorize(bob, 'docs:write', unitA1x))
          assert.deepEqual(await there.effectivePermissions(bob, unitA1x), ['docs:read'])

          // Barreras (422, nada escrito): permiso no delegable/no efectivo, deny del actor (C2),
          // rank ≥ actor, composición por nivel (B5), colisión con un global, owner raíz, otro tenant.
          const spec = { slug: 'lead2', scopeType: 'unit', rank: 20, permissions: ['docs:write'] }
          await rejectsWith(assert, () => managerOver().defineScopedRole(admin, orgA, spec), { status: 422, code: 'E_AUTHZ_PERMISSION_NOT_DELEGABLE' })
          await rejectsWith(assert, () => here.defineScopedRole(adminB, orgA, spec), { status: 422, code: 'E_AUTHZ_PERMISSION_NOT_DELEGABLE' })
          await driver.deny(admin, 'docs:write', orgA)
          await rejectsWith(assert, () => here.defineScopedRole(admin, orgA, spec), { status: 422, code: 'E_AUTHZ_PERMISSION_NOT_DELEGABLE' })
          await driver.removeDeny(admin, 'docs:write', orgA)
          await rejectsWith(assert, () => here.defineScopedRole(admin, orgA, { ...spec, rank: 50 }), { status: 422, code: 'E_AUTHZ_RANK_EXCEEDED' })
          await rejectsWith(assert, () => here.defineScopedRole(admin, orgA, { ...spec, permissions: ['org:settings'] }), { status: 422, code: 'E_AUTHZ_ROLE_NOT_ASSIGNABLE_AT' })
          await rejectsWith(assert, () => here.defineScopedRole(admin, orgA, { ...spec, slug: 'unit-editor' }), { status: 422, code: 'E_AUTHZ_CATALOG_CONFLICT' })
          await rejectsWith(assert, () => here.defineScopedRole(admin, APP_SCOPE, spec), { status: 422, code: 'E_AUTHZ_INVALID_IDENTITY' })
          await rejectsWith(assert, () => here.defineScopedRole(admin, orgB, spec), { status: 422, code: 'E_AUTHZ_PERMISSION_NOT_DELEGABLE' })
          await rejectsWith(assert, () => here.grant(bob, 'lead2', unitA1), { status: 422, code: 'E_AUTHZ_UNKNOWN_ROLE' })
          assert.isNull((await new CatalogCache().view()).rolesNamed('lead2', 'unit')[0] ?? null)
          // Y con la policy en regla, el mismo spec escribe.
          const lead2 = await here.defineScopedRole(admin, orgA, spec)
          await there.grant(bob, 'lead2', unitA2, { within: orgA })
          assert.isTrue(await driver.authorize(bob, 'docs:write', unitA2))
          assert.equal(lead2.owner, lead.owner)
        })

        // 3E · R2 (tester): la carrera de M2 es un PAR de capacidad. Con
        // escrituras de catálogo serializadas (PG/MySQL, cerrojo sobre la
        // fila de versión) el juez exige lo que el README promete —
        // exactamente un ganador y 422 para el perdedor—; sin ellas (SQLite
        // bloquea la base entera) solo lo innegociable: nunca dos, y el
        // perdedor no escribe. Aceptar `oneOf([422, 503])` en todas partes
        // dejaba vivo un mutante que convertía la colisión en un 503.
        const raceOfDefines = (serialized: boolean) =>
          since(
            '2.2',
            serialized
              ? 'dos defineScopedRole del MISMO (slug, nivel) con owners de la misma cadena, en paralelo y con memos distintos: EXACTAMENTE uno gana y el perdedor es 422 E_AUTHZ_CATALOG_CONFLICT — la unicidad no es una carrera'
              : 'dos defineScopedRole del MISMO (slug, nivel) con owners de la misma cadena, en paralelo y con memos distintos: nunca dos ganadores y el perdedor no escribe (sin escrituras de catálogo serializadas su transacción puede morir con 503)',
            async ({ assert }) => {
          // 3D · M2 (auditor V2 🔴 A, reproducido en PG: los dos se insertaban
          // porque el unique de la base es (slug, scope_type, owner_scope_key)
          // y cada uno comprobaba la colisión contra SU foto del memo). Ahora
          // las escrituras del catálogo van en serie (cerrojo sobre la fila de
          // `authz_catalog_version`) y la colisión se re-comprueba DENTRO de la
          // transacción, leyendo la base.
          const delegable = ['docs:read', 'docs:write', 'billing:read']
          const twin = harness.makeTwin ? await harness.makeTwin(driver, tree) : twinOf(driver)
          const here = managerOver({ delegablePermissions: delegable })
          const there = managerOver({ delegablePermissions: delegable }, twin)
          const admin = subject()
          const orgA = await orgUnder(tree, APP_SCOPE)
          const unitA1 = await unitUnder(tree, orgA)
          await driver.grant(admin, 'org-admin', orgA)
          // Los dos memos calientes ANTES de escribir: cada uno con su foto.
          assert.deepEqual(await here.listRoles(admin, orgA), ['org-admin'])
          assert.deepEqual(await there.listRoles(admin, orgA), ['org-admin'])

          const spec = { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'] }
          const results = await Promise.allSettled([
            here.defineScopedRole(admin, orgA, spec),
            there.defineScopedRole(admin, unitA1, { ...spec, permissions: ['docs:read'] }),
          ])
          const ok = results.filter((r) => r.status === 'fulfilled')
          const estado = JSON.stringify(results.map((r) => (r.status === 'rejected' ? `${r.reason?.status} ${r.reason?.code}` : 'ok')))
          if (serialized) {
            // Lo que promete el README con el cerrojo de la fila de versión.
            assert.lengthOf(ok, 1, `exactamente un ganador (${estado})`)
          } else {
            // Sin serialización garantizada: nunca dos. Cuántos confirman
            // depende del motor — SQLite bloquea la base entera y el segundo
            // escritor puede recibir `SQLITE_BUSY`, un fallo de backend
            // legítimo (503) porque su transacción NO se aplicó.
            assert.isAtMost(ok.length, 1, `nunca dos ganadores (${estado})`)
          }
          for (const rejected of results.filter((r) => r.status === 'rejected')) {
            const error = (rejected as PromiseRejectedResult).reason
            if (serialized) {
              assert.equal(error?.status, 422, `el perdedor choca, no se cae: ${error?.code} ${error?.message}`)
              assert.equal(error?.code, 'E_AUTHZ_CATALOG_CONFLICT')
            } else {
              assert.oneOf(error?.status, [422, 503], `el perdedor no escribe: ${error?.code} ${error?.message}`)
              if (error?.status === 422) assert.equal(error?.code, 'E_AUTHZ_CATALOG_CONFLICT')
            }
          }
          let named = (await new CatalogCache().view()).rolesNamed('lead', 'unit')
          assert.lengthOf(named, ok.length, 'en la base hay exactamente lo que se confirmó')
          for (const winner of ok) assert.equal(named[0].uuid, (winner as PromiseFulfilledResult<CatalogRole>).value.uuid)
          if (named.length === 0) {
            await here.defineScopedRole(admin, orgA, spec)
            named = (await new CatalogCache().view()).rolesNamed('lead', 'unit')
          }
          assert.lengthOf(named, 1)

          // Y en SERIE —sin carrera que confunda— el segundo `define` choca
          // SIEMPRE y con el error preciso, venga del owner que venga.
          const conflicto = { status: 422, code: 'E_AUTHZ_CATALOG_CONFLICT' }
          await rejectsWith(assert, () => there.defineScopedRole(admin, orgA, spec), conflicto)
          await rejectsWith(assert, () => there.defineScopedRole(admin, unitA1, spec), conflicto)
          await rejectsWith(assert, () => here.defineScopedRole(admin, orgA, spec), conflicto)
          assert.lengthOf((await new CatalogCache().view()).rolesNamed('lead', 'unit'), 1)
          // Y por tanto el slug no es ambiguo en ninguna parte de la cadena.
          const bob = subject()
          await driver.grant(bob, 'lead', unitA1)
          assert.isTrue(await driver.hasRole(bob, 'lead', unitA1))

          // El RE-CHEQUEO dentro de la transacción (3D · M2 b), que hasta 3E
          // no ejercitaba ningún caso (tester R2: el mutante «sin
          // re-chequeo», forzado a serie, pasaba la suite entera): el rol
          // homónimo aparece SIN subir la versión del catálogo —exactamente
          // lo que ve un escritor cuya foto se tomó antes de que el otro
          // proceso confirmara—, así que el chequeo barato contra el memo lo
          // deja pasar y solo la relectura de la BASE puede pararlo.
          await insertRoleUnseen({ slug: 'sigiloso', scopeType: 'unit', owner: scopeKey(orgA) })
          await rejectsWith(assert, () => here.defineScopedRole(admin, unitA1, { ...spec, slug: 'sigiloso' }), conflicto)
          assert.lengthOf(await rowsNamed('sigiloso', 'unit'), 1, 'no se escribe a ciegas sobre lo que el memo no vio')
        })
        caseFor('serializedCatalogWrites', {
          whenTrue: () => raceOfDefines(true),
          whenFalse: () => raceOfDefines(false),
        })

        since('2.2', 'effectivePermissions es EXACTAMENTE {p | authorize(p)} aunque en la cadena haya un homónimo del rol del holder, y defineScopedRole no delega lo que solo tiene el homónimo (la policy mide por uuid, nunca del slug al catálogo)', async ({
          assert,
        }) => {
          // 3D · M1 (auditor V1 🔴, escalada reproducida en PG): `rolesInChain`
          // devolvía el SLUG y el manager lo volvía a resolver con «el owner
          // más cercano gana», así que `effectivePermissions(pepe, U1)` decía
          // `docs:write` mientras `authorize` decía `false`, y con eso `pepe`
          // delegaba `docs:write` a un títere. Ahora el puerto habla por uuid.
          const delegable = ['docs:read', 'docs:write', 'billing:read']
          const here = managerOver({ delegablePermissions: delegable })
          const pepe = subject()
          const titere = subject()
          const orgA = await orgUnder(tree, APP_SCOPE)
          const unitU1 = await unitUnder(tree, orgA)
          // El rol de pepe: `lead@unit` owner orgA, con SOLO docs:read.
          const suyo = await localRole(orgA, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:read'] })
          await driver.grant(pepe, { uuid: suyo }, unitU1)
          // Y el homónimo, owner de la propia unit, con docs:write. Pepe NO lo tiene.
          const ajeno = await localRole(unitU1, { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'] })
          assert.notEqual(suyo, ajeno)

          assert.isTrue(await driver.authorize(pepe, 'docs:read', unitU1))
          assert.isFalse(await driver.authorize(pepe, 'docs:write', unitU1))
          assert.deepEqual(await here.effectivePermissions(pepe, unitU1), ['docs:read'], 'exactamente {p | authorize(p)}')
          assert.deepEqual(await here.effectivePermissions(pepe, orgA), [])

          // La policy de delegación mide lo mismo: docs:write no es suyo.
          await rejectsWith(
            assert,
            () => here.defineScopedRole(pepe, unitU1, { slug: 'jefe', scopeType: 'unit', rank: 10, permissions: ['docs:write'] }),
            { status: 422, code: 'E_AUTHZ_PERMISSION_NOT_DELEGABLE' }
          )
          assert.deepEqual((await new CatalogCache().view()).rolesNamed('jefe', 'unit'), [], 'nada escrito')
          // Lo que SÍ es suyo se delega, y el rank del homónimo tampoco se hereda.
          const jefe = await here.defineScopedRole(pepe, unitU1, { slug: 'jefe', scopeType: 'unit', rank: 10, permissions: ['docs:read'] })
          await driver.grant(titere, { uuid: jefe.uuid }, unitU1)
          assert.isTrue(await driver.authorize(titere, 'docs:read', unitU1))
          assert.isFalse(await driver.authorize(titere, 'docs:write', unitU1), 'la escalada del auditor, cerrada')
          await rejectsWith(
            assert,
            () => here.defineScopedRole(pepe, unitU1, { slug: 'jefe2', scopeType: 'unit', rank: 20, permissions: ['docs:read'] }),
            { status: 422, code: 'E_AUTHZ_RANK_EXCEEDED' }
          )
        })
        },
        // La cara `false` la juzga el par `purgeRole` de arriba (3E · P4):
        // `defineScopedRole` es 500 antes de escribir, así que esta policy
        // no existe para un driver que no sabe purgar.
      })
      },
      whenFalse: () => {
        since('2.1', 'sin listDenies en el puerto: listDenies, effectivePermissions y authorizedScopes son 500 E_AUTHZ_UNSUPPORTED nombrándolo (nunca un [] simulado); el puerto 2.0 sigue respondiendo', async ({
          assert,
        }) => {
          // 2E · I5 (tester ⚪). Hasta aquí solo lo vigilaba `manager.spec`
          // con un driver falso; ahora lo juzga el contrato sobre el driver
          // real del harness. Un `[]` en su lugar diría «sin denies» y
          // `effectivePermissions` concedería lo denegado.
          assert.notTypeOf((driver as { listDenies?: unknown }).listDenies, 'function', 'el harness declara listDenies: false y el driver lo implementa: declara lo observable')
          const authz = managerOver()
          const alice = subject()
          const orgA = await orgUnder(tree, APP_SCOPE)
          await driver.grant(alice, 'org-editor', orgA)
          for (const [label, call] of [
            ['listDenies', () => authz.listDenies(alice, orgA)],
            ['listDenies (todos)', () => authz.listDenies(alice)],
            ['effectivePermissions', () => authz.effectivePermissions(alice, orgA)],
            ['authorizedScopes', () => authz.authorizedScopes(alice, 'docs:write', 'organization')],
          ] as Array<[string, () => Promise<unknown>]>) {
            try {
              await call()
              assert.fail(`${label}: debería haber rechazado`)
            } catch (error: any) {
              assert.equal(error?.status, 500, `${label}: ${error?.message}`)
              assert.equal(error?.code, 'E_AUTHZ_UNSUPPORTED', label)
              assert.include(String(error?.message), 'listDenies', label)
            }
          }
          // El puerto 2.0 y las primitivas que no restan denies siguen respondiendo.
          assert.isTrue(await authz.authorize(alice, 'docs:write', orgA))
          assert.deepEqual(await authz.authorizeMany(alice, 'docs:write', [orgA, APP_SCOPE]), [true, false])
          assert.deepEqual(await authz.listRoles(alice, orgA), ['org-editor'])
          assert.isTrue(await authz.isWithin(orgA, APP_SCOPE))
        })

        since('2.2', 'sin listDenies en el puerto: defineScopedRole y updateScopedRole son 500 E_AUTHZ_UNSUPPORTED nombrándolo (la policy resta denies del actor: sin ellos no se delega), nada escrito; deleteScopedRole no lo necesita', async ({
          assert,
        }) => {
          // 3B · B3 + 2E · I5: `defineScopedRole` exige `effectivePermissions`
          // del actor (C2: resta denies). Sin `listDenies` no se puede saber
          // si el actor tiene denegado lo que delega ⇒ se DICE, nunca se
          // asume «sin denies» (sería el lavado del auditor).
          const authz = managerOver({ delegablePermissions: ['docs:read', 'docs:write'] })
          const admin = subject()
          const orgA = await orgUnder(tree, APP_SCOPE)
          // El nivel del rol tiene que colgar del owner (3E · P1): la unit
          // existe para que lo que se juzgue aquí sea `listDenies`.
          await unitUnder(tree, orgA)
          await driver.grant(admin, 'org-admin', orgA)
          const spec = { slug: 'lead', scopeType: 'unit', rank: 20, permissions: ['docs:write'] }
          for (const [label, call] of [
            ['defineScopedRole', () => authz.defineScopedRole(admin, orgA, spec)],
          ] as Array<[string, () => Promise<unknown>]>) {
            try {
              await call()
              assert.fail(`${label}: debería haber rechazado`)
            } catch (error: any) {
              assert.equal(error?.status, 500, `${label}: ${error?.message}`)
              assert.equal(error?.code, 'E_AUTHZ_UNSUPPORTED', label)
              assert.include(String(error?.message), 'listDenies', label)
            }
          }
          assert.deepEqual((await new CatalogCache().view()).rolesNamed('lead', 'unit'), [])
          // Un rol local escrito por otro proceso: updateScopedRole con permisos también lo dice; deleteScopedRole no lo necesita.
          const lead = await localRole(orgA, { slug: 'lead', scopeType: 'unit', permissions: ['docs:write'], rank: 20 })
          try {
            await authz.updateScopedRole(admin, lead, { permissions: ['docs:read'] })
            assert.fail('updateScopedRole: debería haber rechazado')
          } catch (error: any) {
            assert.equal(error?.status, 500, error?.message)
            assert.equal(error?.code, 'E_AUTHZ_UNSUPPORTED')
          }
          assert.deepEqual([...(await new CatalogCache().view()).rolePermissionsOf(lead)], ['docs:write'])
          // Sin cambiar permisos no hace falta restar denies: el rank se cambia.
          assert.equal((await authz.updateScopedRole(admin, lead, { rank: 21 })).rank, 21)
        })
      },
    })

    // ── Pares de capacidad ──────────────────────────────────────────────
    // `hierarchyFacts: false` → lo observan N1b/N2/N4/N5 (arriba): el driver
    // responde según el árbol que le resuelve el consumidor, y `tree.move`
    // cambia la respuesta sin escritura. `true` llega en Fase 3b.
    // `injectableClock` tiene su par arriba (2.5 · J1). `transactions` (2.6)
    // y `singleCheckAuthorize` (Fase 3b): pares en su fase; hoy solo pueden
    // declararse `false`.

    caseFor('hierarchyFacts', {
      // Con el árbol en manos del consumidor (`resolveChain`), el árbol
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

          const original = tree.chainOf
          tree.chainOf = async () => {
            throw new Error('el árbol del consumidor está caído')
          }
          try {
            const expected = { status: 503, code: 'E_AUTHZ_RESOLVER_FAILED' }
            await rejectsWith(assert, () => driver.authorize(alice, 'docs:read', org), expected)
            await rejectsWith(assert, () => driver.hasRole(alice, 'editor', org), expected)
          } finally {
            tree.chainOf = original
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
