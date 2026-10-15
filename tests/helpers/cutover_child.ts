/**
 * **Proceso HIJO del runbook de cutover** (`tests/cutover_runbook.spec.ts`, lote R
 * del plan 2.5; metodología M1+M5: «hijo por fase y reloj por IPC»).
 *
 * Un cutover cambia `config.default` entre fases —es un redeploy—, y los comandos
 * resuelven el manager del contenedor GLOBAL (`services/main.ts`), capturado UNA
 * vez al bootear. Así que cada FASE es un proceso: abre la MISMA base que la suite
 * (`bootApp({ reuse })`), construye el manager de ESA fase desde un config real
 * (los dos drivers de roles, los dos de relaciones, el árbol SQL `demo_scopes`, la
 * outbox SQL, el reloj inyectado) y lo registra en el contenedor ANTES de que
 * nadie importe `services/main.js`. Después atiende órdenes del padre por IPC
 * (`process.on('message')`): ejecutar un comando POR EL KERNEL DE ACE
 * (`tests/helpers/ace.ts`), mover el reloj, sembrar, preguntar.
 *
 * **Un manager NUEVO por `exec`.** En producción cada `node ace …` es un proceso
 * nuevo: `authz:freeze` no deja un `#heldFreeze` en memoria que `authz:reconcile`
 * pueda heredar. Reusar un manager entre comandos habría hecho que la pasada
 * «corra dentro de la propia ventana sostenida» en vez de LEER la fila — y la
 * ventana CADUCADA (S2, alpha.10) ya no se observaría. Por eso el binding
 * `authz.manager` es un Proxy que delega en el manager VIGENTE, y cada `exec`
 * lo renueva (los métodos se atan al manager real: los campos privados `#…` no
 * sobreviven a un `this` que sea el proxy).
 *
 *   AUTHZ_TEST_REUSE='{…}' CUTOVER_PHASE='{"default":"database","store":{…}}' \
 *     node --import @poppinss/ts-exec tests/helpers/cutover_child.ts
 */

import { bootApp } from './app.js'

const reuse = JSON.parse(process.env.AUTHZ_TEST_REUSE ?? 'null')
const phase = JSON.parse(process.env.CUTOVER_PHASE ?? 'null')
if (!reuse || !phase || typeof process.send !== 'function') {
  console.error('uso: AUTHZ_TEST_REUSE=<json> CUTOVER_PHASE=<json> cutover_child.ts (con canal IPC)')
  process.exit(2)
}

const HOLDER_TYPES = { users: 'user', admins: 'admin' } as const

const app = await bootApp({ reuse })

// La app GLOBAL (`setApp` la fijó `bootApp`): su contenedor es el que `services/main.js` consulta.
const { default: globalApp } = await import('@adonisjs/core/services/app')
const { default: db } = await import('@adonisjs/lucid/services/db')
const { AuthorizationManager } = await import('../../src/manager.js')
const { RelationsManager } = await import('../../src/relations/manager.js')
const { DatabaseAuthorizationDriver } = await import('../../src/drivers/database_driver.js')
const { DatabaseRelationsDriver } = await import('../../src/drivers/database_relations_driver.js')
const { OpenFgaAuthorizationDriver, OpenFgaRelationsDriver } = await import('../../src/openfga.js')
const { defineRelationsConfig } = await import('../../src/relations/define_relations_config.js')
const { sqlScopeEdges } = await import('../../src/sql_descendants.js')
const { sqlScopeOutbox } = await import('../../src/scope_outbox.js')
const { resolveChainFrom } = await import('../../src/testing/main.js')
const migration = await import('../../src/testing/migration_contract.js')
const { sqlScopeTree } = await import('./sql_scope_tree.js')
const { readFreezeRow, acquireFreeze } = await import('../../src/freeze.js')
const { readAuthzCatalogVersion } = await import('../../src/catalog/catalog_cache.js')
const { aceFor } = await import('./ace.js')

/** La config de relaciones del runbook: `document` (owner ⊆ editor ⊆ viewer) más el `group` built-in. */
export const RUNBOOK_RELATIONS_SPEC = {
  objectTypes: [
    { type: 'document', relations: [{ name: 'owner' }, { name: 'editor', includes: ['owner'] }, { name: 'viewer', includes: ['editor'] }] },
  ],
  holderTypes: ['user', 'admin'],
}

let offsetMs = 0
const clock = () => new Date(Date.now() + offsetMs)
const tree = sqlScopeTree(db)
const chain = resolveChainFrom(tree)
const outbox = sqlScopeOutbox()
const relationsConfig = defineRelationsConfig(RUNBOOK_RELATIONS_SPEC)
const silent = { warn: () => {} }

/**
 * El store de esta corrida. `timeoutMs` amplio a propósito: el servidor del job es
 * COMPARTIDO (otras suites contra el mismo `:8090`) y un 503 por deadline del
 * driver no es lo que este runbook juzga; lo que juzga es el cutover.
 */
function storeOptions() {
  return {
    apiUrl: phase.store.apiUrl as string,
    storeId: phase.store.storeId as string,
    modelId: phase.store.modelId as string,
    timeoutMs: Number(process.env.CUTOVER_RUNBOOK_FGA_TIMEOUT_MS ?? 20_000),
  }
}

/** El config de ESTA fase, como lo declararía `config/authorization.ts` tras el redeploy. */
function phaseConfig(): any {
  return {
    default: phase.default,
    drivers: {
      database: () => new DatabaseAuthorizationDriver({ resolveChain: chain }),
      openfga: () =>
        new OpenFgaAuthorizationDriver({ ...storeOptions(), holderTypes: HOLDER_TYPES, resolveChain: chain, outbox, logger: silent }),
    },
    holderTypes: HOLDER_TYPES,
    scopes: {
      resolveChain: chain,
      enumerateEdges: sqlScopeEdges({ table: 'demo_scopes', uuidColumn: 'uuid', parentColumn: 'parent_uuid', typeColumn: 'type' }),
      outbox,
    },
    clock,
    relations: {
      config: relationsConfig,
      ...(phase.relationsDefault ? { default: phase.relationsDefault } : {}),
      drivers: {
        database: () => new DatabaseRelationsDriver(relationsConfig),
        openfga: () => new OpenFgaRelationsDriver(relationsConfig, { ...storeOptions(), holderTypes: HOLDER_TYPES, logger: silent }),
      },
    },
    warnOnOptInSecurity: false,
  }
}

let current: any = new AuthorizationManager(phaseConfig())
const renew = () => {
  current = new AuthorizationManager(phaseConfig())
}
// El Proxy que delega en el manager VIGENTE (ver el docblock): registrado ANTES de
// que `services/main.js` se importe (lo importan los comandos dentro de `run()`).
const proxy = new Proxy(
  {},
  {
    get(_target, prop) {
      const value = current[prop]
      return typeof value === 'function' ? value.bind(current) : value
    },
    has(_target, prop) {
      return prop in current
    },
  }
)
globalApp.container.singleton('authz.manager', () => proxy as any)

/** Lo que `config/authorization.ts` diría para los comandos que leen `this.app.config` (provision, sync, diff). */
function aceConfig(): any {
  return {
    catalogs: [async () => migration.MIGRATION_CATALOG],
    holderTypes: HOLDER_TYPES,
    openfga: { url: phase.store.apiUrl, storeId: phase.store.storeId, modelId: phase.store.modelId },
    scopes: { resolveChain: chain },
    relations: { config: relationsConfig },
  }
}

let seed: any = null
const reviveSeed = (json: any) => ({ ...json, now: new Date(json.now) })

async function driverNamed(name: string): Promise<any> {
  const driver = await phaseConfig().drivers[name]()
  return typeof driver.withClock === 'function' ? driver.withClock(clock) : driver
}
function relationsManagerOver(name: string): any {
  const driver = phaseConfig().relations.drivers[name]()
  return new RelationsManager(driver, relationsConfig, { clock, driverName: name })
}

async function storeDump(): Promise<string[]> {
  const { OpenFgaClient } = await import('@openfga/sdk')
  const client = new OpenFgaClient({ apiUrl: phase.store.apiUrl, storeId: phase.store.storeId })
  const out: string[] = []
  let continuationToken: string | undefined
  do {
    const page: any = await client.read({}, { pageSize: 100, continuationToken })
    for (const t of page.tuples ?? []) out.push(`${t.key.user}#${t.key.relation}@${t.key.object}`)
    continuationToken = page.continuation_token || undefined
  } while (continuationToken)
  return out.sort()
}

const serializeError = (error: any) =>
  error === undefined || error === null
    ? null
    : { name: error?.constructor?.name, code: error?.code, status: error?.status, message: String(error?.message ?? error) }

async function handle(message: any): Promise<unknown> {
  switch (message.op) {
    case 'exec': {
      renew()
      const loader: any = await import('../../commands/main.js')
      const Command = await loader.getCommand({ commandName: message.command })
      if (!Command) throw new Error(`comando desconocido: ${message.command}`)
      const run = await (await aceFor(Command, { authorization: aceConfig() })).exec(message.argv ?? [])
      return { exitCode: run.exitCode ?? 0, logs: run.logs, error: serializeError(run.error) }
    }
    case 'clock': {
      offsetMs = Number(message.offsetMs)
      return { offsetMs }
    }
    case 'seed': {
      seed = message.seed ? reviveSeed(message.seed) : migration.makeMigrationSeed(clock())
      if (message.plant) {
        await migration.plantMigrationTree(tree, seed)
        await migration.plantMigrationFacts(await driverNamed('database'), seed)
      }
      return seed
    }
    case 'questions': {
      if (!seed) throw new Error('questions: primero `seed`')
      const driver = await driverNamed(message.driver)
      const answers: Record<string, string> = {}
      for (const question of migration.migrationQuestions(seed)) answers[question.id] = await question.ask(driver)
      return answers
    }
    case 'authorize':
      return current.authorize(message.subject, message.permission, message.scope)
    case 'revoke':
      return current.revoke(message.subject, message.role, message.scope)
    case 'deny':
      return current.deny(message.subject, message.permission, message.scope)
    case 'grant':
      return current.grant(message.subject, message.role, message.scope, message.options ?? {})
    case 'relate': {
      const manager = relationsManagerOver(message.driver)
      for (const t of message.tuples) await manager.relate(t.subject, t.relation, t.object, t.partition)
      return message.tuples.length
    }
    case 'check':
      return relationsManagerOver(message.driver).check(message.subject, message.relation, message.object, message.partition)
    case 'enumerateRelations': {
      const page = await relationsManagerOver(message.driver).enumerateRelations(message.partition)
      return page.tuples
        .map((t: any) => {
          const subject = 'object' in t.subject ? `${t.subject.object.type}:${t.subject.object.id}#${t.subject.relation}` : `${t.subject.type}:${t.subject.uuid}`
          return `${t.object.type}:${t.object.id}#${t.relation}@${subject}`
        })
        .sort()
    }
    case 'storeDump':
      return storeDump()
    case 'freezeRow':
      return readFreezeRow({ driver: phase.default })
    case 'acquirePassFreeze':
      return acquireFreeze({ reason: message.reason, holder: message.holder, untilMs: message.untilMs, nowMs: clock().getTime() })
    case 'detach': {
      await tree.detach(message.scope)
      return current.scopes.detached(message.scope)
    }
    case 'deleteScopeRow':
      return db.from('demo_scopes').where('uuid', message.scope.uuid).where('type', message.scope.type).delete()
    case 'catalogVersion':
      return readAuthzCatalogVersion()
    case 'authzCensus': {
      const assignments: any[] = await db.from('authz_assignments').select('holder_type', 'holder_uuid', 'role_uuid', 'scope_type', 'scope_uuid')
      const denies: any[] = await db.from('authz_denies').select('holder_type', 'holder_uuid', 'permission_uuid', 'scope_type', 'scope_uuid')
      return { assignments: assignments.length, denies: denies.length }
    }
    case 'exit':
      return 'bye'
    default:
      throw new Error(`op desconocida: ${message.op}`)
  }
}

process.on('message', async (message: any) => {
  try {
    const result = await handle(message)
    process.send!({ id: message.id, ok: true, result })
    if (message.op === 'exit') {
      await app.teardown()
      process.exit(0)
    }
  } catch (error: any) {
    process.send!({ id: message.id, ok: false, error: serializeError(error) })
  }
})

process.send!({ ready: true, phase: phase.default })
