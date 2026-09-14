/**
 * **2.4.0-alpha.9 · lote A — las banderas de los comandos, por el kernel de
 * ace y con el EFECTO.**
 *
 * El defecto (informes 4 y 5 de COGNITIV, 11-09-2026, sobre alpha.8):
 * `Command.defineFlag(name, options)` de `@adonisjs/ace` construye el flag
 * como `{ name, flagName: string.dashCase(name), required: false, ...options }`
 * y luego hidrata con `Object.defineProperty(this, flag.name, { value:
 * this.parsed.flags[flag.flagName] })`. Pasar **`name: 'dry-run'` en las
 * OPCIONES pisa el nombre de la PROPIEDAD**: el valor cae en `this['dry-run']`
 * y `this.dryRun` queda `undefined`. La opción para renombrar la bandera en la
 * línea de comandos es **`flagName`**; y sin ninguna de las dos,
 * `dashCase(propiedad)` ya produce `--dry-run`.
 *
 * Lo medido con alpha.8: `authz:reconcile --dry-run` **ESCRIBE** (463 tuplas en
 * un store vacío, y por la rama de ÉXITO: el verificador read-only por contrato
 * no lo era), `authz:relations:reconcile --partition-type/--partition-uuid` son
 * inertes ⇒ migra 0 tuplas y reporta ÉXITO, y `--max-age`, `--batch-size`,
 * `--wait-lease-ms`, `--fail-on-shadows`, `--lease-ms` se ignoran en silencio.
 *
 * **El punto ciego que lo permitió** es el que cierra este fichero:
 * `commands.spec.ts` ejecutaba comandos por el kernel pero **nunca con
 * banderas**, y los casos que ponen `cmd.dryRun = true` a mano no ven nada. Así
 * que aquí toda bandera entra por `exec(['--<bandera>=<valor>'])` —el kernel de
 * ace de verdad, `tests/helpers/ace.ts`— y se afirma el EFECTO: filas de
 * `authz_scope_outbox` sin aplicar, cero escrituras en el destino, la partición
 * que llega al motor, el código de salida, la LETRA de la salida, o —donde el
 * efecto es caro— las OPCIONES que llegan al manager, que es el borde donde el
 * valor se consume. Nunca `cmd.<prop>`.
 *
 * Los comandos resuelven el manager del contenedor GLOBAL (`services/main.ts`),
 * no del de la app fixture del harness: el harness es bicéfalo a propósito
 * (`commands.spec.ts`, C-3). Para tener un manager con outbox, con dos drivers
 * o con un espía, estos casos SUSTITUYEN el método concreto del manager global
 * por una delegación al manager montado aquí, y lo restauran en el teardown. Lo
 * sustituido es el CABLEADO (qué manager), nunca el camino de la bandera:
 * `this.dryRun` → opciones → efecto sigue siendo el del comando publicado.
 */

import { test } from '@japa/runner'
import { readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import string from '@poppinss/utils/string'
import db from '@adonisjs/lucid/services/db'
import { v7 as uuidv7 } from 'uuid'
import { aceFor } from './helpers/ace.js'
import authorization from '../services/main.js'
import { AuthorizationManager } from '../src/manager.js'
import { memoryScopeTree, resolveChainFrom } from '../src/testing/main.js'
import { sqlScopeOutbox } from '../src/scope_outbox.js'
import { syncAuthzCatalog } from '../src/catalog/catalog.js'
import { APP_SCOPE } from '../src/types.js'
import { cleanAuthzTables, cleanScopeOutbox } from './helpers/schema.js'
import AuthzScopesRelay from '../commands/authz_scopes_relay.js'
import AuthzScopesRequeue from '../commands/authz_scopes_requeue.js'
import AuthzReconcile from '../commands/authz_reconcile.js'
import AuthzRelationsReconcile from '../commands/authz_relations_reconcile.js'
import AuthzFreeze from '../commands/authz_freeze.js'
import AuthzUnfreeze from '../commands/authz_unfreeze.js'
import AuthzCatalogDiff from '../commands/authz_catalog_diff.js'
import AuthzCatalogPruneOrphans from '../commands/authz_catalog_prune_orphans.js'

const orgScope = () => ({ type: 'organization', uuid: uuidv7() })
const unitScope = () => ({ type: 'unit', uuid: uuidv7() })
const keyOf = (s: any) => `${s.type}|${s.uuid ?? ''}`

/** Un driver de laboratorio que apunta lo que le llega; nada sale a la red. */
function spyDriver() {
  const calls: string[] = []
  const driver: any = {
    authorize: async () => false,
    withClock() {
      return this
    },
    onScopeAttached: async (c: any, p: any) => void calls.push(`attached ${keyOf(c)} → ${keyOf(p)}`),
    onScopeMoved: async (c: any, p: any) => void calls.push(`moved ${keyOf(c)} → ${keyOf(p)}`),
    onScopeDetached: async (c: any) => void calls.push(`detached ${keyOf(c)}`),
    purgeScope: async (c: any) => void calls.push(`purgeScope ${keyOf(c)}`),
  }
  return { driver, calls }
}

/**
 * Sustituye UN método del manager global (el que `services/main.ts` entregó al
 * comando) y devuelve el restaurador. Es el cableado, no el camino de la
 * bandera.
 */
function patchManager(method: string, impl: (...args: any[]) => any): () => void {
  const target: any = authorization
  const had = Object.prototype.hasOwnProperty.call(target, method)
  const previous = had ? Object.getOwnPropertyDescriptor(target, method) : undefined
  Object.defineProperty(target, method, { value: impl, writable: true, configurable: true, enumerable: false })
  return () => {
    if (previous) Object.defineProperty(target, method, previous)
    else delete target[method]
  }
}

/**
 * Cierre del auditor de alpha.10 · R4: `authz:relations:reconcile` resuelve claves, factories y driver
 * ACTIVO desde el manager de servicio (el mismo config que el provider). En la suite ese manager es el
 * global de `bootApp()`, así que para un fixture de config se cablean sus TRES lectores de relaciones
 * con un manager REAL construido desde ese config — lo que el provider haría — durante el `exec`.
 */
function patchRelations(authorizationConfig: any): () => void {
  const fixture = new AuthorizationManager({
    default: authorizationConfig?.default ?? 'database',
    drivers: {},
    ...(authorizationConfig?.relations ? { relations: authorizationConfig.relations } : {}),
    warnOnOptInSecurity: false,
  } as any)
  const undo = ['relationsDriverKey', 'relationsDriverKeys', 'relationsDriverFactory'].map((method) =>
    patchManager(method, (...args: any[]) => (fixture as any)[method](...args))
  )
  return () => undo.reverse().forEach((restore) => restore())
}

/** `aceFor(AuthzRelationsReconcile, { authorization })` con `patchRelations` alrededor de cada `exec`. */
async function relationsAce(options: { authorization?: any }) {
  const ace = await aceFor(AuthzRelationsReconcile, options)
  return {
    ...ace,
    async exec(argv: string[] = []) {
      const restore = patchRelations(options.authorization)
      try {
        return await ace.exec(argv)
      } finally {
        restore()
      }
    },
  }
}

/** Un espía sobre un método del manager global: apunta las OPCIONES y responde lo que se le diga. */
function spyManager(method: string, reply: any = undefined) {
  const seen: any[] = []
  const restore = patchManager(method, async (...args: any[]) => {
    seen.push(args)
    return typeof reply === 'function' ? reply(...args) : reply
  })
  return { seen, restore }
}

/* ══════════════════════════════════════════════════════════════════════════
 * A-G · LA GUARDIA ESTÁTICA. Un comando nuevo con el mismo error nace rojo.
 * ══════════════════════════════════════════════════════════════════════════ */

interface DeclaredFlag {
  file: string
  kind: string
  property: string
  options: string
}

const COMMANDS_DIR = fileURLToPath(new URL('../commands/', import.meta.url))

/**
 * Toda `@flags.<tipo>({ … })` de `commands/` con la propiedad que declara
 * justo debajo. Se lee el FUENTE porque `name: 'only'` —el caso benigno por
 * casualidad— es indistinguible en tiempo de ejecución de no pasarlo.
 */
function declaredFlags(): DeclaredFlag[] {
  const out: DeclaredFlag[] = []
  for (const file of readdirSync(COMMANDS_DIR).filter((f) => f.endsWith('.ts'))) {
    const source = readFileSync(new URL(file, new URL('../commands/', import.meta.url)), 'utf8')
    const re = /@flags\.(boolean|string|number|array)\(([\s\S]*?)\)\s*\r?\n\s*declare\s+([A-Za-z0-9_]+)\s*[:!]/g
    let match: RegExpExecArray | null
    while ((match = re.exec(source)) !== null) {
      out.push({ file, kind: match[1], options: match[2], property: match[3] })
    }
  }
  return out
}

/** `name:` (y no `flagName:`) como clave del objeto de opciones. */
const declaresName = (options: string) => /(?:^|[{,\s])name\s*:/.test(options)
const declaredFlagName = (options: string) => /(?:^|[{,\s])flagName\s*:\s*'([^']+)'/.exec(options)?.[1]

test.group('alpha.9 · A-G · la guardia de las banderas: `name` NUNCA, y la bandera pública es dashCase(propiedad)', () => {
  test('A-G-1 · ninguna opción de `@flags.*` en commands/ declara `name:` — pisa el nombre de la PROPIEDAD y deja la bandera inerte', async ({
    assert,
  }) => {
    const flags = declaredFlags()
    assert.isAbove(flags.length, 20, 'el parser encuentra las banderas de commands/ (si esto baja, el regex se rompió)')
    const culpables = flags
      .filter((f) => declaresName(f.options))
      .map((f) => `${f.file}: @flags.${f.kind}({ name: … }) declare ${f.property}`)
    assert.deepEqual(
      culpables,
      [],
      'ace hace `{ name, flagName: dashCase(name), ...options }` y luego `defineProperty(this, flag.name, …)`: ' +
        '`name` en las OPCIONES pisa el nombre de la PROPIEDAD y el valor cae en `this["la-bandera"]`, ' +
        'con `this.laBandera` en undefined (la bandera queda INERTE). Usa `flagName` para renombrar la ' +
        'bandera pública, o nada: dashCase(propiedad) ya pone el guion.'
    )
  })

  test('A-G-2 · para cada bandera declarada, la bandera pública efectiva es exactamente `dashCase(propiedad)`', async ({
    assert,
  }) => {
    const desajustes: string[] = []
    for (const flag of declaredFlags()) {
      const efectiva = declaredFlagName(flag.options) ?? string.dashCase(flag.property)
      const esperada = string.dashCase(flag.property)
      if (efectiva !== esperada) desajustes.push(`${flag.file}: ${flag.property} ⇒ --${efectiva} (dashCase daría --${esperada})`)
    }
    assert.deepEqual(
      desajustes,
      [],
      'la propiedad tipada y la bandera pública tienen que ser la MISMA cosa escrita de dos maneras: ' +
        'si de verdad hace falta una bandera pública distinta de dashCase(propiedad), es `flagName:` y ' +
        'hay que cambiar esta guardia a propósito (nunca `name:`).'
    )
  })

  test('A-G-3 · y lo mismo visto por ace: en los flags BOOTEADOS de los diez comandos, `flag.name` es la propiedad (sin guiones) y `flag.flagName === dashCase(flag.name)`', async ({
    assert,
  }) => {
    const loader: any = await import('../commands/main.js')
    const metadata: any[] = await loader.getMetaData()
    const propiedades = new Map<string, Set<string>>()
    for (const flag of declaredFlags()) {
      if (!propiedades.has(flag.file)) propiedades.set(flag.file, new Set())
      propiedades.get(flag.file)!.add(flag.property)
    }
    const declaradas = new Set([...propiedades.values()].flatMap((s) => [...s]))
    let vistas = 0
    for (const meta of metadata) {
      const Command: any = await loader.getCommand(meta)
      Command.boot()
      for (const flag of Command.flags as Array<{ name: string; flagName: string }>) {
        vistas++
        assert.notInclude(
          flag.name,
          '-',
          `${meta.commandName}: el flag '${flag.name}' tiene el nombre de la BANDERA donde va el de la PROPIEDAD ` +
            `(alguien pasó \`name: '${flag.name}'\` en las opciones): la propiedad tipada nunca recibirá el valor`
        )
        assert.equal(
          flag.flagName,
          string.dashCase(flag.name),
          `${meta.commandName}: --${flag.flagName} no es dashCase('${flag.name}')`
        )
        assert.isTrue(
          declaradas.has(flag.name),
          `${meta.commandName}: el flag '${flag.name}' no corresponde a ninguna propiedad \`declare\` de commands/`
        )
      }
    }
    assert.isAbove(vistas, 20, 'se han mirado los flags de los diez comandos')
  })
})

/* ══════════════════════════════════════════════════════════════════════════
 * A-1 · `authz:scopes:relay --dry-run`: las dos entradas siguen SIN aplicar.
 * El caso que COGNITIV pide por escrito («un test que ponga cmd.dryRun = true
 * a mano NO lo detecta»).
 * ══════════════════════════════════════════════════════════════════════════ */

test.group('alpha.9 · A-1 · `authz:scopes:relay` con banderas, por el kernel', (group) => {
  const restores: Array<() => void> = []
  group.each.setup(async () => {
    await cleanScopeOutbox(db)
    return async () => {
      while (restores.length) restores.pop()!()
      await cleanScopeOutbox(db)
    }
  })

  /** Un manager con la outbox SQL de verdad y un driver espía. */
  function relayManager(clock?: () => Date) {
    const tree = memoryScopeTree()
    const { driver, calls } = spyDriver()
    const manager = new AuthorizationManager({
      default: 'spy',
      drivers: { spy: () => driver },
      scopes: { resolveChain: resolveChainFrom(tree), outbox: sqlScopeOutbox() },
      warnOnOptInSecurity: false,
      ...(clock === undefined ? {} : { clock }),
    } as any)
    return { manager, tree, calls }
  }

  test('A-1 · EL CASO de COGNITIV: `--dry-run` con DOS entradas pendientes las deja las dos con `applied_at IS NULL` (hoy las aplica)', async ({
    assert,
  }) => {
    const { manager, tree, calls } = relayManager()
    const org = orgScope()
    const unit = unitScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(unit, org)
    await manager.scopes.attached(org, APP_SCOPE)
    await manager.scopes.attached(unit, org)
    assert.lengthOf(await db.from('authz_scope_outbox').select('id'), 2, 'dos entradas encoladas')
    assert.deepEqual(calls, [], 'con outbox nada ha llegado todavía al driver')

    restores.push(patchManager('relayScopeChanges', (options: any) => manager.relayScopeChanges(options)))
    const run = await (await aceFor(AuthzScopesRelay)).exec(['--dry-run'])

    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    const rows: any[] = await db.from('authz_scope_outbox').select('*')
    assert.lengthOf(rows, 2)
    for (const row of rows) {
      assert.isNull(
        row.applied_at ?? null,
        '`--dry-run` es el paso «verificar antes de tocar» del runbook: no puede aplicar NI UNA entrada'
      )
    }
    assert.deepEqual(calls, [], '--dry-run no toca el driver')
    assert.isTrue(
      run.logs.some((l) => l.includes('No se ha aplicado nada: repite sin --dry-run')),
      `la rama de --dry-run en la salida: ${JSON.stringify(run.logs)}`
    )
    assert.notEqual(run.exitCode, undefined)
  })

  test('A-2 · `--max-age=1` con una pendiente vieja ⇒ exit ≠ 0 (hoy nunca dispara: la alarma de edad del runbook)', async ({
    assert,
  }) => {
    // El reloj del manager, 10 minutos por delante del sello de encolado: la
    // cabeza que queda pendiente tiene 600 000 ms y `--max-age=1` la pasa.
    const { manager, tree } = relayManager(() => new Date(Date.now() + 600_000))
    const org = orgScope()
    const otra = orgScope()
    await tree.attach(org, APP_SCOPE)
    await tree.attach(otra, APP_SCOPE)
    await manager.scopes.attached(org, APP_SCOPE)
    await manager.scopes.attached(otra, APP_SCOPE)

    restores.push(patchManager('relayScopeChanges', (options: any) => manager.relayScopeChanges(options)))
    // `--limit=1` (que SÍ funciona hoy: no lleva `name:`) deja una pendiente
    // para que la cola tenga cabeza y la edad exista; el único que decide el
    // código de salida aquí es `--max-age`.
    const conAlarma = await (await aceFor(AuthzScopesRelay)).exec(['--limit=1', '--max-age=1'])

    assert.isUndefined(conAlarma.error, `${conAlarma.error?.constructor?.name}: ${conAlarma.error?.message}`)
    assert.equal(conAlarma.exitCode, 1, `--max-age=1 sobre una cola de 600 000 ms: ${JSON.stringify(conAlarma.logs)}`)
    assert.isTrue(
      conAlarma.logs.some((l) => l.includes('por encima de --max-age=1')),
      `la LETRA de la alarma: ${JSON.stringify(conAlarma.logs)}`
    )
  })

  test('A-3 · `--batch-size` y `--wait-lease-ms` llegan al manager con su valor (hoy llegan `undefined`)', async ({
    assert,
  }) => {
    const spy = spyManager('relayScopeChanges', {
      dryRun: false,
      applied: [],
      wouldApply: [],
      entries: [],
      failures: [],
      missing: [],
      dead: [],
      busy: false,
      remaining: false,
      queue: { oldestPendingAt: null, pendingAgeMs: null },
    })
    restores.push(spy.restore)

    const run = await (await aceFor(AuthzScopesRelay)).exec(['--batch-size=7', '--wait-lease-ms=250'])

    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.lengthOf(spy.seen, 1)
    assert.equal(spy.seen[0][0].batchSize, 7)
    assert.equal(spy.seen[0][0].waitForLeaseMs, 250)
  })
})

/* ══════════════════════════════════════════════════════════════════════════
 * A-4 · `authz:scopes:requeue --wait-lease-ms`.
 * ══════════════════════════════════════════════════════════════════════════ */

test.group('alpha.9 · A-4 · `authz:scopes:requeue --wait-lease-ms`', (group) => {
  const restores: Array<() => void> = []
  group.each.setup(() => async () => {
    while (restores.length) restores.pop()!()
  })

  test('A-4 · `--wait-lease-ms=750` llega a `requeueScopeChanges` (hoy llega `undefined`)', async ({ assert }) => {
    const spy = spyManager('requeueScopeChanges', { requeued: [], overrides: [], forced: false })
    restores.push(spy.restore)

    const run = await (await aceFor(AuthzScopesRequeue)).exec(['--id=12', '--apply', '--wait-lease-ms=750'])

    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.lengthOf(spy.seen, 1)
    assert.deepEqual(spy.seen[0][0], [12], '--id sigue funcionando igual')
    assert.equal(spy.seen[0][1].waitForLeaseMs, 750)
    assert.isTrue(spy.seen[0][1].apply)
  })
})

/* ══════════════════════════════════════════════════════════════════════════
 * A-5 · `authz:reconcile --dry-run`: CERO escrituras en el destino.
 * ══════════════════════════════════════════════════════════════════════════ */

/**
 * Un destino que se comporta como un driver de verdad: escribe en SU store
 * salvo en `--dry-run`. Es el borde donde el valor de la bandera decide si hay
 * escritura, que es justo lo que alpha.8 no respetaba.
 */
function destinoConStore() {
  const store = new Set<string>()
  const seen: any[] = []
  const driver: any = {
    authorize: async () => false,
    store,
    async reconcile(source: any, options: any) {
      seen.push({ source, options })
      const escribiria = ['role:org-editor', 'scope:organization', 'fact:ana@org-editor']
      if (options.dryRun !== true) for (const t of escribiria) store.add(t)
      return {
        to: 'destino',
        dryRun: options.dryRun === true,
        prune: options.prune === true,
        written: escribiria.length,
        updated: 0,
        unchanged: 0,
        extra: 0,
        deleted: 0,
        phases: {
          root: { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
          catalog: { written: 1, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
          tree: { written: 1, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
          facts: { written: 1, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
        },
        skipped: {},
        details: [],
        cycles: [],
        drift: { rootMarker: true, multiParent: [], roleVisibility: 0, pendingRelay: 0, deadRelay: 0 },
        massDelete: false,
      }
    },
  }
  return { driver, store, seen }
}

test.group('alpha.9 · A-5 · `authz:reconcile` con banderas, por el kernel', (group) => {
  const restores: Array<() => void> = []
  group.each.setup(() => async () => {
    while (restores.length) restores.pop()!()
  })

  function reconcileManager(destino: any) {
    const tree = memoryScopeTree()
    return new AuthorizationManager({
      default: 'origen',
      drivers: { origen: () => ({ authorize: async () => false }) as any, destino: () => destino },
      scopes: { resolveChain: resolveChainFrom(tree), enumerateEdges: async () => ({ edges: [], cursor: null }) },
      warnOnOptInSecurity: false,
    } as any)
  }

  test('A-5 · `--dry-run --to=destino --from=origen` ⇒ CERO escrituras en el destino y la rama de dry-run en la salida (hoy escribe y sale por ÉXITO)', async ({
    assert,
  }) => {
    const destino = destinoConStore()
    const manager = reconcileManager(destino.driver)
    restores.push(patchManager('reconcile', (options: any) => manager.reconcile(options)))

    const run = await (await aceFor(AuthzReconcile)).exec(['--to=destino', '--from=origen', '--dry-run'])

    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.equal(destino.store.size, 0, 'el verificador es read-only POR CONTRATO: --dry-run no escribe ni una tupla')
    assert.lengthOf(destino.seen, 1)
    assert.isTrue(destino.seen[0].options.dryRun, 'la bandera llega hasta el DRIVER destino, que es quien decide escribir')
    const texto = run.logs.join('\n')
    assert.isTrue(
      texto.includes('No se ha escrito nada (--dry-run)') || texto.includes('Sin deriva'),
      `la rama de --dry-run en la salida (hoy sale «reconciliado»): ${JSON.stringify(run.logs)}`
    )
    assert.notInclude(texto, 'reconciliado', 'la rama de ÉXITO de una pasada que ESCRIBE no puede salir en un --dry-run')
  })

  test('A-6 · `--allow-mass-delete`, `--batch-size` y `--max-tuples` llegan al manager con su valor (hoy `--allow-mass-delete` cae al lado seguro y los otros dos se ignoran)', async ({
    assert,
  }) => {
    const destino = destinoConStore()
    const manager = reconcileManager(destino.driver)
    restores.push(patchManager('reconcile', (options: any) => manager.reconcile(options)))

    const run = await (await aceFor(AuthzReconcile)).exec([
      '--to=destino',
      '--from=origen',
      '--prune',
      '--allow-mass-delete',
      '--batch-size=25',
      '--max-tuples=4242',
    ])

    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.lengthOf(destino.seen, 1)
    assert.isTrue(destino.seen[0].options.allowMassDelete, '--allow-mass-delete: el seguro no se podía levantar')
    assert.equal(destino.seen[0].options.batchSize, 25)
    assert.equal(destino.seen[0].options.maxTuples, 4242)
  })
})

/* ══════════════════════════════════════════════════════════════════════════
 * alpha.10 · 1 · la dirección RANCIA por el kernel: `--to=<activo> --from=<otro>`.
 * ══════════════════════════════════════════════════════════════════════════ */

test.group('alpha.10 · 1 · `authz:reconcile --to=<activo> --from=<otro>` por el kernel', (group) => {
  const restores: Array<() => void> = []
  group.each.setup(() => async () => {
    while (restores.length) restores.pop()!()
  })

  /** El motor YA sirve desde `destino`: es el despliegue de después del cutover. */
  function activeManager(destino: any) {
    const tree = memoryScopeTree()
    return new AuthorizationManager({
      default: 'destino',
      drivers: { origen: () => ({ authorize: async () => false }) as any, destino: () => destino },
      scopes: { resolveChain: resolveChainFrom(tree), enumerateEdges: async () => ({ edges: [], cursor: null }) },
      warnOnOptInSecurity: false,
    } as any)
  }

  test('alpha.10 · 1a · `--to=<activo> --from=<otro>` ⇒ exit ≠ 0 con la letra y CERO escrituras (hoy re-escribe en el driver activo y sale por ÉXITO)', async ({
    assert,
  }) => {
    const destino = destinoConStore()
    const manager = activeManager(destino.driver)
    restores.push(patchManager('reconcile', (options: any) => manager.reconcile(options)))

    const run = await (await aceFor(AuthzReconcile)).exec(['--to=destino', '--from=origen', '--prune'])

    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.equal(run.exitCode, 1, `la dirección rancia no puede salir en verde: ${JSON.stringify(run.logs)}`)
    assert.equal(destino.store.size, 0, 'ni una tupla escrita en el driver que sirve')
    assert.lengthOf(destino.seen, 0, 'el destino no llega a reconciliar')
    const texto = run.logs.join('\n')
    assert.include(texto, 'resucitaría las revocaciones hechas desde el cutover')
    assert.include(texto, '--allow-stale-source')
  })

  test('alpha.10 · 1d · y SIN `--from` (el origen elegido por descarte) también: exit ≠ 0 y cero escrituras — el guard mira el origen RESUELTO, no la bandera', async ({
    assert,
  }) => {
    const destino = destinoConStore()
    const manager = activeManager(destino.driver)
    restores.push(patchManager('reconcile', (options: any) => manager.reconcile(options)))

    const run = await (await aceFor(AuthzReconcile)).exec(['--to=destino', '--prune'])

    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.equal(run.exitCode, 1, JSON.stringify(run.logs))
    assert.equal(destino.store.size, 0)
    assert.include(run.logs.join('\n'), 'POR DESCARTE')
  })

  test('alpha.10 · 1b · con `--allow-stale-source` la pasada ENTRA (la bandera llega por el kernel, sin `name:`)', async ({
    assert,
  }) => {
    const destino = destinoConStore()
    const manager = activeManager(destino.driver)
    restores.push(patchManager('reconcile', (options: any) => manager.reconcile(options)))

    const run = await (await aceFor(AuthzReconcile)).exec(['--to=destino', '--from=origen', '--allow-stale-source'])

    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.lengthOf(destino.seen, 1)
    assert.equal(destino.store.size, 3, 'la decisión humana escribe')
    assert.include(run.logs.join('\n'), 'Levantada a sabiendas con --allow-stale-source')
  })

  test('alpha.10 · 1c · en `--dry-run` no lanza: lo avisa y sale ≠ 0 (es deriva), sin escribir', async ({ assert }) => {
    const destino = destinoConStore()
    const manager = activeManager(destino.driver)
    restores.push(patchManager('reconcile', (options: any) => manager.reconcile(options)))

    const run = await (await aceFor(AuthzReconcile)).exec(['--to=destino', '--from=origen', '--dry-run'])

    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.equal(run.exitCode, 1)
    assert.equal(destino.store.size, 0)
    assert.include(run.logs.join('\n'), 'dirección RANCIA')
  })
})

/* ══════════════════════════════════════════════════════════════════════════
 * A-7 · `authz:relations:reconcile --partition-type/--partition-uuid`.
 * ══════════════════════════════════════════════════════════════════════════ */

test.group('alpha.9 · A-7 · `authz:relations:reconcile --partition-*`', () => {
  /** Un driver de relaciones de laboratorio que apunta la PARTICIÓN que le piden. */
  function relationsDriver(tuples: any[] = []) {
    const particiones: any[] = []
    const driver: any = {
      // `capabilities` es una PROPIEDAD del puerto de relaciones, no un método.
      capabilities: { enumerateRelations: true, expiry: true },
      async enumerateRelations(partition: any) {
        particiones.push(partition)
        return { tuples, cursor: null }
      },
      async relate() {},
      async unrelate() {},
    }
    return { driver, particiones }
  }

  test('A-7 · la partición que llega al motor es la PEDIDA, no `{app,null}` (hoy migra 0 y reporta éxito)', async ({
    assert,
  }) => {
    const origen = relationsDriver()
    const destino = relationsDriver()
    const uuid = uuidv7()
    const ace = await relationsAce({
      authorization: { relations: { drivers: { origen: () => origen.driver, destino: () => destino.driver } } },
    })

    const run = await ace.exec([
      '--to=destino',
      '--from=origen',
      '--dry-run',
      '--partition-type=organization',
      `--partition-uuid=${uuid}`,
    ])

    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.isAbove(origen.particiones.length, 0, 'el origen se enumeró')
    for (const partition of origen.particiones) {
      assert.deepEqual(
        partition,
        { type: 'organization', uuid },
        'con --partition-type/--partition-uuid inertes la pasada barría `{app,null}`: migraba 0 tuplas y decía ÉXITO'
      )
    }
  })

  test('A-7b · media pareja de banderas NO es silencio: `--partition-uuid` sin `--partition-type` sale ≠ 0 y no enumera nada (cierre alpha.9, 🟡 B del auditor)', async ({
    assert,
  }) => {
    const origen = relationsDriver()
    const destino = relationsDriver()
    const ace = await relationsAce({
      authorization: { relations: { drivers: { origen: () => origen.driver, destino: () => destino.driver } } },
    })

    const run = await ace.exec(['--to=destino', '--from=origen', '--dry-run', `--partition-uuid=${uuidv7()}`])

    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.equal(run.exitCode, 1, 'una errata del runbook no puede reconciliar la RAÍZ en silencio y decir éxito')
    assert.deepEqual(origen.particiones, [], 'y no llega a enumerar nada')
    assert.isTrue(
      run.logs.some((line: string) => line.includes('--partition-type')),
      `el error dice qué falta: ${JSON.stringify(run.logs)}`
    )
  })

  test('A-7c · y al revés: `--partition-type` sin `--partition-uuid` también sale ≠ 0 (antes: uuid vacío)', async ({
    assert,
  }) => {
    const origen = relationsDriver()
    const destino = relationsDriver()
    const ace = await relationsAce({
      authorization: { relations: { drivers: { origen: () => origen.driver, destino: () => destino.driver } } },
    })

    const run = await ace.exec(['--to=destino', '--from=origen', '--dry-run', '--partition-type=organization'])

    assert.equal(run.exitCode, 1)
    assert.deepEqual(origen.particiones, [])
  })

  test('alpha.10 · 5 · A-7d · `--partition-type=app --partition-uuid=<x>` es pareja COMPLETA que caía en la raíz en silencio: sale ≠ 0 y no enumera nada (5.º punto del sexto informe de COGNITIV)', async ({
    assert,
  }) => {
    const origen = relationsDriver()
    const destino = relationsDriver()
    const ace = await relationsAce({
      authorization: { relations: { drivers: { origen: () => origen.driver, destino: () => destino.driver } } },
    })

    const run = await ace.exec(['--to=destino', '--from=origen', '--dry-run', '--partition-type=app', `--partition-uuid=${uuidv7()}`])

    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.equal(run.exitCode, 1, `la raíz no lleva uuid: una errata así no puede reconciliar app y decir éxito (${JSON.stringify(run.logs)})`)
    assert.deepEqual(origen.particiones, [], 'y no llega a enumerar nada')
    assert.include(run.logs.join('\n'), 'la partición raíz no lleva uuid')

    // Gemelo en la API (la que llama un bucle por particiones): misma trampa, 500.
    const { reconcileRelations } = await import('../src/relations/reconcile.js')
    let caught: any
    try {
      await reconcileRelations({ from: origen.driver, to: destino.driver, partition: { type: 'app', uuid: 'x' } as any, dryRun: true })
    } catch (error) {
      caught = error
    }
    assert.equal(caught?.code, 'E_AUTHZ_CONFIG')
    assert.include(String(caught?.message), 'la partición raíz no lleva uuid')

    // Negativo: `--partition-type=app` a secas sigue siendo la raíz, válida.
    const raiz = await ace.exec(['--to=destino', '--from=origen', '--dry-run', '--partition-type=app'])
    assert.notEqual(raiz.exitCode, 1, JSON.stringify(raiz.logs))
    assert.deepEqual(origen.particiones.at(-1), { type: 'app', uuid: null })
  })
})

/* ══════════════════════════════════════════════════════════════════════════
 * alpha.10 · S1 · la dirección RANCIA en `authz:relations:reconcile` (auditoría
 * de sistema sobre alpha.9, 🔴 S1; gemelo del guard de `manager.reconcile`).
 * ══════════════════════════════════════════════════════════════════════════ */

test.group('alpha.10 · S1 · `authz:relations:reconcile` hacia el driver de relaciones ACTIVO', (group) => {
  const resetRow = async () => {
    await db.from('authz_catalog_version').where('id', 2).update({ freeze_reason: null, freeze_holder: null, freeze_until_ms: null })
  }
  group.each.setup(() => resetRow)

  const APP = { type: 'app', uuid: null }
  const share = (uuid: string, doc: string) => ({
    subject: { type: 'user', uuid },
    relation: 'viewer',
    object: { type: 'document', id: doc },
    partition: APP,
    expiresAt: null,
  })
  const key = (t: any) => `${t.object.type}:${t.object.id}#${t.relation}@${t.subject.type}:${t.subject.uuid}`

  /** El doble del auditor: un driver de relaciones con su «store», que apunta escrituras y borrados. */
  function relationsDouble(initial: any[]) {
    const tuples = new Map<string, any>(initial.map((t) => [key(t), t]))
    const writes: string[] = []
    const deletes: string[] = []
    const driver: any = {
      capabilities: { enumerateRelations: true, expiry: true },
      async enumerateRelations() {
        return { tuples: [...tuples.values()], cursor: null }
      },
      async relate(subject: any, relation: string, object: any, partition: any) {
        const t = { subject, relation, object, partition, expiresAt: null }
        tuples.set(key(t), t)
        writes.push(key(t))
      },
      async unrelate(subject: any, relation: string, object: any, partition: any) {
        const k = key({ subject, relation, object, partition })
        tuples.delete(k)
        deletes.push(k)
      },
    }
    return { driver, tuples, writes, deletes }
  }

  /** Tras el cutover: `authz_relations` (database) congelada con la compartición RETIRADA de u-old; el store vivo con la NUEVA de u-new. */
  async function tras(config: Record<string, unknown>) {
    const database = relationsDouble([share('u-old', 'd1')])
    const openfga = relationsDouble([share('u-new', 'd2')])
    const ace = await relationsAce({
      authorization: { ...config, relations: { ...((config.relations as any) ?? {}), drivers: { database: () => database.driver, openfga: () => openfga.driver } } },
    })
    return { database, openfga, ace }
  }

  test('S1a · `--to=openfga` SIN --from con `openfga` activo ⇒ exit ≠ 0 y la compartición retirada NO resucita (alpha.9: la re-escribía y salía en verde)', async ({
    assert,
  }) => {
    const { openfga, ace } = await tras({ default: 'openfga' })
    const run = await ace.exec(['--to=openfga'])
    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.equal(run.exitCode, 1, JSON.stringify(run.logs))
    assert.deepEqual(openfga.writes, [], 'document:d1#viewer@user:u-old sigue retirada')
    const texto = run.logs.join('\n')
    assert.include(texto, 'resucitaría las comparticiones retiradas desde el cutover')
    assert.include(texto, '--allow-stale-source')
  })

  test('S1b · con `--prune` tampoco: la compartición creada DESPUÉS del cutover sigue viva', async ({ assert }) => {
    const { openfga, ace } = await tras({ default: 'openfga' })
    const run = await ace.exec(['--to=openfga', '--prune'])
    assert.equal(run.exitCode, 1, JSON.stringify(run.logs))
    assert.deepEqual(openfga.deletes, [])
    assert.isTrue(openfga.tuples.has('document:d2#viewer@user:u-new'))
    assert.isFalse(openfga.tuples.has('document:d1#viewer@user:u-old'))
  })

  test('S1c · `relations.default` MANDA sobre `default`: `default: database` + `relations.default: openfga` ⇒ `--to=openfga` también se niega', async ({
    assert,
  }) => {
    const { openfga, ace } = await tras({ default: 'database', relations: { default: 'openfga' } })
    const run = await ace.exec(['--to=openfga', '--from=database'])
    assert.equal(run.exitCode, 1, JSON.stringify(run.logs))
    assert.deepEqual(openfga.writes, [])
  })

  test('S1d · `--dry-run` no lanza: avisa, sale ≠ 0 y no escribe; `--allow-stale-source` es la decisión humana y entra', async ({
    assert,
  }) => {
    const seco = await tras({ default: 'openfga' })
    const dry = await seco.ace.exec(['--to=openfga', '--dry-run'])
    assert.isUndefined(dry.error, `${dry.error?.constructor?.name}: ${dry.error?.message}`)
    assert.equal(dry.exitCode, 1)
    assert.deepEqual(seco.openfga.writes, [])
    assert.include(dry.logs.join('\n'), 'dirección RANCIA')

    const humano = await tras({ default: 'openfga' })
    const run = await humano.ace.exec(['--to=openfga', '--allow-stale-source'])
    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.deepEqual(humano.openfga.writes, ['document:d1#viewer@user:u-old'], 'a sabiendas')
    assert.include(run.logs.join('\n'), 'Levantada a sabiendas')
  })

  test('negativos · el cutover LEGÍTIMO (`default: database`, `--to=openfga` por descarte) y la vuelta ANTES de cambiar default (`default: openfga`, `--to=database`) pasan', async ({
    assert,
  }) => {
    const ida = await tras({ default: 'database' })
    const runIda = await ida.ace.exec(['--to=openfga'])
    assert.isUndefined(runIda.error, `${runIda.error?.constructor?.name}: ${runIda.error?.message}`)
    assert.notEqual(runIda.exitCode, 1, JSON.stringify(runIda.logs))
    assert.deepEqual(ida.openfga.writes, ['document:d1#viewer@user:u-old'], 'la migración de siempre')

    const vuelta = await tras({ default: 'openfga' })
    const runVuelta = await vuelta.ace.exec(['--to=database', '--from=openfga'])
    assert.isUndefined(runVuelta.error, `${runVuelta.error?.constructor?.name}: ${runVuelta.error?.message}`)
    assert.notEqual(runVuelta.exitCode, 1, JSON.stringify(runVuelta.logs))
    assert.deepEqual(vuelta.database.writes, ['document:d2#viewer@user:u-new'])
  })

  /** Un manager REAL con `relations.drivers` (lo que el provider construye): las factories se cuentan. */
  function relationsManager(config: { default: string; relationsDefault?: string; drivers: Record<string, () => any> }) {
    const built: string[] = []
    const counted: Record<string, () => any> = {}
    const wrapped = new Map<Function, () => any>()
    for (const [k, f] of Object.entries(config.drivers)) {
      // Una factory COMPARTIDA por dos claves sigue siendo UNA función (el alias).
      if (!wrapped.has(f)) wrapped.set(f, () => (built.push(k), f()))
      counted[k] = wrapped.get(f)!
    }
    const manager = new AuthorizationManager({
      default: config.default,
      drivers: { [config.default]: () => spyDriver().driver },
      relations: { ...(config.relationsDefault ? { default: config.relationsDefault } : {}), drivers: counted },
      scopes: { resolveChain: resolveChainFrom(memoryScopeTree()) },
      warnOnOptInSecurity: false,
    } as any)
    return { manager, built }
  }

  async function caught(run: () => Promise<unknown>): Promise<any> {
    try {
      await run()
    } catch (error) {
      return error
    }
    return undefined
  }

  // Cierre del auditor de alpha.10 · R1 (repro `alpha10-reataque.spec.ts`, aserción INVERTIDA): el primitivo
  // `reconcileRelations` salía de la RAÍZ y el README lo recomendaba para K particiones — sin guard y sin freeze.
  test('cierre · R1 · la vía «from code» para K particiones es `runRelationsReconcile({ partitions })` y NIEGA la dirección rancia; `reconcileRelations` ya no sale de la raíz ni lo recomienda el README', async ({
    assert,
  }) => {
    const raiz: any = await import('../index.js')
    assert.notProperty(raiz, 'reconcileRelations', 'el primitivo sin guard ni ventana no es API pública')
    const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8')
    assert.notInclude(readme, 'from code, `reconcileRelations({ partitions: [...] })` migrates several')
    assert.include(readme, 'runRelationsReconcile(authorization, { toKey, fromKey, partitions')

    const { runRelationsReconcile } = await import('../commands/authz_relations_reconcile.js')
    const database = relationsDouble([share('u-old', 'd1')])
    const openfga = relationsDouble([share('u-new', 'd2')])
    const { manager, built } = relationsManager({ default: 'openfga', drivers: { database: () => database.driver, openfga: () => openfga.driver } })
    const error = await caught(() =>
      runRelationsReconcile(manager, { partitions: [APP as any], prune: true, toKey: 'openfga', fromKey: 'database' })
    )
    assert.equal(error?.code, 'E_AUTHZ_STALE_SOURCE_REFUSED')
    assert.deepEqual(openfga.writes, [], 'la compartición retirada NO resucita')
    assert.deepEqual(openfga.deletes, [], 'y --prune no borra la creada tras el cutover')
    assert.deepEqual(built, [], 'no se construyó ningún driver: el guard va antes')
    const { readFreezeRow } = await import('../src/freeze.js')
    assert.isNull((await readFreezeRow()).reason, 'ni se congeló')
  })

  // Cierre del auditor de alpha.10 · R4 (repro, aserción INVERTIDA): la función juzgaba ETIQUETAS del llamante.
  test('cierre · R4 · las etiquetas ya no deciden: instancias `from`/`to` y `activeKey` son 500 E_AUTHZ_CONFIG sin escribir (a: fromKey === toKey copiado; b: activeKey que contradice al manager)', async ({
    assert,
  }) => {
    const { runRelationsReconcile } = await import('../commands/authz_relations_reconcile.js')
    const a = { database: relationsDouble([share('u-old', 'd1')]), openfga: relationsDouble([]) }
    const { manager } = relationsManager({ default: 'openfga', drivers: { database: () => a.database.driver, openfga: () => a.openfga.driver } })
    const ea = await caught(() =>
      runRelationsReconcile(manager, { from: a.database.driver, to: a.openfga.driver, partition: APP as any, toKey: 'openfga', fromKey: 'openfga' } as any)
    )
    assert.equal(ea?.code, 'E_AUTHZ_CONFIG', '(a) instancias fuera')
    assert.deepEqual(a.openfga.writes, [])
    const eaKeys = await caught(() => runRelationsReconcile(manager, { partition: APP as any, toKey: 'openfga', fromKey: 'openfga' }))
    assert.equal(eaKeys?.code, 'E_AUTHZ_CONFIG', '(a) y por clave: origen === destino es el MISMO driver')
    const eb = await caught(() =>
      runRelationsReconcile(manager, { partition: APP as any, toKey: 'openfga', fromKey: 'database', activeKey: 'database' } as any)
    )
    assert.equal(eb?.code, 'E_AUTHZ_CONFIG', '(b) activeKey fuera: el activo lo dice el manager')
    assert.include(String(eb?.message), '`activeKey`')
    assert.deepEqual(a.openfga.writes, [])
    const sinClaves = await caught(() => runRelationsReconcile(manager, { partition: APP as any } as any))
    assert.equal(sinClaves?.code, 'E_AUTHZ_CONFIG', 'sin claves: 500, no un paso libre')
  })

  // Tabla de verdad del guard de relaciones (entradas discretas: qué resuelve el destino, qué resuelve el
  // origen, dryRun, allowStaleSource). La identidad es la FACTORY resuelta: `openfgaBis` es un alias del activo.
  test('cierre · R4 · tabla de verdad por IDENTIDAD del driver resuelto (alias incluidos) × dryRun × allowStaleSource', async ({
    assert,
  }) => {
    const { runRelationsReconcile, relationsReconcileLines } = await import('../commands/authz_relations_reconcile.js')
    type Fila = { to: string; from: string; dryRun: boolean; allow: boolean; espera: 'pasa' | 'marca' | 'niega' | 'config' }
    const filas: Fila[] = []
    const destinos: Array<[string, string, 'activo' | 'otro' | 'mismo']> = [
      ['openfga', 'database', 'activo'],
      ['openfgaBis', 'database', 'activo'], // alias del activo: misma factory, otra etiqueta
      ['database', 'openfga', 'otro'], // la vuelta ANTES de cambiar default
      ['database', 'openfgaBis', 'otro'],
      ['openfga', 'openfgaBis', 'mismo'], // origen y destino = el mismo driver bajo dos claves
      ['openfga', 'openfga', 'mismo'],
    ]
    for (const [to, from, clase] of destinos)
      for (const dryRun of [false, true])
        for (const allow of [false, true])
          filas.push({ to, from, dryRun, allow, espera: clase === 'mismo' ? 'config' : clase === 'otro' ? 'pasa' : dryRun || allow ? 'marca' : 'niega' })
    assert.lengthOf(filas, 24)
    for (const fila of filas) {
      const database = relationsDouble([share('u-old', 'd1')])
      const openfga = relationsDouble([share('u-new', 'd2')])
      const fga = () => openfga.driver
      const { manager, built } = relationsManager({ default: 'openfga', drivers: { database: () => database.driver, openfga: fga, openfgaBis: fga } })
      const nombre = JSON.stringify(fila)
      let report: any
      const error = await caught(async () => {
        report = await runRelationsReconcile(manager, { partition: APP as any, toKey: fila.to, fromKey: fila.from, dryRun: fila.dryRun, allowStaleSource: fila.allow })
      })
      if (fila.espera === 'config' || fila.espera === 'niega') {
        assert.equal(error?.code, fila.espera === 'config' ? 'E_AUTHZ_CONFIG' : 'E_AUTHZ_STALE_SOURCE_REFUSED', nombre)
        assert.deepEqual(built, [], `${nombre}: ningún driver construido`)
        assert.deepEqual([...openfga.writes, ...database.writes], [], `${nombre}: cero escrituras`)
        continue
      }
      assert.isUndefined(error, `${nombre}: ${error?.code} ${error?.message}`)
      if (fila.espera === 'pasa') {
        assert.isUndefined(report.staleSource, `${nombre}: sin marca`)
      } else {
        assert.deepEqual(report.staleSource, { to: fila.to, from: fila.from, allowed: fila.allow }, nombre)
        if (fila.dryRun && !fila.allow) assert.isFalse(relationsReconcileLines(report).clean, `${nombre}: en el verificador es deriva`)
      }
      if (fila.dryRun) assert.deepEqual([...openfga.writes, ...database.writes], [], `${nombre}: dry-run no escribe`)
    }
  })

  // Cierre-2 · C1 (repro «R4 cierre»): decisión §2026-09-13 (7) = DECLARAR. Este caso FIJA el límite tal como está
  // escrito (README ×2, CHANGELOG, CLAUDE.md): con la MISMA referencia el alias se niega; con dos factories DISTINTAS
  // sobre el mismo backend pasa. Si 2.5 trae la identidad de backend, este caso se pone rojo y hay que cambiar la letra
  // a la vez — que es lo que se quiere.
  test('cierre-2 · C1 · límite DECLARADO fijado: la identidad es la REFERENCIA de la factory — alias con la misma referencia ⇒ STALE; dos factories distintas sobre el mismo store ⇒ pasa (gemelo roles en reconcile.spec)', async ({
    assert,
  }) => {
    const { runRelationsReconcile } = await import('../commands/authz_relations_reconcile.js')
    const openfga = relationsDouble([share('u-new', 'd2')])
    const database = relationsDouble([share('u-old', 'd1')])
    const misma = () => openfga.driver
    const { manager } = relationsManager({
      default: 'openfga',
      drivers: { database: () => database.driver, openfga: misma, alias: misma, fga: () => openfga.driver },
    })
    const negado = await caught(() => runRelationsReconcile(manager, { partition: APP as any, toKey: 'alias', fromKey: 'database' }))
    assert.equal(negado?.code, 'E_AUTHZ_STALE_SOURCE_REFUSED', 'misma referencia: detectado')
    assert.deepEqual(openfga.writes, [])
    const report: any = await runRelationsReconcile(manager, { partition: APP as any, toKey: 'fga', fromKey: 'database', dryRun: true })
    assert.isUndefined(report.staleSource, 'LÍMITE DECLARADO: otra arrow sobre el mismo store no se detecta')

  })
})

/* ══════════════════════════════════════════════════════════════════════════
 * Cierre del auditor de alpha.10 · R1 — GUARDIA DE SUPERFICIE (M7) del linaje L6
 * en relaciones: ningún módulo público del paquete (el `exports` de package.json)
 * entrega el primitivo `reconcileRelations`. La única vía pública es
 * `runRelationsReconcile`, donde viven el guard y la ventana. Un re-export nuevo
 * —en la raíz o en cualquier subpath— nace rojo aquí.
 * ══════════════════════════════════════════════════════════════════════════ */

test.group('cierre alpha.10 · R1 · guardia de superficie: el primitivo sin guard no es API pública', () => {
  test('ningún subpath de `exports` exporta `reconcileRelations` (por identidad, no por nombre); `runRelationsReconcile` sí es alcanzable', async ({
    assert,
  }) => {
    const { reconcileRelations } = await import('../src/relations/reconcile.js')
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
    const sources: string[] = []
    for (const [subpath, target] of Object.entries<string>(pkg.exports)) {
      const source = target.replace(/^\.\/build\//, '').replace(/\.js$/, '.ts')
      if (source.includes('*')) {
        const dir = source.slice(0, source.indexOf('*'))
        for (const file of readdirSync(new URL(`../${dir}`, import.meta.url))) {
          if (file.endsWith('.ts')) sources.push(`${dir}${file}`)
        }
        continue
      }
      // `services/relations` exporta la INSTANCIA del servicio (y exige `relations.config` para importarse):
      // no puede re-exportar una función; se comprueba por su fuente.
      if (subpath === './services/relations') {
        const text = readFileSync(new URL(`../${source}`, import.meta.url), 'utf8')
        assert.notInclude(text, 'reconcile', `${subpath}: no toca el reconcile`)
        continue
      }
      sources.push(source)
    }
    assert.isAtLeast(sources.length, 20, `se recorrieron los módulos públicos: ${sources.join(', ')}`)
    let runFound = false
    /**
     * Cierre-2 · C5: la identidad se busca también DENTRO de lo exportado —objetos anidados (`{ internals: {
     * reconcileRelations } }`) y propiedades propias de funciones/clases (`static x = reconcileRelations`)—, con
     * visitados y profundidad acotada. ALCANCE DECLARADO: esto detecta un re-export del primitivo por IDENTIDAD, a
     * cualquier profundidad de objeto; NO detecta un `reconcileRelations.bind(null)` ni un wrapper `(o) =>
     * reconcileRelations(o)` (son funciones distintas). Eso lo cubre, a nivel de IMPORT, la guardia por fuente de abajo.
     */
    const hunt = (value: unknown, path: string, seen: Set<unknown>, depth: number) => {
      assert.notStrictEqual(value, reconcileRelations, `exporta el primitivo sin guard en ${path}`)
      if (depth >= 6 || value === null || (typeof value !== 'object' && typeof value !== 'function') || seen.has(value)) return
      seen.add(value)
      for (const key of Object.getOwnPropertyNames(value)) {
        if (typeof value === 'function' && (key === 'prototype' || key === 'caller' || key === 'arguments')) continue
        const descriptor = Object.getOwnPropertyDescriptor(value, key)
        if (descriptor && 'value' in descriptor) hunt(descriptor.value, `${path}.${key}`, seen, depth + 1)
      }
    }
    for (const source of sources) {
      const mod: Record<string, unknown> = await import(`../${source}`)
      for (const [name, value] of Object.entries(mod)) {
        hunt(value, `${source}#${name}`, new Set(), 0)
        if (name === 'runRelationsReconcile') runFound = true
      }
    }
    assert.isTrue(runFound, 'la vía pública con guard y ventana sigue exportada')
  })

  // Cierre-2 · C5: guardia por FUENTE (la que la identidad no puede dar). Ningún módulo publicable importa el VALOR
  // del primitivo (`src/relations/reconcile.js`) salvo la vía con guard y el harness DECLARADO (`/testing`, que
  // siembra sus propias particiones uuidv7 y solo poda dentro de ellas). Un wrapper o un `.bind` en un módulo nuevo
  // nace rojo aquí. Límite declarado: un wrapper DENTRO de uno de esos dos ficheros no lo ve ninguna de las dos.
  test('cierre-2 · C5 · guardia por fuente: solo `commands/authz_relations_reconcile.ts` y el harness de `/testing` importan el VALOR de `relations/reconcile.js`', async ({
    assert,
  }) => {
    const { readdirSync: readdir, statSync } = await import('node:fs')
    const root = fileURLToPath(new URL('../', import.meta.url))
    const walk = (dir: string): string[] =>
      readdir(root + dir).flatMap((entry) => {
        const rel = `${dir}${entry}`
        return statSync(root + rel).isDirectory() ? walk(`${rel}/`) : rel.endsWith('.ts') ? [rel] : []
      })
    const files = [...walk('src/'), ...walk('commands/'), ...walk('services/'), ...walk('providers/'), 'index.ts', 'configure.ts']
    // Re-ataque del cierre-2 · ⚪ 1: se compara la RUTA RESUELTA del especificador, no su texto (`./relations/./reconcile.js`,
    // `import(\`…\`)` o `import d, * as ns` pasaban una regex sobre el literal). Import de VALOR: `import type`/`export type`
    // y cláusulas `{ type A, type B }` enteramente de tipos no cuentan.
    const { dirname, resolve } = await import('node:path')
    const primitive = resolve(root, 'src/relations/reconcile.ts')
    const importers = files.filter((file) => {
      if (file === 'src/relations/reconcile.ts') return false
      const text = readFileSync(root + file, 'utf8')
      const specifiers: string[] = []
      for (const m of text.matchAll(/(?:^|[\n;])\s*(?:import|export)\s+(type\s+)?([^'"`;]*?)\s*from\s*['"`]([^'"`$]+)['"`]/g)) {
        if (m[1]) continue
        const clause = m[2].trim()
        const braces = /^\{([^}]*)\}$/.exec(clause)
        if (braces && braces[1].split(',').map((x) => x.trim()).filter(Boolean).every((x) => x.startsWith('type '))) continue
        specifiers.push(m[3])
      }
      for (const m of text.matchAll(/(?:^|[\n;])\s*import\s*['"`]([^'"`$]+)['"`]/g)) specifiers.push(m[1])
      for (const m of text.matchAll(/import\(\s*['"`]([^'"`$]+)['"`]\s*[,)]/g)) specifiers.push(m[1])
      return specifiers.some(
        (spec) => spec.startsWith('.') && resolve(dirname(root + file), spec).replace(/\.js$/, '.ts') === primitive
      )
    })
    assert.isAtLeast(files.length, 60, 'se recorrió el árbol publicable')
    assert.sameMembers(importers, ['commands/authz_relations_reconcile.ts', 'src/testing/relations_reconcile_contract.ts'])
  })
})

/* ══════════════════════════════════════════════════════════════════════════
 * alpha.10 · M2 · banderas que pasaban por un `exec` sin que ningún caso se
 * pusiera rojo inertes (panel de metodología, tester §M2): efecto por el kernel.
 * ══════════════════════════════════════════════════════════════════════════ */

test.group('alpha.10 · M2 · `authz:relations:reconcile --dry-run` y `authz:reconcile --prune`, con EFECTO', (group) => {
  const restores: Array<() => void> = []
  group.each.setup(() => async () => {
    while (restores.length) restores.pop()!()
  })

  test('M2-a · `authz:relations:reconcile --dry-run` ⇒ CERO escrituras en el destino (la gemela de la que ESCRIBÍA en alpha.8); sin la bandera, escribe', async ({
    assert,
  }) => {
    const tupla = { subject: { type: 'user', uuid: 'u1' }, relation: 'viewer', object: { type: 'document', id: 'd1' }, partition: { type: 'app', uuid: null }, expiresAt: null }
    const doble = (tuples: any[]) => {
      const writes: string[] = []
      return {
        writes,
        driver: {
          capabilities: { enumerateRelations: true, expiry: true },
          enumerateRelations: async () => ({ tuples, cursor: null }),
          relate: async (_s: any, relation: string, object: any) => void writes.push(`${object.type}:${object.id}#${relation}`),
          unrelate: async () => {},
        } as any,
      }
    }
    for (const [argv, esperado] of [
      [['--to=destino', '--from=origen', '--dry-run'], 0],
      [['--to=destino', '--from=origen'], 1],
    ] as const) {
      const origen = doble([tupla])
      const destino = doble([])
      const ace = await relationsAce({
        authorization: { default: 'origen', relations: { drivers: { origen: () => origen.driver, destino: () => destino.driver } } },
      })
      const run = await ace.exec([...argv])
      assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
      assert.lengthOf(destino.writes, esperado, `${argv.join(' ')}: ${JSON.stringify(run.logs)}`)
    }
  })

  test('M2-b · `authz:reconcile --prune` ⇒ el hecho SOBRANTE se borra; sin `--prune` se queda', async ({ assert }) => {
    const destinoConSobrante = () => {
      const store = new Set(['fact:sobrante'])
      const driver: any = {
        ...destinoConStore().driver,
        async reconcile(_source: any, options: any) {
          const borrar = options.prune === true && options.dryRun !== true
          if (borrar) store.delete('fact:sobrante')
          const phases = {
            root: { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
            catalog: { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
            tree: { written: 0, updated: 0, unchanged: 0, extra: 0, deleted: 0 },
            facts: { written: 0, updated: 0, unchanged: 0, extra: 1, deleted: borrar ? 1 : 0 },
          }
          return {
            to: 'destino', dryRun: options.dryRun === true, prune: options.prune === true,
            written: 0, updated: 0, unchanged: 0, extra: 1, deleted: borrar ? 1 : 0, phases,
            skipped: borrar ? {} : { 'extra-fact': 1 }, details: [], cycles: [],
            drift: { rootMarker: false, multiParent: [], roleVisibility: 0, pendingRelay: 0, deadRelay: 0 }, massDelete: false,
          }
        },
      }
      return { store, driver }
    }
    for (const [argv, queda] of [
      [['--to=destino', '--from=origen', '--prune'], false],
      [['--to=destino', '--from=origen'], true],
    ] as const) {
      const destino = destinoConSobrante()
      const manager = new AuthorizationManager({
        default: 'origen',
        drivers: { origen: () => ({ authorize: async () => false }) as any, destino: () => destino.driver },
        scopes: { resolveChain: resolveChainFrom(memoryScopeTree()), enumerateEdges: async () => ({ edges: [], cursor: null }) },
        warnOnOptInSecurity: false,
      } as any)
      const restore = patchManager('reconcile', (options: any) => manager.reconcile(options))
      const run = await (await aceFor(AuthzReconcile)).exec([...argv])
      restore()
      assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
      assert.equal(destino.store.has('fact:sobrante'), queda, `${argv.join(' ')}: ${JSON.stringify(run.logs)}`)
    }
  })
})

/* ══════════════════════════════════════════════════════════════════════════
 * alpha.10 · S5/S6/S7 · `authz:scopes:relay`: la salida no puede mentir
 * (auditoría de sistema; el repro del auditor afirmaba el defecto, aquí va dado la vuelta).
 * ══════════════════════════════════════════════════════════════════════════ */

test.group('alpha.10 · S5/S6/S7 · `authz:scopes:relay` en estados mixtos', (group) => {
  const restores: Array<() => void> = []
  group.each.setup(() => async () => {
    while (restores.length) restores.pop()!()
  })
  const change = (child: string) => ({ op: 'attached', child: { type: 'unit', uuid: child }, parent: { type: 'organization', uuid: 'org' } })
  const baseReport = {
    applied: [], failed: null, failures: [], deferred: [], deadCount: 0, busy: false, missing: [], entries: [], dead: [],
    queue: { oldestPendingAt: null, pendingAgeMs: null },
  }

  test('S5 · `--dry-run` con una APARCADA y una PENDIENTE ⇒ exit ≠ 0 (alpha.9: 0); con la aparcada sola, también', async ({ assert }) => {
    const aparcada = { id: 1, change: change('u1'), attempts: 5, error: 'padre borrado' }
    restores.push(
      patchManager('relayScopeChanges', async () => ({ ...baseReport, deadCount: 1, dryRun: true, remaining: true, dead: [aparcada], wouldApply: [{ id: 2, change: change('u2'), attempts: 0 }] }))
    )
    const run = await (await aceFor(AuthzScopesRelay)).exec(['--dry-run'])
    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.equal(run.exitCode, 1, JSON.stringify(run.logs))
    restores.pop()!()
    restores.push(patchManager('relayScopeChanges', async () => ({ ...baseReport, deadCount: 1, dryRun: true, remaining: false, dead: [aparcada], wouldApply: [] })))
    const control = await (await aceFor(AuthzScopesRelay)).exec(['--dry-run'])
    assert.equal(control.exitCode, 1)
  })

  test('S6 · `--only=12` con #12 APLAZADA ⇒ exit ≠ 0 y dice que NO aterrizó (alpha.9: «outbox vacía» en verde); con un id inexistente, no dice «vacía»', async ({
    assert,
  }) => {
    const e = { id: 12, change: change('u12'), attempts: 0 }
    restores.push(
      patchManager('relayScopeChanges', async () => ({
        ...baseReport, dryRun: false, remaining: true, wouldApply: [],
        deferred: [{ ...e, error: 'x' }], entries: [{ ...e, status: 'deferred', reason: 'depends-on:3', origin: 'pending' }],
      }))
    )
    const run = await (await aceFor(AuthzScopesRelay)).exec(['--only=12'])
    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.equal(run.exitCode, 1, JSON.stringify(run.logs))
    const texto = run.logs.join('\n')
    assert.notInclude(texto, 'La outbox del árbol está vacía')
    assert.include(texto, '#12')
    assert.include(texto, 'no ha aterrizado')
    restores.pop()!()

    restores.push(patchManager('relayScopeChanges', async () => ({ ...baseReport, dryRun: false, remaining: true, wouldApply: [], missing: [999] })))
    const typo = await (await aceFor(AuthzScopesRelay)).exec(['--only=999'])
    const textoTypo = typo.logs.join('\n')
    assert.notInclude(textoTypo, 'La outbox del árbol está vacía', JSON.stringify(typo.logs))
    assert.include(textoTypo, '#999')
  })

  // Cierre del auditor de alpha.10 · R3 (repro `alpha10-reataque.spec.ts`, aserción INVERTIDA): la rama
  // `--dry-run` retornaba antes del bloque S6 y decía «outbox vacía» con un id pedido que no existe.
  test('cierre · R3 · `--dry-run --only=999` (errata) por el kernel con el manager REAL y la outbox SQL: nombra #999 y NO dice «La outbox del árbol está vacía»', async ({
    assert,
  }) => {
    await cleanScopeOutbox(db)
    const manager = new AuthorizationManager({
      default: 'spy',
      drivers: { spy: () => ({ authorize: async () => false }) as any },
      scopes: { resolveChain: resolveChainFrom(memoryScopeTree()), outbox: sqlScopeOutbox() },
      warnOnOptInSecurity: false,
    } as any)
    const seen: any[] = []
    restores.push(
      patchManager('relayScopeChanges', async (o: any) => {
        const r = await manager.relayScopeChanges(o)
        seen.push(r)
        return r
      })
    )
    const run = await (await aceFor(AuthzScopesRelay)).exec(['--dry-run', '--only=999'])
    assert.isUndefined(run.error, `${run.error?.code}: ${run.error?.message}`)
    assert.deepEqual(seen[0]?.missing, [999], 'el manager sabe que #999 no existe')
    assert.isFalse(run.logs.some((l) => l.includes('La outbox del árbol está vacía')), JSON.stringify(run.logs))
    assert.isTrue(run.logs.some((l) => l.includes('#999')), `nombra el id pedido: ${JSON.stringify(run.logs)}`)
    assert.isTrue(run.logs.some((l) => l.includes('--dry-run: ninguno de los ids pedidos')), 'y la línea dice su rama')
    assert.notEqual(run.exitCode, 1, 'misma decisión que S6: un id `missing` no es exit 1 (puede haberlo aplicado otra pasada)')
  })

  // Tabla de verdad de la rama `--dry-run` (entradas discretas: --only, pendientes, missing, aparcadas).
  // Sin --only el manager nunca devuelve `missing` (fila imposible: no aplica).
  test('cierre · R3 · tabla de verdad de `--dry-run`: «vacía» SOLO sin --only, sin pendientes y sin aparcadas; exit 1 ⇔ aparcadas; cada id missing nombrado', async ({
    assert,
  }) => {
    const aparcada = { id: 1, change: change('u1'), attempts: 5, error: 'padre borrado' }
    const pendiente = { id: 12, change: change('u12'), attempts: 0 }
    const filas: Array<{ only: boolean; pend: boolean; missing: boolean; dead: boolean; vacia: boolean; exit1: boolean }> = []
    for (const only of [false, true])
      for (const pend of [false, true])
        for (const missing of only ? [false, true] : [false])
          for (const dead of [false, true])
            filas.push({ only, pend, missing, dead, vacia: !only && !pend && !dead, exit1: dead })
    assert.lengthOf(filas, 12)
    for (const fila of filas) {
      restores.push(
        patchManager('relayScopeChanges', async () => ({
          ...baseReport,
          dryRun: true,
          remaining: fila.pend,
          deadCount: fila.dead ? 1 : 0,
          dead: fila.dead ? [aparcada] : [],
          wouldApply: fila.pend ? [pendiente] : [],
          missing: fila.missing ? [999] : [],
        }))
      )
      const argv = ['--dry-run', ...(fila.only ? ['--only=12,999'] : [])]
      const run = await (await aceFor(AuthzScopesRelay)).exec(argv)
      restores.pop()!()
      const nombre = JSON.stringify(fila)
      const texto = run.logs.join('\n')
      assert.isUndefined(run.error, `${nombre}: ${run.error?.message}`)
      assert.equal(texto.includes('La outbox del árbol está vacía'), fila.vacia, `${nombre} «vacía»: ${JSON.stringify(run.logs)}`)
      assert.equal(run.exitCode === 1, fila.exit1, `${nombre} exit: ${JSON.stringify(run.logs)}`)
      assert.equal(texto.includes('#999'), fila.missing, `${nombre} nombra #999`)
      assert.equal(texto.includes('pendiente: #12'), fila.pend, `${nombre} pendiente`)
    }
  })

  // Cierre-2 · C2 (repro `alpha10-cierre-reataque.spec.ts` «R3 cierre», aserción INVERTIDA): `--only=a,b --limit=1`
  // decía «#b no estaba ni pendiente ni aparcado … o no existe» con #b PENDIENTE (y exit 0 en la pasada que aplica):
  // `missing` metía todo lo que quedó fuera del lote. Ahora `missing` = NO está en la cola; `notEvaluated` = está
  // PENDIENTE y la pasada no llegó (límite). Tabla de verdad con el manager REAL y la outbox SQL, por el kernel:
  // estado del id × dentro/fuera de `--limit` × `--dry-run`. El id objetivo T va SIEMPRE detrás de una pendiente A
  // (independiente: raíz, que no es clave), así que con `--limit=1` T queda FUERA y con `--limit=10` DENTRO.
  test('cierre-2 · C2 · tabla de verdad: estado del id pedido × dentro/fuera de --limit × --dry-run ⇒ bucket del reporte, letra por id y exit (manager REAL, outbox SQL)', async ({
    assert,
  }) => {
    type Estado = 'pendiente' | 'aparcado' | 'aplicado' | 'inexistente'
    const filas: Array<{ estado: Estado; limit: 1 | 10; dry: boolean }> = []
    for (const estado of ['pendiente', 'aparcado', 'aplicado', 'inexistente'] as Estado[])
      for (const limit of [1, 10] as const) for (const dry of [false, true]) filas.push({ estado, limit, dry })
    assert.lengthOf(filas, 16)
    for (const fila of filas) {
      await cleanScopeOutbox(db)
      const tree = memoryScopeTree()
      const spy = spyDriver()
      const manager = new AuthorizationManager({
        default: 'spy',
        drivers: { spy: () => spy.driver },
        scopes: { resolveChain: resolveChainFrom(tree), outbox: sqlScopeOutbox() },
        warnOnOptInSecurity: false,
      } as any)
      const a = orgScope()
      await tree.attach(a, APP_SCOPE)
      const [idA] = (await manager.scopes.attached(a, APP_SCOPE)).queued
      let idT: string | number = 999_999
      if (fila.estado !== 'inexistente') {
        const t = orgScope()
        await tree.attach(t, APP_SCOPE)
        idT = (await manager.scopes.attached(t, APP_SCOPE)).queued[0]
        if (fila.estado === 'aparcado') await db.from('authz_scope_outbox').where('id', idT).update({ attempts: 5, last_error: 'padre borrado' })
        if (fila.estado === 'aplicado') await db.from('authz_scope_outbox').where('id', idT).update({ applied_at: new Date() })
      }
      const seen: any[] = []
      const restore = patchManager('relayScopeChanges', async (o: any) => {
        const r = await manager.relayScopeChanges(o)
        seen.push(r)
        return r
      })
      const argv = [...(fila.dry ? ['--dry-run'] : []), `--only=${idA},${idT}`, `--limit=${fila.limit}`]
      const run = await (await aceFor(AuthzScopesRelay)).exec(argv)
      restore()
      const nombre = JSON.stringify(fila)
      assert.isUndefined(run.error, `${nombre}: ${run.error?.code}: ${run.error?.message}`)
      const report = seen[0]
      const texto = run.logs.join('\n')
      const T = String(idT)
      const ids = (xs: any[]) => xs.map((x: any) => String(x?.id ?? x))
      const fuera = fila.estado === 'pendiente' && fila.limit === 1
      const dentro = fila.estado === 'pendiente' && fila.limit === 10
      const noEnCola = fila.estado === 'aplicado' || fila.estado === 'inexistente'
      assert.equal(ids(report.missing).includes(T), noEnCola, `${nombre}: missing ⇔ no está en la cola (${JSON.stringify(report.missing)})`)
      assert.equal(ids(report.notEvaluated).includes(T), fuera, `${nombre}: notEvaluated ⇔ pendiente fuera del límite (${JSON.stringify(report.notEvaluated)})`)
      assert.equal(ids(fila.dry ? report.wouldApply : report.applied).includes(T), dentro, `${nombre}: evaluado ⇔ pendiente dentro del límite`)
      assert.equal(ids(report.entries.filter((e: any) => e.status === 'dead')).includes(T), fila.estado === 'aparcado', `${nombre}: aparcado`)
      // La letra, por id, dice la rama; nunca «no existe» para un id que está en la cola.
      assert.equal(texto.includes(`#${T} no estaba ni pendiente ni aparcado`), noEnCola, `${nombre}: letra missing: ${JSON.stringify(run.logs)}`)
      assert.equal(texto.includes(`#${T} está PENDIENTE y esta pasada NO lo evaluó`), fuera, `${nombre}: letra notEvaluated: ${JSON.stringify(run.logs)}`)
      if (fuera) assert.include(texto, `--limit=${fila.limit}`, `${nombre}: nombra el límite`)
      if (fila.estado === 'aparcado') assert.include(texto, `APARCADO tras agotar los intentos: #${T}`, `${nombre}: ${JSON.stringify(run.logs)}`)
      assert.equal(run.exitCode === 1, fila.estado === 'aparcado' || fuera, `${nombre}: exit: ${JSON.stringify(run.logs)}`)
      // `applied_at` real: la pasada que aplica con T fuera del límite NO lo aplicó.
      if (fila.estado === 'pendiente') {
        const rowT: any = await db.from('authz_scope_outbox').where('id', idT).first()
        assert.equal(rowT.applied_at !== null && rowT.applied_at !== undefined, dentro && !fila.dry, `${nombre}: applied_at de T`)
      }
    }
    await cleanScopeOutbox(db)
  })

  // Gemelo de C2 (misma clase: «no estaba ni … aparcado» para un id APARCADO): `entries` de lo aparcado salía de la
  // lectura acotada a `batchSize`, así que un id pedido aparcado más allá del primer lote era `missing`.
  test('cierre-2 · C2 gemelo · `--only=<aparcado más allá de --batch-size>` ⇒ se nombra APARCADO (exit 1), nunca «no existe»; en --dry-run y en la pasada que aplica', async ({
    assert,
  }) => {
    for (const dry of [false, true]) {
      await cleanScopeOutbox(db)
      const tree = memoryScopeTree()
      const manager = new AuthorizationManager({
        default: 'spy',
        drivers: { spy: () => spyDriver().driver },
        scopes: { resolveChain: resolveChainFrom(tree), outbox: sqlScopeOutbox() },
        warnOnOptInSecurity: false,
      } as any)
      const ids: Array<string | number> = []
      for (let i = 0; i < 2; i++) {
        const s = orgScope()
        await tree.attach(s, APP_SCOPE)
        ids.push((await manager.scopes.attached(s, APP_SCOPE)).queued[0])
      }
      await db.from('authz_scope_outbox').whereIn('id', ids).update({ attempts: 5, last_error: 'padre borrado' })
      const seen: any[] = []
      const restore = patchManager('relayScopeChanges', async (o: any) => {
        const r = await manager.relayScopeChanges(o)
        seen.push(r)
        return r
      })
      const run = await (await aceFor(AuthzScopesRelay)).exec([...(dry ? ['--dry-run'] : []), `--only=${ids[1]}`, '--batch-size=1'])
      restore()
      const texto = run.logs.join('\n')
      assert.isUndefined(run.error, `dry=${dry}: ${run.error?.message}`)
      assert.deepEqual(seen[0].missing, [], `dry=${dry}: el aparcado no es missing`)
      assert.deepEqual(seen[0].entries.filter((e: any) => e.status === 'dead').map((e: any) => String(e.id)), [String(ids[1])])
      assert.notInclude(texto, 'no estaba ni pendiente ni aparcado', `dry=${dry}: ${JSON.stringify(run.logs)}`)
      assert.include(texto, `APARCADO tras agotar los intentos: #${ids[1]}`, `dry=${dry}: ${JSON.stringify(run.logs)}`)
      assert.equal(run.exitCode, 1)
    }
    await cleanScopeOutbox(db)
  })

  test('S7 · `--max-age=-1` / `--max-age=1.5` se rechazan ANTES de relevar: exit ≠ 0 y el relay NO se llama (alpha.9: aplicaba y reventaba con TypeError)', async ({
    assert,
  }) => {
    for (const bad of ['--max-age=-1', '--max-age=1.5']) {
      const seen: any[] = []
      const restore = patchManager('relayScopeChanges', async (o: any) => {
        seen.push(o)
        return { ...baseReport, dryRun: false, remaining: false, wouldApply: [] }
      })
      const run = await (await aceFor(AuthzScopesRelay)).exec([bad])
      restore()
      assert.isUndefined(run.error, `${bad}: ${run.error?.constructor?.name}: ${run.error?.message}`)
      assert.lengthOf(seen, 0, `${bad}: la cola no se toca`)
      assert.equal(run.exitCode, 1)
      assert.include(run.logs.join('\n'), 'No se ha relevado nada')
    }
  })
})

/* ══════════════════════════════════════════════════════════════════════════
 * A-8 · `authz:freeze --lease-ms`.
 * ══════════════════════════════════════════════════════════════════════════ */

test.group('alpha.9 · A-8 · `authz:freeze --lease-ms`', (group) => {
  const restores: Array<() => void> = []
  group.each.setup(() => async () => {
    while (restores.length) restores.pop()!()
  })

  test('A-8 · `--lease-ms=60000` llega a `freeze()` y la salida DICE que la ventana caduca sola (hoy dice lo contrario)', async ({
    assert,
  }) => {
    const spy = spyManager('freeze', { fence: 7 })
    restores.push(spy.restore)

    const run = await (await aceFor(AuthzFreeze)).exec(['--reason=cutover', '--lease-ms=60000'])

    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.lengthOf(spy.seen, 1)
    assert.equal(spy.seen[0][1].leaseMs, 60_000, 'con la bandera inerte el comando pedía `leaseMs: null`')
    const texto = run.logs.join('\n')
    assert.include(texto, 'caduca SOLA en 60000 ms')
    assert.notInclude(texto, 'La ventana NO caduca sola', 'el operador se quedaba sin la red que creía tener')
  })
})

/* ══════════════════════════════════════════════════════════════════════════
 * alpha.10 · 2 · `authz:unfreeze` con la ventana CADUCADA, por el kernel.
 * ══════════════════════════════════════════════════════════════════════════ */

test.group('alpha.10 · 2 · `authz:unfreeze` con la ventana CADUCADA', (group) => {
  const restores: Array<() => void> = []
  const resetRow = () =>
    db.from('authz_catalog_version').where('id', 2).update({ freeze_reason: null, freeze_holder: null, freeze_until_ms: null })
  group.each.setup(async () => {
    await resetRow()
    return async () => {
      while (restores.length) restores.pop()!()
      await resetRow()
    }
  })

  test('alpha.10 · 2 · `freeze --lease-ms` + reloj avanzado ⇒ `unfreeze` sale ≠ 0 con la hora y lo que significa (hoy: «nada que levantar» en verde); el segundo `unfreeze` es éxito', async ({
    assert,
  }) => {
    let wall = Date.parse('2030-06-15T12:00:00.000Z')
    const clock = () => new Date(wall)
    const config = (): any => ({
      default: 'spy',
      drivers: { spy: () => spyDriver().driver },
      scopes: { resolveChain: resolveChainFrom(memoryScopeTree()) },
      warnOnOptInSecurity: false,
      clock,
    })
    // Dos procesos: el del `authz:freeze` (que termina) y el del `authz:unfreeze`.
    const operador = new AuthorizationManager(config())
    const cierre = new AuthorizationManager(config())
    let tokenOperador: any = null
    restores.push(
      patchManager('freeze', async (...args: any[]) => (tokenOperador = await (operador.freeze as any)(...args)))
    )
    for (const method of ['freezeStatus', 'lastFreezeStatus', 'unfreeze']) {
      restores.push(patchManager(method, (...args: any[]) => (cierre as any)[method](...args)))
    }

    const abierta = await (await aceFor(AuthzFreeze)).exec(['--reason=cutover', '--lease-ms=60000'])
    assert.isUndefined(abierta.error, `${abierta.error?.constructor?.name}: ${abierta.error?.message}`)

    wall += 5 * 60_000 // el cutover tardó más que el lease

    const primero = await (await aceFor(AuthzUnfreeze)).exec([])
    assert.isUndefined(primero.error, `${primero.error?.constructor?.name}: ${primero.error?.message}`)
    assert.equal(primero.exitCode, 1, `una ventana que caducó a mitad no es un cierre limpio: ${JSON.stringify(primero.logs)}`)
    const texto = primero.logs.join('\n')
    assert.include(texto, '2030-06-15T12:01:00.000Z', 'cuándo venció, en ISO')
    assert.include(texto, 'hace 240000 ms', 'y cuánto tiempo estuvo la flota escribiendo, con el reloj del config')
    assert.include(texto, 'volvieron a entrar')
    const fila = await db.from('authz_catalog_version').where('id', 2).first()
    assert.isNull(fila.freeze_reason, 'y limpia la fila: el aviso se da UNA vez')

    const segundo = await (await aceFor(AuthzUnfreeze)).exec([])
    assert.isUndefined(segundo.error, `${segundo.error?.constructor?.name}: ${segundo.error?.message}`)
    assert.notEqual(segundo.exitCode, 1, `el segundo unfreeze es «nada que levantar»: ${JSON.stringify(segundo.logs)}`)

    // Higiene: el renovador del proceso «operador» (que en la vida real ya
    // terminó). La fila ya está limpia: esto solo suelta su timer.
    assert.isFalse(await operador.unfreeze(tokenOperador), 'la ventana ya no era suya que levantar')
  })

  // Cierre del auditor de alpha.10 · ⚪ 4: la letra de `authz:unfreeze` bajo carrera la decide el RESULTADO del UPDATE
  // condicional y la fila releída. Entradas discretas: el plan (lift/expired), si el UPDATE casó, y qué hay después.
  test('cierre · ⚪ 4 · tabla de verdad bajo carrera: plan × UPDATE casó × fila después ⇒ línea propia y exit propio; nunca «queda limpia» ni «venció su lease» si no es verdad', async ({
    assert,
  }) => {
    const vencida = { reason: 'cutover', holder: 'operator:1:aa', kind: 'operator', untilMs: T0_UNFREEZE, fence: 7, expired: true, checkedAtMs: T0_UNFREEZE + 1000 }
    const viva = { ...vencida, untilMs: null, expired: false }
    const otro = { reason: 'otra pasada', holder: 'reconcile:9:zz', kind: 'reconcile', untilMs: null, fence: 8, expired: false, checkedAtMs: 0 }
    const filas = [
      { plan: 'lift', antes: viva, casa: true, despues: null, exit1: false, dice: 'levantado: la flota vuelve a escribir' },
      { plan: 'lift', antes: viva, casa: false, despues: null, exit1: false, dice: 'otro proceso lo levantó entre la lectura y el levantamiento' },
      { plan: 'lift', antes: viva, casa: false, despues: otro, exit1: true, dice: 'No se ha levantado nada' },
      { plan: 'expired', antes: vencida, casa: true, despues: null, exit1: true, dice: 'La fila queda limpia' },
      { plan: 'expired', antes: vencida, casa: false, despues: null, exit1: true, dice: 'ya la había limpiado otro proceso' },
      { plan: 'expired', antes: vencida, casa: false, despues: otro, exit1: true, dice: 'La fila NO se ha limpiado' },
      // Cierre-2 · C4: el UPDATE no casó y la fila es LA MISMA (mismo holder y fence): no la cambió «otro proceso».
      { plan: 'lift', antes: viva, casa: false, despues: viva, exit1: true, dice: 'la fila NO cambió' },
      { plan: 'expired', antes: vencida, casa: false, despues: vencida, exit1: true, dice: 'la fila NO cambió' },
    ] as const
    for (const fila of filas) {
      const lecturas = [fila.antes, fila.despues]
      restores.push(patchManager('lastFreezeStatus', async () => lecturas.shift() ?? null))
      restores.push(patchManager('unfreeze', async () => fila.casa))
      const run = await (await aceFor(AuthzUnfreeze)).exec([])
      restores.pop()!()
      restores.pop()!()
      const nombre = `${fila.plan}/casa=${fila.casa}/después=${fila.despues === null ? 'null' : fila.despues === otro ? 'otro' : 'misma'}`
      const texto = run.logs.join('\n')
      assert.isUndefined(run.error, `${nombre}: ${run.error?.message}`)
      assert.equal(run.exitCode === 1, fila.exit1, `${nombre} exit: ${JSON.stringify(run.logs)}`)
      assert.include(texto, fila.dice, nombre)
      assert.notInclude(texto, 'venció su lease', `${nombre}: vencer no hace fallar el UPDATE`)
      if (!(fila.plan === 'expired' && fila.casa)) assert.notInclude(texto, 'queda limpia', nombre)
      if (fila.despues === otro) assert.include(texto, 'reconcile:9:zz', `${nombre}: nombra lo que hay ahora`)
      if (fila.despues !== null && fila.despues !== otro) {
        assert.notInclude(texto, 'otro proceso la cambió', `${nombre}: no afirma un cambio que no ocurrió`)
        assert.notInclude(texto, 'la fila cambió y ahora es', `${nombre}: no afirma un cambio que no ocurrió`)
      }
    }
  })

  // Cierre del auditor de alpha.10 · ⚪ 5: una fila con motivo y SIN holder (legada o a mano) se publica como holder '?',
  // y `unfreeze({ holder: '?' })` no casaba nunca: el aviso de caducada se repetía para siempre con exit 1.
  test('cierre · ⚪ 5 · fila con motivo y holder NULL (y cierre-2 · C4: holder LITERAL `?`), CADUCADA: el primer `authz:unfreeze` avisa (exit 1) y la LIMPIA; el segundo es éxito', async ({
    assert,
  }) => {
    await db.from('authz_catalog_version').where('id', 2).update({ freeze_reason: 'a mano', freeze_holder: null, freeze_until_ms: 1 })
    const primero = await (await aceFor(AuthzUnfreeze)).exec([])
    assert.isUndefined(primero.error, `${primero.error?.constructor?.name}: ${primero.error?.message}`)
    assert.equal(primero.exitCode, 1, JSON.stringify(primero.logs))
    assert.include(primero.logs.join('\n'), 'La fila queda limpia')
    const fila = await db.from('authz_catalog_version').where('id', 2).first()
    assert.isNull(fila.freeze_reason, 'limpia de verdad')
    const segundo = await (await aceFor(AuthzUnfreeze)).exec([])
    assert.notEqual(segundo.exitCode, 1, JSON.stringify(segundo.logs))

    // Cierre-2 · C4 (repro «holder LITERAL `?`», aserción INVERTIDA): la fila con holder `'?'` escrito a mano se
    // publica igual que la NULL; antes el token no la casaba y `authz:unfreeze` repetía «La fila NO se ha limpiado:
    // … otro proceso la cambió» con exit 1 en bucle. Ahora: primera pasada avisa y limpia; segunda, éxito.
    await db.from('authz_catalog_version').where('id', 2).update({ freeze_reason: 'a mano', freeze_holder: '?', freeze_until_ms: 1 })
    const literal1 = await (await aceFor(AuthzUnfreeze)).exec([])
    assert.equal(literal1.exitCode, 1, JSON.stringify(literal1.logs))
    assert.include(literal1.logs.join('\n'), 'La fila queda limpia', JSON.stringify(literal1.logs))
    assert.notInclude(literal1.logs.join('\n'), 'otro proceso la cambió')
    assert.isNull((await db.from('authz_catalog_version').where('id', 2).first()).freeze_reason, 'limpia de verdad')
    const literal2 = await (await aceFor(AuthzUnfreeze)).exec([])
    assert.notEqual(literal2.exitCode, 1, JSON.stringify(literal2.logs))

    // Y viva sin holder (kind desconocido): sin --fence se niega; con --fence la levanta.
    await db.from('authz_catalog_version').where('id', 2).update({ freeze_reason: 'a mano viva', freeze_holder: null, freeze_until_ms: null })
    const { readFreezeRow } = await import('../src/freeze.js')
    const { fence } = await readFreezeRow()
    const sinFence = await (await aceFor(AuthzUnfreeze)).exec([])
    assert.equal(sinFence.exitCode, 1)
    const conFence = await (await aceFor(AuthzUnfreeze)).exec([`--fence=${fence}`])
    assert.notEqual(conFence.exitCode, 1, JSON.stringify(conFence.logs))
    assert.include(conFence.logs.join('\n'), 'levantado')
    assert.isNull((await readFreezeRow()).reason)
  })
})

const T0_UNFREEZE = Date.parse('2030-06-15T12:01:00.000Z')

/* ══════════════════════════════════════════════════════════════════════════
 * alpha.10 · S2 · la ventana del operador PISADA (auditoría de sistema, 🟠 S2).
 * El repro del auditor afirmaba el defecto (verde = presente); aquí va dado la
 * vuelta: la pasada NO se certifica con su propia ventana encima de la del
 * operador caducada, NO borra el rastro, y la salida dice en qué ventana corrió.
 * ══════════════════════════════════════════════════════════════════════════ */

test.group('alpha.10 · S2 · `authz:reconcile` y la ventana del operador caducada o ausente', (group) => {
  const restores: Array<() => void> = []
  const resetRow = async () => {
    await db.from('authz_catalog_version').where('id', 2).update({ freeze_reason: null, freeze_holder: null, freeze_until_ms: null })
  }
  group.each.setup(async () => {
    await resetRow()
    return async () => {
      while (restores.length) restores.pop()!()
      await resetRow()
    }
  })
  const T0 = Date.UTC(2030, 5, 15, 12, 0, 0)

  function reconcileManager(clockMs: { now: number }) {
    const destino = destinoConStore()
    destino.driver.withClock = function () {
      return this
    }
    const manager = new AuthorizationManager({
      default: 'origen',
      drivers: { origen: () => ({ authorize: async () => false, withClock() { return this } }) as any, destino: () => destino.driver },
      scopes: { resolveChain: resolveChainFrom(memoryScopeTree()), enumerateEdges: async () => ({ edges: [], cursor: null }) },
      clock: () => new Date(clockMs.now),
      warnOnOptInSecurity: false,
    } as any)
    return { manager, destino }
  }

  test('S2 · ventana del operador (otro proceso, `--lease-ms`) CADUCADA ⇒ la pasada NO toma la suya: exit ≠ 0 nombrando cuándo venció, cero escrituras, y la fila CONSERVA el rastro para `authz:unfreeze`', async ({
    assert,
  }) => {
    const { acquireFreeze, readFreezeRow } = await import('../src/freeze.js')
    const { unfreezePlan } = await import('../commands/authz_unfreeze.js')
    const op = await acquireFreeze({ reason: 'cutover a openfga', holder: 'operator:4242:deadbeef', untilMs: T0 + 60_000, nowMs: T0 })
    assert.isNotNull(op)
    const clock = { now: T0 + 120_000 }
    const { manager, destino } = reconcileManager(clock)
    restores.push(patchManager('reconcile', (options: any) => manager.reconcile(options)))

    const run = await (await aceFor(AuthzReconcile)).exec(['--to=destino', '--from=origen'])

    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.equal(run.exitCode, 1, `la pasada no se certifica con una ventana que no es la del cutover: ${JSON.stringify(run.logs)}`)
    assert.lengthOf(destino.seen, 0, 'ni llega a reconciliar')
    const texto = run.logs.join('\n')
    assert.include(texto, '2030-06-15T12:01:00.000Z')
    assert.include(texto, 'authz:unfreeze')
    const row = await readFreezeRow({})
    assert.equal(row.reason, 'cutover a openfga', 'el rastro de la ventana caducada sigue en la fila')
    assert.equal(row.fence, op!.fence, 'nadie tomó otra encima')
    assert.equal(unfreezePlan(await manager.lastFreezeStatus(), undefined).action, 'expired', 'y authz:unfreeze lo delatará')
  })

  test('S2-control · la salida DICE en qué ventana corrió: dentro de la del operador (fence N) ≠ «tomé mi PROPIA ventana»', async ({
    assert,
  }) => {
    const { acquireFreeze, releaseFreeze } = await import('../src/freeze.js')
    const clock = { now: T0 + 120_000 }

    const op = await acquireFreeze({ reason: 'cutover a openfga', holder: 'operator:4242:deadbeef', untilMs: null, nowMs: T0 })
    const dentro = reconcileManager(clock)
    restores.push(patchManager('reconcile', (options: any) => dentro.manager.reconcile(options)))
    const conVentana = await (await aceFor(AuthzReconcile)).exec(['--to=destino', '--from=origen'])
    assert.isUndefined(conVentana.error, `${conVentana.error?.constructor?.name}: ${conVentana.error?.message}`)
    const textoDentro = conVentana.logs.join('\n')
    assert.include(textoDentro, `ventana del operador (fence ${op!.fence})`)
    assert.notInclude(textoDentro, 'PROPIA')
    await releaseFreeze(op!, { nowMs: T0 })
    restores.pop()!()

    const sola = reconcileManager(clock)
    restores.push(patchManager('reconcile', (options: any) => sola.manager.reconcile(options)))
    const sinVentana = await (await aceFor(AuthzReconcile)).exec(['--to=destino', '--from=origen'])
    const textoSola = sinVentana.logs.join('\n')
    assert.include(textoSola, 'SU PROPIA ventana', JSON.stringify(sinVentana.logs))
    assert.include(textoSola, 'NO había ventana de operador viva')
    assert.notInclude(textoSola, 'ventana del operador (fence')
  })

  test('gemelo · `runRelationsReconcile` (relaciones) tampoco pisa la ventana del operador caducada, y su línea dice PROPIA cuando la toma', async ({
    assert,
  }) => {
    const { acquireFreeze, readFreezeRow } = await import('../src/freeze.js')
    const { runRelationsReconcile, relationsReconcileLines } = await import('../commands/authz_relations_reconcile.js')
    const empty: any = { capabilities: { enumerateRelations: true }, enumerateRelations: async () => ({ tuples: [], cursor: null }), relate: async () => {}, unrelate: async () => {} }
    const clock = { now: T0 + 120_000 }
    const manager = new AuthorizationManager({
      default: 'origen',
      drivers: { origen: () => ({ authorize: async () => false, withClock() { return this } }) as any },
      relations: { drivers: { a: () => empty, b: () => ({ ...empty }) } },
      scopes: { resolveChain: resolveChainFrom(memoryScopeTree()) },
      clock: () => new Date(clock.now),
      warnOnOptInSecurity: false,
    } as any)
    // Cierre R4: origen y destino por CLAVE, resueltos del config del manager (sin instancias ni `activeKey`).
    const opciones: any = { partition: { type: 'app', uuid: null }, toKey: 'b', fromKey: 'a' }

    await acquireFreeze({ reason: 'cutover', holder: 'operator:1:aa', untilMs: T0 + 60_000, nowMs: T0 })
    let caught: any
    try {
      await runRelationsReconcile(manager, opciones)
    } catch (error) {
      caught = error
    }
    assert.equal(caught?.code, 'E_AUTHZ_OPERATOR_WINDOW_EXPIRED')
    assert.equal((await readFreezeRow({})).reason, 'cutover', 'el rastro sigue')

    await resetRow()
    const report = await runRelationsReconcile(manager, opciones)
    assert.equal(report.frozen?.window, 'own')
    assert.include(relationsReconcileLines(report).lines.map((l) => l.message).join('\n'), 'ventana PROPIA')
  })
})

/* ══════════════════════════════════════════════════════════════════════════
 * A-9 · `authz:catalog:prune-orphans --allow-mass-purge`.
 * ══════════════════════════════════════════════════════════════════════════ */

test.group('alpha.9 · A-9 · `authz:catalog:prune-orphans --allow-mass-purge`', (group) => {
  const restores: Array<() => void> = []
  group.each.setup(() => async () => {
    while (restores.length) restores.pop()!()
  })

  test('A-9 · `--force --allow-mass-purge` llegan a `pruneOrphanRoles` (hoy el seguro no se podía levantar)', async ({
    assert,
  }) => {
    const spy = spyManager('pruneOrphanRoles', { orphans: [], purged: [], skipped: [], massPurge: false, dryRun: false })
    restores.push(spy.restore)

    const run = await (await aceFor(AuthzCatalogPruneOrphans)).exec(['--force', '--allow-mass-purge'])

    assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.lengthOf(spy.seen, 1)
    assert.isTrue(spy.seen[0][0].force)
    assert.isTrue(spy.seen[0][0].allowMassPurge)
  })
})

/* ══════════════════════════════════════════════════════════════════════════
 * A-10 · `authz:catalog:diff --fail-on-shadows`: el EFECTO es el exit code.
 * ══════════════════════════════════════════════════════════════════════════ */

test.group('alpha.9 · A-10 · `authz:catalog:diff --fail-on-shadows`', (group) => {
  group.each.setup(async () => {
    await cleanAuthzTables()
    return async () => {
      await cleanAuthzTables()
    }
  })

  /** `unit|unit-a1` cuelga de `organization|org-a`: el rol del ANCESTRO ensombrece al del descendiente. */
  const anidados = async (scope: any) =>
    scope.type === 'app'
      ? [APP_SCOPE]
      : scope.uuid === 'unit-a1'
        ? [scope, { type: 'organization', uuid: 'org-a' }, APP_SCOPE]
        : [scope, APP_SCOPE]

  const SPEC = { permissions: [{ slug: 'docs:read' }], roles: [] }

  async function dosLocalesHomonimos() {
    const { withAuthzCatalogWrite } = await import('../src/catalog/catalog_cache.js')
    await syncAuthzCatalog(SPEC as any)
    await withAuthzCatalogWrite(async (trx: any) => {
      const now = new Date()
      for (const owner of ['organization|org-a', 'unit|unit-a1']) {
        await trx.table('authz_roles').insert({
          uuid: uuidv7(),
          slug: 'viewer',
          name: 'viewer',
          scope_type: 'unit',
          rank: 1,
          owner_scope_key: owner,
          created_at: now,
          updated_at: now,
        })
      }
    })
  }

  test('A-10 · con un local ENSOMBRECIDO por el de un ancestro, `--fail-on-shadows` es exit 1 y sin la bandera es exit 0 (hoy la bandera no cambia nada)', async ({
    assert,
  }) => {
    await dosLocalesHomonimos()
    const config = { catalogs: [async () => SPEC], scopes: { resolveChain: anidados } }

    const sinFlag = await (await aceFor(AuthzCatalogDiff, { authorization: config })).exec([])
    assert.isUndefined(sinFlag.error, `${sinFlag.error?.constructor?.name}: ${sinFlag.error?.message}`)
    assert.notEqual(sinFlag.exitCode, 1, `el default no cambia: ${JSON.stringify(sinFlag.logs)}`)

    const conFlag = await (await aceFor(AuthzCatalogDiff, { authorization: config })).exec(['--fail-on-shadows'])
    assert.isUndefined(conFlag.error, `${conFlag.error?.constructor?.name}: ${conFlag.error?.message}`)
    assert.equal(
      conFlag.exitCode,
      1,
      `--fail-on-shadows es la forma de ELEGIR enterarse: con la bandera inerte el gate seguía verde: ${JSON.stringify(conFlag.logs)}`
    )
    assert.include(conFlag.logs.join('\n'), '--fail-on-shadows')
  })
})
