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
    const ace = await aceFor(AuthzRelationsReconcile, {
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
    const ace = await aceFor(AuthzRelationsReconcile, {
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
    const ace = await aceFor(AuthzRelationsReconcile, {
      authorization: { relations: { drivers: { origen: () => origen.driver, destino: () => destino.driver } } },
    })

    const run = await ace.exec(['--to=destino', '--from=origen', '--dry-run', '--partition-type=organization'])

    assert.equal(run.exitCode, 1)
    assert.deepEqual(origen.particiones, [])
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
