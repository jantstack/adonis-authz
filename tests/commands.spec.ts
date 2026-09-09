/**
 * **Los comandos del paquete, ejecutados por un kernel de ace de verdad**
 * (2.4.0-alpha.4; panel alpha.4). Hasta alpha.3 ningún caso construía un
 * kernel ni instanciaba un `BaseCommand`: los nueve comandos se juzgaban por
 * sus funciones puras con el config a mano (`permissionsOfCatalogs`,
 * `reconcileLines`, `unfreezePlan`…) y tres módulos de `commands/` no los
 * importaba ningún spec. Por ese punto ciego se publicaron DOS defectos:
 *
 *  - **el barrel `@jantstack/adonis-authz/commands` no era un loader de ace**
 *    (`configure.ts:47` lo registra en el `adonisrc` del consumidor y el
 *    kernel exige `getMetaData()`/`getCommand()`; exportaba nueve clases y
 *    nada más), así que en un consumidor configurado con `node ace configure`
 *    **`node ace` entero reventaba** — `TypeError: loaderInstance.getMetaData
 *    is not a function` — y no solo `openfga:provision`;
 *  - **`openfga:provision` (`startApp: false`) leía `this.app.config` antes de
 *    `app.boot()`**: `app.config` no existe hasta `boot()` (`Application.init()`
 *    no llama a `ConfigManager.process()`; `boot()` sí), y el ignitor de ace
 *    solo bootea con `startApp: true` ⇒ `TypeError: Cannot read properties of
 *    undefined (reading 'get')` en la primera línea de `run()` (COGNITIV,
 *    2026-09-09).
 *
 * El harness (`tests/helpers/ace.ts`) tiene dos reglas medidas —`AppFactory`,
 * jamás `IgnitorFactory`; `kernel.exec` NO relanza, se afirma sobre
 * `cmd.error`— y el hook `loading` copia la del ignitor real: la app SOLO
 * bootea si el comando declara `startApp`. El `catalogs` de la fixture es un
 * ESPÍA: «no explotó» no basta, hay que ver «leyó ESTE config».
 */
import { test } from '@japa/runner'
import { readdirSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { AppFactory } from '@adonisjs/core/factories/app'
import { Kernel } from '@adonisjs/core/ace'
import globalApp from '@adonisjs/core/services/app'
import { aceFor, fgaStub } from './helpers/ace.js'
import type { FgaStub } from './helpers/ace.js'
import OpenFgaProvision from '../commands/openfga_provision.js'
import AuthzCatalogDiff from '../commands/authz_catalog_diff.js'
import AuthzCatalogSync from '../commands/authz_catalog_sync.js'
import AuthzFreeze from '../commands/authz_freeze.js'
import AuthzReconcile from '../commands/authz_reconcile.js'
import AuthzRelationsReconcile from '../commands/authz_relations_reconcile.js'

const REPO = new URL('../', import.meta.url)

/** Los nueve, por nombre: la lista LITERAL, para que un comando nuevo sin registrar sea rojo. */
const NINE = [
  'openfga:provision',
  'authz:catalog:diff',
  'authz:catalog:sync',
  'authz:catalog:prune-orphans',
  'authz:scopes:relay',
  'authz:reconcile',
  'authz:relations:reconcile',
  'authz:freeze',
  'authz:unfreeze',
].sort()

/* ── C · el barrel es un loader de ace ─────────────────────────────────────── */

test.group('alpha.4 · C · `commands/main.ts` es un loader de ace válido (el barrel que registra configure.ts)', () => {
  test('C-1 · registrado como lo registra createAceKernel (`kernel.addLoader(() => import(barrel))`), kernel.boot() lista los NUEVE comandos', async ({
    assert,
  }) => {
    const app: any = new AppFactory().create(REPO, (id: string) => import(id))
    await app.init()
    const kernel: any = new Kernel(app)
    // Exactamente lo que hace `@adonisjs/core` con cada entrada de
    // `rcFile.commands`: el MÓDULO importado es el loader.
    kernel.addLoader(() => import('../commands/main.js') as any)
    await kernel.boot()
    // El kernel trae de serie su `list`; lo demás tiene que ser NUESTRO y ser los nueve.
    const names = kernel
      .getCommands()
      .map((command: any) => command.commandName)
      .filter((name: string) => name !== 'list')
      .sort()
    assert.deepEqual(names, NINE)
    assert.strictEqual(globalApp !== app, true, 'AppFactory no toca la app global de la suite')
  })

  test('C-2 · metadata de los nueve: commandName único, namespace, description, y `startApp` DECLARADO (openfga:provision sigue en false, los otros ocho en true)', async ({
    assert,
  }) => {
    const loader: any = await import('../commands/main.js')
    assert.isFunction(loader.getMetaData, 'el barrel exporta getMetaData()')
    assert.isFunction(loader.getCommand, 'el barrel exporta getCommand()')
    const metadata: any[] = await loader.getMetaData()
    assert.lengthOf(metadata, 9)
    assert.deepEqual(metadata.map((m) => m.commandName).sort(), NINE)
    for (const meta of metadata) {
      assert.equal(meta.namespace, meta.commandName.split(':')[0], `${meta.commandName}: namespace`)
      assert.isNotEmpty(meta.description, `${meta.commandName}: description`)
      assert.isBoolean(meta.options?.startApp, `${meta.commandName}: startApp declarado explícitamente`)
      assert.strictEqual(
        meta.options.startApp,
        meta.commandName !== 'openfga:provision',
        `${meta.commandName}: openfga:provision es el ÚNICO bootstrap sin base (startApp: false); los otros ocho leen authz_*`
      )
      const Command = await loader.getCommand(meta)
      assert.isFunction(Command, `${meta.commandName}: getCommand devuelve la clase`)
      assert.equal(Command.commandName, meta.commandName)
    }
    assert.isNull(await loader.getCommand({ commandName: 'authz:no-existe' }), 'un nombre desconocido es null, no un throw')
  })

  test('C-5 · diente estático: cada fichero de commands/ (salvo main.ts) es un comando del loader — un comando nuevo sin registrar es rojo', async ({
    assert,
  }) => {
    const loader: any = await import('../commands/main.js')
    const registered = new Set((await loader.getMetaData()).map((m: any) => m.commandName))
    const dir = fileURLToPath(new URL('../commands/', import.meta.url))
    const files = readdirSync(dir).filter((f) => f.endsWith('.ts') && f !== 'main.ts')
    assert.lengthOf(files, 9, `commands/ tiene nueve comandos: ${files.join(', ')}`)
    for (const file of files) {
      const mod: any = await import(`../commands/${file.replace(/\.ts$/, '.js')}`)
      const Command = mod.default
      assert.isFunction(Command, `${file}: exporta la clase por defecto`)
      assert.isString(Command.commandName, `${file}: commandName`)
      assert.isTrue(registered.has(Command.commandName), `${file} (${Command.commandName}) no está en el loader de commands/main.ts`)
      assert.strictEqual(await loader.getCommand({ commandName: Command.commandName }), Command, `${file}: getCommand devuelve ESA clase`)
    }
    // Y las re-exportaciones con nombre siguen ahí para quien importe la clase suelta.
    assert.strictEqual(loader.OpenFgaProvision, OpenFgaProvision)
  })

  test('C-6 · la FORMA del módulo: Object.values(m) son exactamente 9 clases + 2 funciones (getMetaData, getCommand) y NO hay default — por eso `new ListLoader(Object.values(m))` ya no vale', async ({
    assert,
  }) => {
    const m: any = await import('../commands/main.js')
    const names = Object.keys(m).sort()
    assert.notInclude(names, 'default', 'ace llama getMetaData() sobre el namespace y no desenvuelve default: un default sería mentira')
    const classes = names.filter((k) => typeof m[k] === 'function' && typeof m[k].commandName === 'string')
    const functions = names.filter((k) => typeof m[k] === 'function' && typeof m[k].commandName !== 'string')
    assert.lengthOf(classes, 9, `clases: ${classes.join(', ')}`)
    assert.deepEqual(functions, ['getCommand', 'getMetaData'])
    assert.lengthOf(names, 11)
    // El envoltorio que COGNITIV usaba (la única forma que funcionaba antes de alpha.4) hoy revienta:
    const { ListLoader } = await import('@adonisjs/core/ace')
    let wrapped: any
    try {
      await new ListLoader(Object.values(m) as any).getMetaData()
    } catch (error) {
      wrapped = error
    }
    assert.instanceOf(wrapped, TypeError, 'ListLoader.getMetaData() llama serialize() sobre cada valor, funciones incluidas')
  })

  test('C-7 · la nota de migración del README (sección Install) con su letra', async ({ assert }) => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    const start = readme.indexOf('## Install')
    const end = readme.indexOf('\n## ', start + 1)
    const install = readme.slice(start, end)
    assert.include(install, 'Upgrading to 2.4.0-alpha.4')
    assert.include(install, 'is now a real ace loader')
    assert.include(install, '`getMetaData()`/`getCommand()`')
    assert.include(install, 'TypeError: loaderInstance.getMetaData is not a function')
    assert.include(
      install,
      'If you registered the commands by wrapping the barrel in a `ListLoader(Object.values(m))` (the only way it worked before alpha.4), remove the wrapper and register the module directly: `() => import(\'@jantstack/adonis-authz/commands\')`, which is what `node ace configure` writes. The wrapper now fails with `TypeError: command.serialize is not a function`, because the module also exports the loader functions'
    )
    assert.include(install, 'no `default` export on purpose')
  })
})

/* ── A · openfga:provision por el kernel, SIN servidor (el defecto de COGNITIV) ── */

function authzFixture(stubUrl: string, over: Record<string, unknown> = {}) {
  const spy = { called: 0 }
  const config: Record<string, unknown> = {
    holderTypes: { users: 'user' },
    catalogs: [
      async () => {
        spy.called++
        return { permissions: [{ slug: 'posts.read' }, { slug: 'posts.write' }] }
      },
    ],
    relations: { config: { objectTypes: [{ type: 'document', relations: [{ name: 'owner' }, { name: 'viewer', includes: ['owner'] }] }] } },
    openfga: { url: stubUrl },
    ...over,
  }
  return { spy, config }
}

test.group('alpha.4 · A · openfga:provision por el kernel, sin servidor: lee el config real y llega a la red (caso 1)', (group) => {
  let stub: FgaStub
  group.setup(async () => {
    stub = await fgaStub()
  })
  group.teardown(async () => stub.close())
  group.each.setup(() => {
    stub.seen.length = 0
  })

  test('A-0 · la decisión: openfga:provision es startApp: false (bootstrap sin base) — y por eso tiene que bootear él', ({ assert }) => {
    assert.strictEqual(OpenFgaProvision.options.startApp, false)
  })

  test('A-1 · sin flags: cmd.error NO es TypeError, catalogs() se llamó UNA vez, el stub recibió POST /stores y el error es el 400 del stub', async ({
    assert,
  }) => {
    const { spy, config } = authzFixture(stub.url)
    const ace = await aceFor(OpenFgaProvision, { authorization: config })
    const run = await ace.exec([])
    assert.notInstanceOf(run.error, TypeError, `ROJO de alpha.3: ${run.error?.message} (${run.error?.stack?.split('\n')[1]?.trim()})`)
    assert.equal(spy.called, 1, 'los catálogos del config REAL se resolvieron (leyó ESTE config)')
    assert.deepEqual(
      stub.seen.map((r) => `${r.method} ${r.url}`),
      ['POST /stores'],
      'llegó a provisionar contra la URL del config'
    )
    assert.isDefined(run.error, 'el 400 del stub sale como error del comando')
    assert.match(String(run.error?.message), /stub: aquí no hay un OpenFGA de verdad/)
    assert.equal(run.exitCode, 1)
    assert.equal(ace.app.getState(), 'booted', 'la app quedó BOOTEADA (config cargado), no `ready` (sin start)')
    assert.isFalse(ace.app.isReady)
  })

  test('A-2 · sin URL en ningún sitio: la LETRA del error, exit 1, sin error, cero requests', async ({ assert }) => {
    const { spy, config } = authzFixture(stub.url, { openfga: {} })
    const run = await (await aceFor(OpenFgaProvision, { authorization: config })).exec([])
    assert.isUndefined(run.error, run.error?.message)
    assert.equal(run.exitCode, 1)
    assert.isTrue(
      run.logs.some((l) => l.includes('Falta la URL del servidor: --url o `openfga.url` en config/authorization.ts')),
      JSON.stringify(run.logs)
    )
    assert.equal(spy.called, 0)
    assert.deepEqual(stub.seen, [])
  })

  test('A-3 · sin catalogs (config real, no un {}): la frase de resolvePermissions, exit 1 y el stub NO recibe nada', async ({ assert }) => {
    const { config } = authzFixture(stub.url, { catalogs: undefined })
    const run = await (await aceFor(OpenFgaProvision, { authorization: config })).exec([])
    assert.isUndefined(run.error, run.error?.message)
    assert.equal(run.exitCode, 1)
    assert.isTrue(
      run.logs.some((l) => l.includes('El modelo `facts` declara cuatro relaciones por permiso')),
      JSON.stringify(run.logs)
    )
    assert.deepEqual(stub.seen, [], 'la negativa ocurre ANTES de crear un store que denegaría todo')
  })

  test('A-4 · --url gana al config (openfga.url apunta a un puerto muerto; --url al stub)', async ({ assert }) => {
    const { spy, config } = authzFixture(stub.url, { openfga: { url: 'http://127.0.0.1:1' } })
    const run = await (await aceFor(OpenFgaProvision, { authorization: config })).exec(['--url', stub.url])
    assert.notInstanceOf(run.error, TypeError)
    assert.equal(spy.called, 1)
    assert.deepEqual(
      stub.seen.map((r) => `${r.method} ${r.url}`),
      ['POST /stores']
    )
  })

  test('A-5 · LA DECISIÓN (B, no A): con un provider del consumidor cuyo ready() consulta la base, el comando llega a run() — boot() del provider corrió, ready() NO, ningún preload', async ({
    assert,
  }) => {
    // Un provider como los del appliance: `boot()` inocuo, `ready()` que
    // toca la base. Con `startApp: true` (opción A) el kernel haría
    // boot()+start() y `ready()` mataría el comando ANTES de run() — con la
    // base ausente, que es exactamente el escenario del bootstrap.
    const calls: string[] = []
    class NoisyProvider {
      constructor(_app: unknown) {}
      register() {
        calls.push('register')
      }
      boot() {
        calls.push('boot')
      }
      start() {
        calls.push('start')
      }
      ready() {
        calls.push('ready')
        throw new Error('ready(): SELECT 1 falla, la base todavía no existe')
      }
    }
    const { spy, config } = authzFixture(stub.url)
    const ace = await aceFor(OpenFgaProvision, {
      authorization: config,
      providers: [async () => ({ default: NoisyProvider })],
    })
    const run = await ace.exec([])
    assert.deepEqual(calls, ['register', 'boot'], 'boot() sí (carga config/*); start()/ready() NO')
    assert.equal(spy.called, 1, 'y aun así leyó el config real')
    assert.deepEqual(
      stub.seen.map((r) => `${r.method} ${r.url}`),
      ['POST /stores']
    )
    assert.notMatch(String(run.error?.message), /ready\(\)/, 'el error es el del backend, no el ready() del consumidor')
    assert.equal(ace.app.getState(), 'booted')
  })

  test('A-6 · idempotente: invocado sobre una app YA arrancada (booted+ready), prepare() no relanza ni bootea dos veces', async ({
    assert,
  }) => {
    const { spy, config } = authzFixture(stub.url)
    const ace = await aceFor(OpenFgaProvision, { authorization: config })
    await ace.app.boot()
    await ace.app.start(() => {})
    assert.equal(ace.app.getState(), 'ready')
    const run = await ace.exec([])
    assert.notInstanceOf(run.error, TypeError)
    assert.equal(spy.called, 1)
    assert.deepEqual(
      stub.seen.map((r) => `${r.method} ${r.url}`),
      ['POST /stores']
    )
    assert.equal(ace.app.getState(), 'ready', 'sigue `ready`: no se retrocedió ni se re-booteó')
  })

  test('A-7 · ⚪ 9: si tras boot() app.config sigue sin existir (un boot() que no carga config), el comando lo DICE y sale 1 — nunca el TypeError con otro disfraz', async ({
    assert,
  }) => {
    // `Application.boot()` es un no-op SILENCIOSO si el estado no es
    // `initiated`; aquí se simula ese silencio con un `boot()` que no hace
    // nada, y se exige que la guarda de `prepare()` lo vea.
    const { spy, config } = authzFixture(stub.url)
    const ace = await aceFor(OpenFgaProvision, { authorization: config })
    ace.app.boot = async () => {}
    const run = await ace.exec([])
    assert.notInstanceOf(run.error, TypeError, run.error?.message)
    assert.isUndefined(run.error, run.error?.message)
    assert.equal(run.exitCode, 1)
    assert.isTrue(run.logs.some((l) => l.includes('config/* no está cargado')), JSON.stringify(run.logs))
    assert.equal(spy.called, 0)
    assert.deepEqual(stub.seen, [])
  })
})

/* ── L-F · provisión: validar el modelo ANTES de crear el store ────────────── */

test.group('alpha.4 · L-F · provisionOpenFgaStore valida el modelo ANTES de crear el store (⚪ 7 del auditor)', (group) => {
  let stub: FgaStub
  group.setup(async () => {
    stub = await fgaStub()
  })
  group.teardown(async () => stub.close())
  group.each.setup(() => {
    stub.seen.length = 0
  })

  /** Un catálogo que desborda los 262.144 bytes del modelo (~800 slugs cortos con 1 holder ya lo hacen). */
  const tooMany = Array.from({ length: 1500 }, (_, i) => `recurso_${i}:accion_bastante_larga_${i}`)

  test('un catálogo que desborda el techo de bytes ⇒ 500 E_AUTHZ_MODEL_TOO_LARGE y CERO requests (ningún store huérfano)', async ({
    assert,
  }) => {
    const { provisionOpenFgaStore } = await import('../src/openfga.js')
    let caught: any
    try {
      await provisionOpenFgaStore(stub.url, 'huerfano', { users: 'user' }, tooMany)
    } catch (error) {
      caught = error
    }
    assert.isDefined(caught, 'ROJO: provisionó (o murió en el SDK) con un modelo impublicable')
    assert.equal(caught?.code, 'E_AUTHZ_MODEL_TOO_LARGE', `${caught?.constructor?.name}: ${caught?.message}`)
    assert.equal(caught?.status, 500)
    assert.deepEqual(stub.seen, [], 'el store NO se creó: validar va antes que crear')
  })

  test('un catálogo inválido (dos permisos que colisionan en el espacio de relaciones) ⇒ el error del PAQUETE y cero requests', async ({
    assert,
  }) => {
    const { provisionOpenFgaStore } = await import('../src/openfga.js')
    let caught: any
    try {
      await provisionOpenFgaStore(stub.url, 'huerfano', { users: 'user' }, ['x', 'can_x'])
    } catch (error) {
      caught = error
    }
    assert.isDefined(caught)
    assert.isString(caught?.code, `un error con code del paquete, no el crudo del SDK: ${caught?.constructor?.name}`)
    assert.deepEqual(stub.seen, [])
  })

  test('y por el comando: el catálogo que desborda sale como E_AUTHZ_MODEL_TOO_LARGE del comando, sin tocar el servidor', async ({ assert }) => {
    const { config } = authzFixture(stub.url, {
      catalogs: [async () => ({ permissions: tooMany.map((slug) => ({ slug })) })],
    })
    const run = await (await aceFor(OpenFgaProvision, { authorization: config })).exec([])
    assert.equal(run.error?.code, 'E_AUTHZ_MODEL_TOO_LARGE', `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.deepEqual(stub.seen, [])
  })

  test('y con --store-id (actualizar el modelo de un store existente): el mismo gate, E_AUTHZ_MODEL_TOO_LARGE y CERO requests (⚪ N1 del auditor)', async ({ assert }) => {
    // Hasta este caso la rama `--store-id` NO validaba: el desbordamiento salía
    // como `FgaApiValidationError` del SDK con UNA request ya hecha. Es justo la
    // rama donde se toca el techo (el modelo crece con cada catálogo).
    const { config } = authzFixture(stub.url, {
      catalogs: [async () => ({ permissions: tooMany.map((slug) => ({ slug })) })],
    })
    const run = await (await aceFor(OpenFgaProvision, { authorization: config })).exec(['--store-id', '01ARZ3NDEKTSV4RRFFQ69G5FAV'])
    assert.equal(run.error?.code, 'E_AUTHZ_MODEL_TOO_LARGE', `${run.error?.constructor?.name}: ${run.error?.message}`)
    assert.deepEqual(stub.seen, [], 'ninguna request al servidor: el modelo no publicable no se intenta escribir')
  })

  test('control: un catálogo publicable sí llega a POST /stores (el orden nuevo no bloquea la provisión sana)', async ({ assert }) => {
    const { provisionOpenFgaStore } = await import('../src/openfga.js')
    let caught: any
    try {
      await provisionOpenFgaStore(stub.url, 'sano', { users: 'user' }, ['posts.read'])
    } catch (error) {
      caught = error
    }
    assert.match(String(caught?.message), /stub: aquí no hay un OpenFGA de verdad/)
    assert.deepEqual(
      stub.seen.map((r) => `${r.method} ${r.url}`),
      ['POST /stores']
    )
  })
})

/* ── C-3 · los seis comandos con guarda pre-base, ejecutados por el kernel ── */

test.group('alpha.4 · C-3 · los seis comandos con bail-out pre-base llegan a su guarda por el kernel (cada comando carga y su run() llega al config)', () => {
  /**
   * Los tres que NO tienen guarda —`authz:unfreeze`, `authz:catalog:prune-orphans`,
   * `authz:scopes:relay`— van directos a `services/main.js`, que resuelve
   * `authz.manager` del contenedor GLOBAL (el de la suite, no el de la app
   * fixture): el harness sería bicéfalo (config de una app, manager de
   * otra) y no un end-to-end. Quedan fuera a propósito (2.6, `roadmap-2.0.md`).
   */
  const CASES: Array<[string, any, unknown, string[], string]> = [
    ['authz:catalog:diff', AuthzCatalogDiff, {}, [], 'No hay catálogos declarados'],
    ['authz:catalog:sync', AuthzCatalogSync, {}, [], 'No hay catálogos declarados'],
    ['authz:freeze', AuthzFreeze, {}, [], 'Falta --reason'],
    ['authz:reconcile', AuthzReconcile, {}, [], 'Falta --to'],
    ['authz:relations:reconcile (sin --to)', AuthzRelationsReconcile, {}, [], 'Falta --to'],
    ['authz:relations:reconcile (sin relations.drivers)', AuthzRelationsReconcile, {}, ['--to=openfga'], 'No hay `relations.drivers`'],
    ['openfga:provision', OpenFgaProvision, { openfga: {} }, [], 'Falta la URL del servidor'],
  ]

  for (const [label, Command, authorization, argv, phrase] of CASES) {
    test(`${label} ⇒ exit 1 con «${phrase}», sin TypeError`, async ({ assert }) => {
      const ace = await aceFor(Command, { authorization })
      const run = await ace.exec(argv)
      assert.notInstanceOf(run.error, TypeError, `${label}: ${run.error?.message}`)
      assert.isUndefined(run.error, `${label}: ${run.error?.message}`)
      assert.equal(run.exitCode, 1, label)
      assert.isTrue(run.logs.some((l) => l.includes(phrase)), `${label}: ${JSON.stringify(run.logs)}`)
      // Con `startApp: true` el kernel arrancó la app entera; con `false`
      // (openfga:provision) la booteó el comando. En los dos casos el config existe.
      assert.isDefined(ace.app.config, `${label}: app.config`)
    })
  }
})

/* ── B · contra el :8101 ───────────────────────────────────────────────────── */

const openFgaTestUrl = process.env.OPENFGA_TEST_URL
if (openFgaTestUrl) {
  const apiUrl: string = openFgaTestUrl

  test.group('alpha.4 · B · openfga:provision por el kernel contra OPENFGA_TEST_URL (caso 2)', (group) => {
    const stores: string[] = []
    group.teardown(async () => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      while (stores.length) await new OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore()
    })

    async function provisionByKernel(over: Record<string, unknown> = {}, argv: string[] = []) {
      const { spy, config } = authzFixture(apiUrl, over)
      const run = await (await aceFor(OpenFgaProvision, { authorization: config })).exec(argv)
      const text = run.logs.join('\n')
      const storeId = /^OPENFGA_STORE_ID=(.+)$/m.exec(text)?.[1]
      const modelId = /^OPENFGA_MODEL_ID=(.+)$/m.exec(text)?.[1]
      return { run, spy, storeId, modelId }
    }

    test('B-1 · sin flags: exit 0, imprime OPENFGA_STORE_ID/OPENFGA_MODEL_ID, el store existe y su modelo lleva las CUATRO relaciones por permiso (con `rooted` en can_<P>) y el tipo de relación fusionado', async ({
      assert,
    }) => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const { factsRelationsOf } = await import('../src/openfga.js')
      const { run, spy, storeId, modelId } = await provisionByKernel({ openfga: { url: apiUrl, storeName: `alpha4-b1-${Date.now()}` } })
      assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
      assert.equal(run.exitCode ?? 0, 0, JSON.stringify(run.logs))
      assert.equal(spy.called, 1)
      assert.isString(storeId, `el stdout ES el contrato (el operador lo copia al .env): ${JSON.stringify(run.logs)}`)
      assert.isString(modelId)
      stores.push(storeId!)

      const client = new OpenFgaClient({ apiUrl, storeId })
      const store = await client.getStore()
      assert.equal(store.id, storeId)
      assert.match(store.name, /^alpha4-b1-/)
      const latest = await client.readLatestAuthorizationModel()
      assert.equal(latest.authorization_model?.id, modelId, 'el modelo impreso es el ÚLTIMO del store')
      const types = new Map((latest.authorization_model?.type_definitions ?? []).map((t: any) => [t.type, t]))
      for (const type of ['scope', 'role', 'role_binding', 'user', 'document']) assert.isTrue(types.has(type), `tipo ${type}`)
      const scope: any = types.get('scope')
      const role: any = types.get('role')
      for (const permission of ['posts.read', 'posts.write']) {
        const r = factsRelationsOf(permission)
        // `Object.hasOwn` y no `assert.property`: el `.` del slug no es una ruta anidada.
        assert.isTrue(Object.hasOwn(scope.relations, r.base), `${permission}: ${r.base}`)
        assert.isTrue(Object.hasOwn(scope.relations, r.can), `${permission}: ${r.can}`)
        assert.isTrue(Object.hasOwn(scope.relations, r.denied), `${permission}: ${r.denied}`)
        assert.isTrue(Object.hasOwn(role.relations, r.permits), `${permission}: ${r.permits} en role`)
        // Invariante 9 · c2r: sin `and rooted` un subárbol desgajado concedería.
        assert.include(JSON.stringify(scope.relations[r.can]), '"rooted"', `${permission}: can_<P> exige rooted`)
      }
      const document: any = types.get('document')
      assert.property(document.relations, 'owner')
      assert.property(document.relations, 'viewer')
    })

    test('B-2 · --store-id escribe un modelo NUEVO en el store existente (no crea otro) con el permiso añadido', async ({ assert }) => {
      const { OpenFgaClient } = await import('@openfga/sdk')
      const { factsRelationsOf } = await import('../src/openfga.js')
      const first = await provisionByKernel({ openfga: { url: apiUrl, storeName: `alpha4-b2-${Date.now()}` } })
      assert.isUndefined(first.run.error, first.run.error?.message)
      stores.push(first.storeId!)
      const before = (await new OpenFgaClient({ apiUrl }).listStores()).stores?.length ?? 0

      const second = await provisionByKernel(
        {
          openfga: { url: apiUrl },
          catalogs: [async () => ({ permissions: [{ slug: 'posts.read' }, { slug: 'posts.write' }, { slug: 'posts.publish' }] })],
        },
        ['--store-id', first.storeId!]
      )
      assert.isUndefined(second.run.error, second.run.error?.message)
      assert.equal(second.storeId, first.storeId)
      assert.notEqual(second.modelId, first.modelId, 'un modelo NUEVO (versionado) sobre el mismo store')
      const after = (await new OpenFgaClient({ apiUrl }).listStores()).stores?.length ?? 0
      assert.equal(after, before, 'no se creó otro store')
      const latest = await new OpenFgaClient({ apiUrl, storeId: first.storeId }).readLatestAuthorizationModel()
      assert.equal(latest.authorization_model?.id, second.modelId)
      const scope: any = latest.authorization_model?.type_definitions?.find((t: any) => t.type === 'scope')
      assert.isTrue(Object.hasOwn(scope.relations, factsRelationsOf('posts.publish').can))
    })
  })
}
