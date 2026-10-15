/**
 * **El runbook del cutover, EJECUTABLE** (lote R del plan 2.5; metodología
 * 2026-09-13: M1 transformada —un test con pasos numerados cuyos pasos salen de
 * la lista de ESTADOS de M5 × comandos, no del README— y `CLAUDE.md` puntos 8, 9
 * y 10). Es el job `cutover-runbook` de CI (`npm run cutover-runbook`): pg y
 * sqlite-fichero con OpenFGA REAL.
 *
 * Lo que recorre, POR EL KERNEL DE ACE y con un PROCESO por fase
 * (`tests/helpers/cutover_child.ts`: un cutover cambia `config.default` entre
 * fases, y cada `node ace …` de producción es un proceso nuevo):
 *
 *   ANTES   (`default: database`)  provision · catálogo · siembra (roles de
 *           `runMigrationContract` + relaciones en DOS particiones con `group`) ·
 *           verificador en rojo · ventana del operador (otro PROCESO recibe 503) ·
 *           relaciones por partición · hechos · `--prune` sobre el store COMPARTIDO ·
 *           verificadores en verde ANTES del switch · cierre de la ventana.
 *   DESPUÉS (`default: openfga`)   escrituras nuevas (revoke, deny, detached +
 *           relay) · REPETIDA en dirección rancia (roles con y sin --prune,
 *           relaciones) · mantenimiento y `--prune` · ventana CADUCADA antes de la
 *           pasada · ventana adoptada con lease · pasada ABORTADA (freeze de un
 *           proceso muerto, con y sin lease vencido) · vuelta ANTES del switch.
 *   VUELTA  (`default: database`)  paridad de las 448 · REPETIDA en dirección
 *           rancia con `database` activo (sin --from, con --from, relaciones).
 *   PENDING (lote D)                opt-in del deny en dos fases · rollback
 *           prohibido con denies vivos.
 *
 * Y el README se afirma contra la tabla de pasos: **cada línea `node ace …` del
 * bloque «The cutover window» tiene que tener su paso ejecutable** (mismo comando,
 * mismas banderas; las de entre corchetes son opcionales). Borrar un paso deja el
 * README sin respaldo y este fichero en rojo.
 *
 * Sin `.skip`: el fichero no registra nada en `:memory:` (un hijo no puede abrir
 * esa base) ni sin `OPENFGA_TEST_URL`, salvo que `CUTOVER_RUNBOOK_REQUIRED=1`
 * (el script del job), en cuyo caso registra un caso ROJO que lo dice.
 * Sin sleeps: toda caducidad es el reloj inyectado del hijo, movido por IPC.
 */

import { test } from '@japa/runner'
import { execFileSync, fork } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { v7 as uuidv7 } from 'uuid'
import db from '@adonisjs/lucid/services/db'
import { aceFor } from './helpers/ace.js'
import { testEngine } from './helpers/app.js'
import type { TestApp } from './helpers/app.js'
import { cleanAuthzTables, cleanScopeOutbox } from './helpers/schema.js'
import { cleanSqlScopeTree } from './helpers/sql_scope_tree.js'
import { MIGRATION_CATALOG, MIGRATION_QUESTION_COUNT } from '../src/testing/main.js'
import OpenFgaProvision from '../commands/openfga_provision.js'

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const CHILD = fileURLToPath(new URL('./helpers/cutover_child.ts', import.meta.url))
const FREEZE_CHILD = fileURLToPath(new URL('./helpers/freeze_child.ts', import.meta.url))
const README = fileURLToPath(new URL('../README.md', import.meta.url))
const HOLDER_TYPES = { users: 'user', admins: 'admin' }
const RELATIONS_SPEC = {
  objectTypes: [
    { type: 'document', relations: [{ name: 'owner' }, { name: 'editor', includes: ['owner'] }, { name: 'viewer', includes: ['editor'] }] },
  ],
  holderTypes: ['user', 'admin'],
}

const apiUrl = process.env.OPENFGA_TEST_URL
const engine = testEngine()
const eligible = engine !== 'sqlite' && !!apiUrl
const required = process.env.CUTOVER_RUNBOOK_REQUIRED === '1'

/* ── Infraestructura: pasos, hijos por fase, el otro proceso ─────────────── */

interface Invocation {
  step: number
  command: string
  argv: string[]
}

/** Lo ejecutado por el kernel en esta corrida: la TABLA contra la que se afirma el README. */
const executed: Invocation[] = []
/** Los pasos, con su estado, para el informe y para los `pending`. */
const steps: Array<{ n: number; label: string; status: 'ok' | 'pending' | 'failed'; lot?: string }> = []
let currentStep = 0

/**
 * HALLAZGOS: lo que el runbook observa que contradice el README o el punto 7 de
 * `CLAUDE.md` pero NO impide seguir (el efecto es el correcto y solo miente la letra
 * o el exit). Se apuntan, el recorrido continúa, y al final el caso es ROJO si hay
 * alguno: un gate que tolera lo que encuentra es ceremonia. Cada uno va con repro
 * (el paso) al informe del lote.
 */
const findings: string[] = []
function finding(id: string, holds: boolean, text: string): void {
  if (!holds) findings.push(`${id} (paso ${currentStep}): ${text}`)
}

/** Tope por ORDEN al hijo: un paso que se cuelga tiene que salir ROJO nombrando el paso, no colgar el job. */
const OP_TIMEOUT_MS = 30_000

async function step(n: number, label: string, fn: () => Promise<void>): Promise<void> {
  currentStep = n
  process.stderr.write(`[cutover-runbook] paso ${n} · ${label}\n`)
  try {
    await fn()
    steps.push({ n, label, status: 'ok' })
  } catch (error: any) {
    steps.push({ n, label, status: 'failed' })
    error.message = `paso ${n} · ${label}\n${error.message}`
    throw error
  }
}

function pending(n: number, label: string, lot: string): void {
  steps.push({ n, label, status: 'pending', lot })
}

async function suiteApp(): Promise<Pick<TestApp, 'engine' | 'connection' | 'database'>> {
  const raw: any = structuredClone(db.manager.get('primary')?.config)
  return { engine, connection: raw, database: String(raw?.connection?.database ?? raw?.connection?.filename ?? '') }
}

class Phase {
  #child: ChildProcess
  #pending = new Map<number, { resolve: (v: any) => void; reject: (e: any) => void }>()
  #seq = 0
  stderr = ''

  private constructor(child: ChildProcess, readonly label: string) {
    this.#child = child
    child.stderr?.on('data', (chunk) => (this.stderr += String(chunk)))
    child.on('message', (message: any) => {
      const waiter = this.#pending.get(message.id)
      if (!waiter) return
      this.#pending.delete(message.id)
      if (message.ok) waiter.resolve(message.result)
      else waiter.reject(Object.assign(new Error(`[${this.label}] ${message.error?.message}`), { code: message.error?.code }))
    })
    child.on('exit', (code) => {
      for (const waiter of this.#pending.values()) waiter.reject(new Error(`[${this.label}] el hijo salió con ${code}:\n${this.stderr}`))
      this.#pending.clear()
    })
  }

  static async start(label: string, phase: Record<string, unknown>): Promise<Phase> {
    const child = fork(CHILD, [], {
      cwd: ROOT,
      execArgv: ['--import', '@poppinss/ts-exec'],
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
      env: { ...process.env, AUTHZ_TEST_REUSE: JSON.stringify(await suiteApp()), CUTOVER_PHASE: JSON.stringify(phase) },
    })
    const instance = new Phase(child, label)
    await new Promise<void>((resolve, reject) => {
      const onExit = (code: number | null) => reject(new Error(`[${label}] el hijo murió antes de arrancar (${code}):\n${instance.stderr}`))
      child.once('exit', onExit)
      child.on('message', function ready(message: any) {
        if (message?.ready) {
          child.off('message', ready)
          child.off('exit', onExit)
          resolve()
        }
      })
    })
    return instance
  }

  send(op: string, payload: Record<string, unknown> = {}): Promise<any> {
    const id = ++this.#seq
    if (!this.#child.connected) return Promise.reject(new Error(`[${this.label}] el hijo ya no está (orden '${op}', paso ${currentStep})`))
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id)
        reject(new Error(`[${this.label}] la orden '${op}' ${JSON.stringify(payload).slice(0, 200)} no respondió en ${OP_TIMEOUT_MS} ms (paso ${currentStep}):\n${this.stderr.slice(-2000)}`))
      }, OP_TIMEOUT_MS)
      this.#pending.set(id, {
        resolve: (v) => {
          clearTimeout(timer)
          resolve(v)
        },
        reject: (e) => {
          clearTimeout(timer)
          reject(e)
        },
      })
      this.#child.send({ id, op, ...payload })
    })
  }

  /** Un comando POR EL KERNEL en el proceso de la fase; queda apuntado para el README. */
  async exec(command: string, argv: string[]): Promise<{ exitCode: number; logs: string[]; error: any; text: string }> {
    executed.push({ step: currentStep, command, argv })
    const run = await this.send('exec', { command, argv })
    return { ...run, text: run.logs.join('\n') }
  }

  #stopped = false
  /** Idempotente: el caso para cada fase y el teardown del grupo por si el caso murió a medias. */
  async stop(): Promise<void> {
    if (this.#stopped) return
    this.#stopped = true
    if (!this.#child.connected) return
    const exited = new Promise<void>((resolve) => this.#child.once('exit', () => resolve()))
    try {
      await this.send('exit')
      await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 5_000))])
    } catch {
      /* ya salió */
    } finally {
      if (this.#child.exitCode === null && this.#child.signalCode === null) this.#child.kill('SIGKILL')
    }
  }
}

/** La escritura de OTRO proceso (el patrón de `freeze_multiprocess.spec`): `accepted` o `<code>/<status>`. */
async function otherProcessWrite(): Promise<string> {
  const output = execFileSync(process.execPath, ['--import', '@poppinss/ts-exec', FREEZE_CHILD], {
    encoding: 'utf-8',
    cwd: ROOT,
    timeout: 60_000,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, AUTHZ_TEST_REUSE: JSON.stringify(await suiteApp()) },
  })
  const line = output.split('\n').find((l) => l.startsWith('{'))
  if (!line) throw new Error(`el hijo del freeze no imprimió JSON:\n${output}`)
  return JSON.parse(line).attempted
}

/**
 * Una bandera tal como la escribe el README: `--to=openfga` fija el VALOR (la letra);
 * `--partition-type=<t>`, `--reason="…"` o `$VAR` admiten cualquiera (placeholder).
 */
interface ReadmeFlag {
  name: string
  value: string | null
}
const parseReadmeFlags = (text: string): ReadmeFlag[] =>
  [...text.matchAll(/(--[a-z-]+)(?:=(\S+))?/g)].map((m) => {
    const raw = m[2]
    const placeholder = raw === undefined || /[<>$"']/.test(raw)
    return { name: m[1], value: placeholder ? null : raw }
  })

/** Las líneas `node ace …` del bloque bash de «The cutover window» del README, con sus banderas (obligatorias y opcionales). */
function readmeRunbook(): Array<{ line: string; command: string; required: ReadmeFlag[]; optional: ReadmeFlag[] }> {
  const readme = readFileSync(README, 'utf8')
  const inicio = readme.indexOf('### The cutover window: `authz:freeze` / `authz:unfreeze`')
  if (inicio < 0) throw new Error('el README ya no tiene la sección «The cutover window»')
  const seccion = readme.slice(inicio, readme.indexOf('\n### ', inicio + 10))
  const desde = seccion.indexOf('```bash')
  const bloque = seccion.slice(desde + 7, seccion.indexOf('```', desde + 7))
  return bloque
    .split('\n')
    .map((l) => l.replace(/#.*$/, '').trim())
    .filter((l) => l.startsWith('node ace '))
    .map((line) => {
      const optional = [...line.matchAll(/\[([^\]]+)\]/g)].flatMap((m) => parseReadmeFlags(m[1]))
      const sinCorchetes = line.replace(/\[[^\]]+\]/g, '')
      const command = sinCorchetes.split(/\s+/)[2]
      const required = parseReadmeFlags(sinCorchetes)
      return { line, command, required, optional }
    })
}

const argvFlags = (argv: string[]): ReadmeFlag[] =>
  argv.filter((a) => a.startsWith('--')).map((a) => {
    const eq = a.indexOf('=')
    return eq === -1 ? { name: a, value: null } : { name: a.slice(0, eq), value: a.slice(eq + 1) }
  })
/** Una bandera ejecutada satisface la del README si coincide el nombre y, cuando el README fija un valor literal, el valor. */
const satisfies = (got: ReadmeFlag, wanted: ReadmeFlag) => got.name === wanted.name && (wanted.value === null || got.value === wanted.value)
/** Una invocación respalda una línea del README si lleva todas las obligatorias y nada fuera de obligatorias ∪ opcionales. */
function backs(inv: Invocation, line: { command: string; required: ReadmeFlag[]; optional: ReadmeFlag[] }): boolean {
  if (inv.command !== line.command) return false
  const got = argvFlags(inv.argv)
  const permitted = [...line.required, ...line.optional]
  return line.required.every((w) => got.some((g) => satisfies(g, w))) && got.every((g) => permitted.some((w) => satisfies(g, w)))
}
const relationTuples = (dump: string[]) => dump.filter((t) => /@(document|group):/.test(t)).sort()

/* ── El runbook ──────────────────────────────────────────────────────────── */

if (!eligible && required) {
  test.group('cutover-runbook · entorno', () => {
    test('el job exige pg/mysql/sqlite-file y OPENFGA_TEST_URL: aquí no se puede ejecutar el runbook y eso es ROJO, no un skip', ({ assert }) => {
      assert.fail(`TEST_DB=${engine} (${engine === 'sqlite' ? 'un hijo no puede abrir :memory:' : 'ok'}) · OPENFGA_TEST_URL=${apiUrl ?? '(sin servidor)'}`)
    })
  })
}

if (eligible) {
  const url: string = apiUrl!
  test.group(`cutover-runbook · ${engine} + OpenFGA real`, (group) => {
    const phases: Phase[] = []
    const stores: string[] = []
    group.setup(async () => {
      await cleanAuthzTables()
      await cleanSqlScopeTree(db)
      await cleanScopeOutbox(db)
    })
    group.teardown(async () => {
      for (const phase of phases) await phase.stop()
      const { OpenFgaClient } = await import('@openfga/sdk')
      while (stores.length) {
        try {
          await new OpenFgaClient({ apiUrl: url, storeId: stores.pop()! }).deleteStore()
        } catch {
          /* best-effort: la red de bin/test.ts barre lo que quede */
        }
      }
      await cleanAuthzTables()
      await cleanSqlScopeTree(db)
      await cleanScopeOutbox(db)
    })

    test('el runbook entero, paso a paso, por el kernel de ace (un proceso por fase)', async ({ assert }) => {
      const ok = (run: { exitCode: number; error: any; text: string }, label: string) => {
        assert.isNull(run.error, `${label}: ${run.error?.name} ${run.error?.code ?? ''}: ${run.error?.message}`)
        assert.equal(run.exitCode, 0, `${label}: exit ${run.exitCode}\n${run.text}`)
      }
      const ko = (run: { exitCode: number; error: any; text: string }, label: string, letra: string) => {
        assert.isNull(run.error, `${label}: ${run.error?.name} ${run.error?.code ?? ''}: ${run.error?.message}`)
        assert.equal(run.exitCode, 1, `${label}: exit ${run.exitCode}\n${run.text}`)
        assert.include(run.text, letra, `${label}: la salida dice qué rama corrió (punto 7)`)
      }

      let store = { apiUrl: url, storeId: '', modelId: '' }
      let seed: any
      const partA = () => ({ type: 'organization', uuid: seed.scopes.org1.uuid })
      const partB = () => ({ type: 'organization', uuid: seed.scopes.org2.uuid })
      const partitionFlags = (p: { type: string; uuid: string }) => [`--partition-type=${p.type}`, `--partition-uuid=${p.uuid}`]
      const docA1 = uuidv7()
      const docA2 = uuidv7()
      const docB1 = uuidv7()
      const groupA = uuidv7()
      const holder = (i: number) => seed.holders[i]

      /* ── 0 · provision (bootstrap sin base: corre aquí, el ÚNICO startApp:false) ── */
      await step(0, 'openfga:provision --url --name crea el store con el modelo facts fusionado', async () => {
        const config = {
          holderTypes: HOLDER_TYPES,
          catalogs: [async () => MIGRATION_CATALOG],
          relations: { config: RELATIONS_SPEC },
          openfga: { url: 'http://127.0.0.1:1/debe-ganar-la-bandera' },
        }
        const name = `runbook-${Date.now()}-${uuidv7().slice(0, 8)}`
        executed.push({ step: 0, command: 'openfga:provision', argv: [`--url=${url}`, `--name=${name}`] })
        const run = await (await aceFor(OpenFgaProvision, { authorization: config })).exec([`--url=${url}`, `--name=${name}`])
        assert.isUndefined(run.error, `${run.error?.constructor?.name}: ${run.error?.message}`)
        assert.equal(run.exitCode ?? 0, 0, JSON.stringify(run.logs))
        const text = run.logs.join('\n')
        store = { apiUrl: url, storeId: /^OPENFGA_STORE_ID=(.+)$/m.exec(text)![1], modelId: /^OPENFGA_MODEL_ID=(.+)$/m.exec(text)![1] }
        stores.push(store.storeId)
        const { OpenFgaClient } = await import('@openfga/sdk')
        const client = new OpenFgaClient({ apiUrl: url, storeId: store.storeId })
        assert.equal((await client.getStore()).name, name, 'el store se llama como --name')
        const model: any = (await client.readLatestAuthorizationModel()).authorization_model
        const types = new Map(model.type_definitions.map((t: any) => [t.type, t]))
        for (const type of ['scope', 'role', 'role_binding', 'user', 'admin', 'document', 'group']) assert.isTrue(types.has(type), `tipo ${type} en el modelo`)
        const { factsRelationsOf } = await import('../src/openfga.js')
        const scope: any = types.get('scope')
        const r = factsRelationsOf('docs:read')
        assert.isTrue(Object.hasOwn(scope.relations, 'rooted'), 'scope#rooted (c2r)')
        for (const name of [r.base, r.can, r.denied]) assert.isTrue(Object.hasOwn(scope.relations, name), `scope#${name}`)
        assert.isTrue(Object.hasOwn((types.get('role') as any).relations, r.permits), `role#${r.permits}`)
      })

      /* ══════════════ ANTES · default: database ══════════════ */
      const antes = await Phase.start('ANTES', { default: 'database', store })
      phases.push(antes)

      await step(1, 'authz:catalog:sync y authz:catalog:diff en verde; la versión compartida sube', async () => {
        const before = await antes.send('catalogVersion')
        ok(await antes.exec('authz:catalog:sync', []), 'sync')
        assert.equal(await antes.send('catalogVersion'), Number(before) + 1, 'authz_catalog_version sube UNA vez')
        ok(await antes.exec('authz:catalog:diff', []), 'diff')
      })

      await step(2, 'siembra: 7 nodos, 6 holders, 14 grants, 6 denies (database) y relaciones en DOS particiones con group', async () => {
        seed = await antes.send('seed', { plant: true })
        const u = (i: number) => ({ type: 'users', uuid: holder(i).uuid })
        await antes.send('relate', {
          driver: 'database',
          tuples: [
            { subject: u(0), relation: 'viewer', object: { type: 'document', id: docA1 }, partition: partA() },
            { subject: u(1), relation: 'member', object: { type: 'group', id: groupA }, partition: partA() },
            { subject: { object: { type: 'group', id: groupA }, relation: 'member' }, relation: 'editor', object: { type: 'document', id: docA2 }, partition: partA() },
            { subject: u(2), relation: 'viewer', object: { type: 'document', id: docB1 }, partition: partB() },
          ],
        })
        assert.lengthOf(await antes.send('enumerateRelations', { driver: 'database', partition: partA() }), 3)
        assert.lengthOf(await antes.send('enumerateRelations', { driver: 'database', partition: partB() }), 1)
        assert.isTrue(await antes.send('check', { driver: 'database', subject: u(1), relation: 'viewer', object: { type: 'document', id: docA2 }, partition: partA() }), 'u2 ve dA2 por el grupo')
      })

      await step(3, 'authz:reconcile --to=openfga --from=database --dry-run sobre el store vacío ⇒ DERIVA (exit 1) y CERO escrituras', async () => {
        ko(await antes.exec('authz:reconcile', ['--to=openfga', '--from=database', '--dry-run']), 'dry-run inicial', 'DERIVA')
        assert.lengthOf(await antes.send('storeDump'), 0, 'el verificador es read-only por contrato')
      })

      await step(4, 'authz:freeze --reason abre la ventana del operador: fila operator sin caducidad y OTRO PROCESO recibe 503 E_AUTHZ_FROZEN', async () => {
        const run = await antes.exec('authz:freeze', ['--reason=cutover to openfga'])
        ok(run, 'freeze')
        assert.include(run.text, 'NO caduca sola')
        const row = await antes.send('freezeRow')
        assert.match(String(row.holder), /^operator:/)
        assert.isNull(row.untilMs)
        assert.equal(await otherProcessWrite(), 'E_AUTHZ_FROZEN/503', 'la ventana alcanza a la flota')
      })

      await step(5, 'authz:relations:reconcile … --partition-* --dry-run (A) ⇒ exit 1 y ninguna tupla de relación en el store', async () => {
        ko(await antes.exec('authz:relations:reconcile', ['--to=openfga', '--from=database', ...partitionFlags(partA()), '--dry-run']), 'relations dry-run A', 'DERIVA')
        assert.lengthOf(relationTuples(await antes.send('storeDump')), 0)
      })

      await step(6, 'authz:relations:reconcile por partición (A y B) dentro de la ventana: las tuplas de cada partición llegan al store, group incluido', async () => {
        ok(await antes.exec('authz:relations:reconcile', ['--to=openfga', '--from=database', ...partitionFlags(partA())]), 'relations A')
        ok(await antes.exec('authz:relations:reconcile', ['--to=openfga', '--from=database', ...partitionFlags(partB())]), 'relations B')
        for (const partition of [partA(), partB()]) {
          assert.deepEqual(
            await antes.send('enumerateRelations', { driver: 'openfga', partition }),
            await antes.send('enumerateRelations', { driver: 'database', partition }),
            `partición ${partition.uuid}: el store tiene exactamente las tuplas del origen`
          )
        }
        assert.lengthOf(relationTuples(await antes.send('storeDump')), 4)
      })

      await step(7, 'authz:reconcile --to=openfga --from=database dentro de la ventana del operador: exit 0, la ventana aguantó entera, 448 respuestas iguales', async () => {
        const run = await antes.exec('authz:reconcile', ['--to=openfga', '--from=database'])
        ok(run, 'reconcile')
        assert.include(run.text, 'operador', 'la pasada dice en QUÉ ventana corrió')
        assert.include(run.text, 'dentro de la ventana del operador')
        const a = await antes.send('questions', { driver: 'database' })
        const b = await antes.send('questions', { driver: 'openfga' })
        assert.lengthOf(Object.keys(a), MIGRATION_QUESTION_COUNT)
        const distintas = Object.keys(a).filter((id) => a[id] !== b[id])
        assert.deepEqual(distintas, [], `${distintas.length} de ${MIGRATION_QUESTION_COUNT} respuestas cambian: ${distintas.slice(0, 5).join(', ')}`)
      })

      await step(8, 'authz:reconcile --prune sobre el store COMPARTIDO: las tuplas de relación quedan intactas y se reportan como ajenas', async () => {
        const before = relationTuples(await antes.send('storeDump'))
        const run = await antes.exec('authz:reconcile', ['--to=openfga', '--from=database', '--prune'])
        ok(run, 'reconcile --prune')
        assert.include(run.text, 'ajenas', 'lo que esta pasada NO gobierna se dice')
        assert.deepEqual(relationTuples(await antes.send('storeDump')), before, '--prune no toca lo ajeno (alpha.9 · B)')
      })

      await step(9, 'verificar ANTES del switch: roles y relaciones con --from … --dry-run en verde', async () => {
        const roles = await antes.exec('authz:reconcile', ['--to=openfga', '--from=database', '--dry-run'])
        ok(roles, 'roles dry-run')
        assert.include(roles.text, 'Sin deriva')
        for (const partition of [partA(), partB()]) {
          const rel = await antes.exec('authz:relations:reconcile', ['--to=openfga', '--from=database', ...partitionFlags(partition), '--dry-run'])
          ok(rel, `relations dry-run ${partition.uuid}`)
          assert.include(rel.text, 'Sin deriva')
        }
      })

      await step(10, 'authz:unfreeze cierra la ventana: fila limpia y la escritura del OTRO PROCESO entra', async () => {
        ok(await antes.exec('authz:unfreeze', []), 'unfreeze')
        assert.isNull((await antes.send('freezeRow')).reason)
        assert.equal(await otherProcessWrite(), 'accepted')
      })
      await antes.stop()

      /* ══════════════ DESPUÉS · default: openfga (redeploy) ══════════════ */
      const despues = await Phase.start('DESPUÉS', { default: 'openfga', store })
      phases.push(despues)
      await despues.send('seed', { plant: false, seed })
      const u1 = () => holder(0)
      const u2 = () => holder(1)
      const u3 = () => holder(2)

      await step(11, 'escrituras tras el cutover (en openfga): revoke, deny, scopes.detached + authz:scopes:relay purga el scope del store', async () => {
        assert.isTrue(await despues.send('authorize', { subject: u1(), permission: 'docs:write', scope: seed.scopes.org1 }), 'u1 mig-editor@app concede antes del revoke')
        await despues.send('revoke', { subject: u1(), role: 'mig-editor', scope: seed.scopes.app })
        assert.isFalse(await despues.send('authorize', { subject: u1(), permission: 'docs:write', scope: seed.scopes.org1 }))
        assert.isTrue(await despues.send('authorize', { subject: u2(), permission: 'docs:read', scope: seed.scopes.org1 }), 'u2 mig-viewer@org1')
        await despues.send('deny', { subject: u2(), permission: 'docs:read', scope: seed.scopes.org1 })
        assert.isFalse(await despues.send('authorize', { subject: u2(), permission: 'docs:read', scope: seed.scopes.org1 }), 'el deny nuevo gana')
        await despues.send('detach', { scope: seed.scopes.unit3 })
        ok(await despues.exec('authz:scopes:relay', []), 'relay')
        const dump: string[] = await despues.send('storeDump')
        assert.isFalse(dump.some((t) => t.includes(`unit|${seed.scopes.unit3.uuid}`)), 'el scope borrado se purgó del store')
      })

      await step(12, 'REPETIDA en dirección rancia (openfga activo): --from=database con y sin --prune y las relaciones ⇒ refusada, nada escrito, la revocación NO resucita', async () => {
        const dumpBefore = await despues.send('storeDump')
        for (const argv of [
          ['--to=openfga', '--from=database'],
          ['--to=openfga', '--from=database', '--prune'],
        ]) {
          const run = await despues.exec('authz:reconcile', argv)
          ko(run, `rancia ${argv.join(' ')}`, 'es el driver ACTIVO')
          assert.include(run.text, 'No se ha leído, congelado ni escrito nada')
        }
        const rel = await despues.exec('authz:relations:reconcile', ['--to=openfga', '--from=database', ...partitionFlags(partA())])
        ko(rel, 'relaciones rancia', 'No se ha construido, leído, congelado ni escrito nada')
        assert.deepEqual(await despues.send('storeDump'), dumpBefore, 'el store es idéntico tras las tres negativas')
        assert.isFalse(await despues.send('authorize', { subject: u1(), permission: 'docs:write', scope: seed.scopes.org1 }), 'la revocación sigue')
      })

      await step(13, 'mantenimiento tras el switch: --dry-run sin --from en verde; una fila del árbol borrada SIN detached ⇒ --prune la limpia y el resto sigue concediendo', async () => {
        const verify = await despues.exec('authz:reconcile', ['--to=openfga', '--dry-run'])
        ok(verify, 'mantenimiento dry-run')
        assert.include(verify.text, 'Sin deriva')
        ok(await despues.exec('authz:reconcile', ['--to=openfga']), 'mantenimiento')
        await despues.send('deleteScopeRow', { scope: seed.scopes.unit4 })
        const prune = await despues.exec('authz:reconcile', ['--to=openfga', '--prune'])
        assert.isNull(prune.error, `mantenimiento --prune: ${prune.error?.message}`)
        assert.notInclude(prune.text, 'ni borra', 'la letra de mantenimiento dice lo que --prune borra (alpha.10)')
        assert.include(prune.text, 'borradas 4', 'los 4 tuplas del scope muerto (2 assignee + role + binding) se borran')
        const dump: string[] = await despues.send('storeDump')
        assert.isFalse(dump.some((t) => t.includes(`unit|${seed.scopes.unit4.uuid}`)), 'los hechos del scope muerto se fueron')
        // Observado al construir el runbook (2026-10-14): la pasada BORRABA los hechos del scope
        // muerto y a la vez los contaba en `skipped.unknown-scope` ⇒ «queda algo que esta pasada
        // no arregla sola», exit 1, cuando sí lo arregló (punto 7: la salida miente de rama).
        // Cerrado en el lote A (F-R1, linaje L8): el bucket es `pruned`, la letra dice BORRADOS y
        // el exit es 0. El hallazgo se queda como aserción del runbook.
        finding(
          'F-R1',
          prune.exitCode === 0,
          `mantenimiento --prune borró los hechos del scope muerto (borradas 4, el store ya no los tiene) y aun así salió ${prune.exitCode} ` +
            'contándolos en skipped.unknown-scope («queda algo que esta pasada no arregla sola»)'
        )
        assert.include(prune.text, "del propio store por 'unknown-scope' BORRADOS por --prune", 'F-R1: la letra dice lo que hizo')
        assert.notInclude(prune.text, "sin migrar por 'unknown-scope'", 'F-R1: y no lo cuenta como sin migrar')
        const again = await despues.exec('authz:reconcile', ['--to=openfga', '--dry-run'])
        ok(again, 'verificador tras el --prune')
        assert.include(again.text, 'Sin deriva', 'la segunda pasada confirma que la primera lo dejó limpio')
        assert.isTrue(await despues.send('authorize', { subject: u3(), permission: 'docs:read', scope: seed.scopes.unit1 }), 'u3 mig-lead@unit1 sigue concediendo')
      })

      await step(14, 'ventana CADUCADA antes de la pasada: la flota escribe, reconcile la reconoce (503) y no la pisa, unfreeze sale 1 con la hora y limpia; el segundo unfreeze es éxito', async () => {
        await despues.send('clock', { offsetMs: -10 * 60_000 })
        const freeze = await despues.exec('authz:freeze', ['--reason=cutover corto', '--lease-ms=60000'])
        ok(freeze, 'freeze --lease-ms')
        assert.include(freeze.text, 'caduca SOLA')
        await despues.send('clock', { offsetMs: 0 })
        assert.equal(await otherProcessWrite(), 'accepted', 'vencido el lease los escritores vuelven SOLOS (el precio declarado)')
        ko(await despues.exec('authz:reconcile', ['--to=openfga']), 'reconcile sobre ventana caducada', 'CADUCÓ el')
        assert.isNotNull((await despues.send('freezeRow')).reason, 'la fila CONSERVA el rastro')
        const unfreeze = await despues.exec('authz:unfreeze', [])
        ko(unfreeze, 'unfreeze caducada', 'CADUCÓ el')
        assert.match(unfreeze.text, /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/, 'la hora ISO')
        assert.isNull((await despues.send('freezeRow')).reason)
        const again = await despues.exec('authz:unfreeze', [])
        ok(again, 'segundo unfreeze')
        assert.include(again.text, 'nada que levantar')
      })

      await step(15, 'ventana del operador ADOPTADA con lease: la pasada dice cuándo caduca', async () => {
        ok(await despues.exec('authz:freeze', ['--reason=con lease', '--lease-ms=600000']), 'freeze con lease')
        const run = await despues.exec('authz:reconcile', ['--to=openfga'])
        ok(run, 'reconcile adoptando la ventana')
        assert.include(run.text, 'CADUCA el')
        ok(await despues.exec('authz:unfreeze', []), 'unfreeze')
      })

      await step(16, 'pasada ABORTADA: el freeze de un proceso muerto (lease vivo) bloquea la pasada y unfreeze solo lo levanta con --fence; con el lease vencido, la pasada lo pisa', async () => {
        const token = await despues.send('acquirePassFreeze', { reason: 'authz:reconcile --to=openfga', holder: 'reconcile:muerto', untilMs: Date.now() + 600_000 })
        assert.isNotNull(token)
        const held = await despues.exec('authz:reconcile', ['--to=openfga'])
        // F-R3 (lote A): el 423 sale como LETRA con exit 1 —como su gemelo de relaciones—, no como error crudo.
        ko(held, 'dos pasadas no se pisan (E_AUTHZ_FREEZE_HELD como letra)', `fence ${token.fence}`)
        assert.include(held.text, 'authz:unfreeze', 'y cómo se levanta')
        assert.isNull(held.error, `F-R3: el freeze ajeno ya no es un error crudo del comando: ${held.error?.message}`)
        const refuse = await despues.exec('authz:unfreeze', [])
        ko(refuse, 'unfreeze de una pasada ajena', `--fence=${token.fence}`)
        ok(await despues.exec('authz:unfreeze', [`--fence=${token.fence}`]), 'unfreeze --fence (decisión humana)')
        assert.isNull((await despues.send('freezeRow')).reason)
        const dead = await despues.send('acquirePassFreeze', { reason: 'authz:reconcile --to=openfga', holder: 'reconcile:muerto-sin-lease', untilMs: Date.now() - 1000 })
        assert.isNotNull(dead)
        const takeover = await despues.exec('authz:reconcile', ['--to=openfga'])
        ok(takeover, 'la pasada pisa el lease VENCIDO de otra pasada (SIGKILL)')
        assert.include(takeover.text, 'SU PROPIA ventana')
        assert.isNull((await despues.send('freezeRow')).reason)
      })

      await step(17, 'vuelta atrás ANTES de cambiar default: --to=database --from=openfga (--prune) y las relaciones por partición, verificadas, dentro de una ventana', async () => {
        ok(await despues.exec('authz:freeze', ['--reason=rollback']), 'freeze')
        ok(await despues.exec('authz:reconcile', ['--to=database', '--from=openfga', '--prune']), 'vuelta de roles')
        for (const partition of [partA(), partB()]) {
          ok(await despues.exec('authz:relations:reconcile', ['--to=database', '--from=openfga', ...partitionFlags(partition)]), `vuelta de relaciones ${partition.uuid}`)
          assert.deepEqual(
            await despues.send('enumerateRelations', { driver: 'database', partition }),
            await despues.send('enumerateRelations', { driver: 'openfga', partition })
          )
        }
        const verify = await despues.exec('authz:reconcile', ['--to=database', '--from=openfga', '--dry-run'])
        ok(verify, 'verificador de la vuelta')
        assert.include(verify.text, 'Sin deriva')
        const a = await despues.send('questions', { driver: 'database' })
        const b = await despues.send('questions', { driver: 'openfga' })
        const distintas = Object.keys(a).filter((id) => a[id] !== b[id])
        assert.deepEqual(distintas, [], `${distintas.length} respuestas cambian tras la vuelta: ${distintas.slice(0, 5).join(', ')}`)
        ok(await despues.exec('authz:unfreeze', []), 'unfreeze')
      })
      await despues.stop()

      /* ══════════════ VUELTA · default: database (redeploy) ══════════════ */
      const vuelta = await Phase.start('VUELTA', { default: 'database', store })
      phases.push(vuelta)
      await vuelta.send('seed', { plant: false, seed })

      await step(18, 'con database activo las 448 respuestas siguen iguales en los dos drivers y la revocación del cutover está en authz_*', async () => {
        const a = await vuelta.send('questions', { driver: 'database' })
        const b = await vuelta.send('questions', { driver: 'openfga' })
        assert.deepEqual(Object.keys(a).filter((id) => a[id] !== b[id]), [])
        assert.isFalse(await vuelta.send('authorize', { subject: u1(), permission: 'docs:write', scope: seed.scopes.org1 }))
      })

      await step(19, 'REPETIDA en dirección rancia con database activo: --to=database sin --from, con --from=openfga, y las relaciones ⇒ refusada sin escribir', async () => {
        const census = await vuelta.send('authzCensus')
        for (const argv of [['--to=database'], ['--to=database', '--from=openfga']]) {
          ko(await vuelta.exec('authz:reconcile', argv), `rancia ${argv.join(' ')}`, 'es el driver ACTIVO')
        }
        ko(await vuelta.exec('authz:relations:reconcile', ['--to=database', '--from=openfga', ...partitionFlags(partA())]), 'relaciones rancia', 'No se ha construido, leído, congelado ni escrito nada')
        assert.deepEqual(await vuelta.send('authzCensus'), census, 'authz_* no cambió')
      })
      await vuelta.stop()

      /* ══════════════ PENDING · lote D (deny): se activan cuando D esté en main ══════════════ */
      pending(20, 'opt-in del deny en dos fases: fase 1 ⇒ `deny` 422; fase 2 (modelo con denied_*) ⇒ deny vivo y check=false en los dos drivers', 'D')
      pending(21, 'rollback prohibido con denies vivos: retirar el opt-in ⇒ provision exit 1 / 500, y la vuelta no deja un deny sin honrar', 'D')

      const resumen = steps.map((s) => `${s.status === 'ok' ? '✔' : s.status === 'pending' ? '…' : '✖'} ${s.n} ${s.label}${s.lot ? ` [pendiente: lote ${s.lot}]` : ''}`)
      console.log(`[cutover-runbook] ${engine}: ${steps.filter((s) => s.status === 'ok').length} pasos en verde, ${steps.filter((s) => s.status === 'pending').length} pendientes\n  ${resumen.join('\n  ')}`)
      assert.deepEqual(findings, [], `el runbook recorrió todos los pasos y encontró ${findings.length} hallazgo(s):\n  ${findings.join('\n  ')}`)
    }).timeout(120_000)

    test('docs con dientes: cada `node ace …` del runbook del README tiene su paso ejecutable (mismo comando, mismas banderas)', ({ assert }) => {
      const lines = readmeRunbook()
      assert.isAtLeast(lines.length, 7, 'el bloque bash del README sigue siendo el runbook')
      const sinPaso = lines.filter((line) => !executed.some((inv) => backs(inv, line)))
      assert.deepEqual(
        sinPaso.map((l) => l.line),
        [],
        'líneas del README sin paso ejecutable: el runbook publicado no está respaldado por el job (o el paso se borró)'
      )
      console.log(`[cutover-runbook] README: ${lines.length} líneas, todas con paso ejecutable; invocaciones por el kernel: ${executed.length}`)
    })
  })
}
