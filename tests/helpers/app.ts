/**
 * Arranque autónomo de AdonisJS + Lucid para los tests del PAQUETE.
 *
 * El motor depende de `@adonisjs/lucid/services/db` (un singleton del
 * contenedor), así que necesita una app booteada — pero no un proyecto Adonis
 * completo. Aquí se monta lo mínimo sobre el motor SQL que pida `TEST_DB`
 * (2.5 · J2), de modo que la MISMA suite corra en CI sin la app anfitriona:
 *
 *   TEST_DB=sqlite       (default) SQLite en memoria, pool 1/1: `npm test`
 *   TEST_DB=sqlite-file  SQLite en fichero (mkdtemp) con pool 2..5: concurrencia real
 *   TEST_DB=pg           PostgreSQL vía TEST_PG_URL (default postgres://postgres:postgres@127.0.0.1:5432/authz_test)
 *   TEST_DB=mysql        MySQL vía TEST_MYSQL_URL (default mysql://root:root@127.0.0.1:3306/authz_test)
 *
 * Con PG/MySQL la base de la URL es solo el NOMBRE BASE: cada ejecución crea
 * `<nombre>_<sufijo aleatorio>` desde una conexión administrativa (`postgres`
 * / sin base) y la borra al terminar (`teardown`). Nunca se toca una base
 * existente del servidor: dos suites en paralelo no se pisan y una que muere
 * a medias deja como mucho una base con sufijo que se reconoce a simple vista.
 *
 * Orden importante: `setApp()` ANTES de que se importe `services/db.js` — ese
 * módulo hace `await app.booted(...)` en su top-level.
 */

import { AppFactory } from '@adonisjs/core/factories/app'
import { setApp } from '@adonisjs/core/services/app'
import { LoggerFactory } from '@adonisjs/core/factories/logger'
import { Emitter } from '@adonisjs/core/events'
import { Database } from '@adonisjs/lucid/database'
import { BaseModel } from '@adonisjs/lucid/orm'
import { randomBytes } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export type TestEngine = 'sqlite' | 'sqlite-file' | 'pg' | 'mysql'

const ENGINES: TestEngine[] = ['sqlite', 'sqlite-file', 'pg', 'mysql']

/** Motor pedido por `TEST_DB` (default `sqlite`); un valor desconocido es un error, no un default silencioso. */
export function testEngine(): TestEngine {
  const raw = process.env.TEST_DB ?? 'sqlite'
  if (!(ENGINES as string[]).includes(raw)) {
    throw new Error(`TEST_DB='${raw}' no es un motor de la suite (${ENGINES.join(' | ')})`)
  }
  return raw as TestEngine
}

export interface TestApp {
  db: Database
  engine: TestEngine
  /** Nombre de la base creada para esta ejecución (PG/MySQL), o el fichero (sqlite-file), o `:memory:`. */
  database: string
  /**
   * Config de la conexión principal (cliente + credenciales + base de ESTA
   * ejecución): lo que otro PROCESO necesita para abrir la misma base
   * (`bootApp({ reuse })`, tests de dos procesos — 2.5-B · K2).
   */
  connection: Record<string, unknown>
  /** Cierra el pool y destruye la base/fichero de esta ejecución. Idempotente. */
  teardown(): Promise<void>
}

export interface BootOptions {
  /**
   * Abre una base YA provisionada por otro proceso (la `connection` de su
   * `TestApp`) en vez de crear una: `teardown()` solo cierra el pool, nunca
   * destruye lo que no es suyo. Para procesos hijos que comparten la base de
   * la suite (2.5-B · K2: dos procesos con `TZ` distinta).
   */
  reuse?: { engine: TestEngine; connection: Record<string, unknown>; database: string }
}

const DEFAULT_URLS: Record<'pg' | 'mysql', string> = {
  pg: 'postgres://postgres:postgres@127.0.0.1:5432/authz_test',
  mysql: 'mysql://root:root@127.0.0.1:3306/authz_test',
}

function parseUrl(engine: 'pg' | 'mysql'): { host: string; port: number; user: string; password: string; baseName: string } {
  const variable = engine === 'pg' ? 'TEST_PG_URL' : 'TEST_MYSQL_URL'
  const url = new URL(process.env[variable] ?? DEFAULT_URLS[engine])
  const baseName = url.pathname.replace(/^\//, '') || 'authz_test'
  if (!/^[a-z_][a-z0-9_]*$/i.test(baseName)) {
    throw new Error(`${variable}: el nombre base '${baseName}' tiene que ser un identificador simple`)
  }
  return {
    host: url.hostname,
    port: Number(url.port || (engine === 'pg' ? 5432 : 3306)),
    user: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    baseName,
  }
}

/** Nombre único por ejecución: `<base>_<8 hex>`. */
function uniqueName(baseName: string): string {
  return `${baseName}_${randomBytes(4).toString('hex')}`
}

function makeDatabase(app: any, connection: Record<string, unknown>): Database {
  return new Database(
    { connection: 'primary', connections: { primary: connection } } as any,
    new LoggerFactory().create(),
    new Emitter(app) as any
  )
}

/**
 * Crea la base de esta ejecución desde una conexión administrativa y
 * devuelve la config de la conexión principal y cómo destruirla.
 */
async function provisionServerDatabase(
  app: any,
  engine: 'pg' | 'mysql'
): Promise<{ connection: Record<string, unknown>; database: string; drop(): Promise<void> }> {
  const { host, port, user, password, baseName } = parseUrl(engine)
  const database = uniqueName(baseName)
  const client = engine === 'pg' ? 'pg' : 'mysql2'
  const adminConnection = engine === 'pg' ? { host, port, user, password, database: 'postgres' } : { host, port, user, password }
  const admin = makeDatabase(app, { client, connection: adminConnection, pool: { min: 0, max: 1 } })
  const adminSql = (sql: string) => admin.rawQuery(sql)
  try {
    if (engine === 'pg') await adminSql(`CREATE DATABASE "${database}"`)
    else await adminSql(`CREATE DATABASE \`${database}\` CHARACTER SET utf8mb4`)
  } finally {
    await admin.manager.closeAll()
  }
  return {
    connection: {
      client,
      connection: {
        host,
        port,
        user,
        password,
        database,
        // MySQL (2.5-B · K2): la suite abre su conexión con `timezone: 'Z'`
        // (mysql2 serializa/parsea los `Date` en UTC). El driver NO depende
        // de esta opción —escribe y lee `expires_at` como cadena UTC
        // explícita— y `expiry_timezone.spec` lo demuestra con procesos
        // hijos que abren la MISMA base sin ella y con `TZ` distinta.
        ...(engine === 'mysql' ? { timezone: 'Z' } : {}),
      },
      pool: { min: 2, max: 5 },
    },
    database,
    drop: async () => {
      const again = makeDatabase(app, { client, connection: adminConnection, pool: { min: 0, max: 1 } })
      try {
        if (engine === 'pg') await again.rawQuery(`DROP DATABASE IF EXISTS "${database}" WITH (FORCE)`)
        else await again.rawQuery(`DROP DATABASE IF EXISTS \`${database}\``)
      } finally {
        await again.manager.closeAll()
      }
    },
  }
}

/** La app booteada por `bootApp` (para abrir bases de trabajo con su emitter). */
let bootedApp: any = null

export interface ScratchDatabase {
  db: Database
  /** Config de la conexión (para un proceso hijo: `bootApp({ reuse })`). */
  connection: Record<string, unknown>
  database: string
  engine: TestEngine
  /** Cierra el pool y destruye la base/fichero. Idempotente. */
  drop(): Promise<void>
}

/**
 * OTRA base vacía del mismo motor que la suite (2.5-B · K11/K14), aparte
 * de la de la suite: para ejecutar ahí una migración (la publicada, o la de
 * 1.x más la receta de subida) y compararla con el espejo. PG/MySQL: otra
 * base con sufijo; `sqlite-file`: otro fichero; `sqlite`: otra `:memory:`.
 * Se destruye con `drop()`; nunca toca la base de la suite.
 */
export async function openScratchDatabase(): Promise<ScratchDatabase> {
  if (!bootedApp) throw new Error('openScratchDatabase: bootApp() primero')
  const engine = testEngine()
  let connection: Record<string, unknown>
  let database: string
  let destroy: () => Promise<void> = async () => {}
  if (engine === 'sqlite') {
    database = ':memory:'
    connection = { client: 'better-sqlite3', connection: { filename: ':memory:' }, useNullAsDefault: true, pool: { min: 1, max: 1 } }
  } else if (engine === 'sqlite-file') {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'authz-sqlite-scratch-'))
    database = path.join(dir, 'scratch.sqlite')
    connection = { client: 'better-sqlite3', connection: { filename: database }, useNullAsDefault: true, pool: { min: 2, max: 5 } }
    destroy = async () => fs.rmSync(dir, { recursive: true, force: true })
  } else {
    const provisioned = await provisionServerDatabase(bootedApp, engine)
    connection = provisioned.connection
    database = provisioned.database
    destroy = provisioned.drop
  }
  const scratch = makeDatabase(bootedApp, connection)
  let dropped = false
  return {
    db: scratch,
    connection,
    database,
    engine,
    drop: async () => {
      if (dropped) return
      dropped = true
      await scratch.manager.closeAll()
      await destroy()
    },
  }
}

/**
 * Red de seguridad SÍNCRONA contra el `process.exit()` (3b-1, ⚪ 4 de 3b-0b).
 *
 * La fuga «no determinista» de bases en PostgreSQL no estaba en la suite —que
 * cierra a cero, medido— sino en los scripts de reproducción que viven fuera
 * de ella: `bootApp()` … `process.exit(0)`, el patrón de TODOS los `*.ts` de
 * `.claude/reproducciones/`. `process.exit()` no espera a ninguna promesa, así
 * que `teardown()` no llega a correr y queda exactamente UNA base huérfana
 * por ejecución (reproducido: 3 scripts ⇒ 3 bases). Por eso dos re-ejecuciones
 * aisladas de la suite nunca lo reproducían.
 *
 * `process.on('exit')` es lo único que corre ahí, y solo admite trabajo
 * SÍNCRONO: `spawnSync` de `drop_database.mjs`. Además AVISA por stderr, para
 * que una fuga no vuelva a ser silenciosa. Es del harness, no del paquete.
 */
function registerExitGuard(
  engine: TestEngine,
  connection: Record<string, unknown>,
  database: string,
  isTorn: () => boolean
): () => void {
  if (engine === 'sqlite') return () => {} // la base vive dentro de la conexión
  if (engine === 'sqlite-file') {
    // El fichero se borra con el directorio temporal, y `fs.rmSync` YA es
    // síncrono: no hace falta salir del proceso.
    const dir = path.dirname(database)
    const onExitFile = () => {
      if (isTorn()) return
      process.stderr.write(
        `\n[harness] el proceso salió SIN await app.teardown() (¿process.exit?): borrando '${dir}' desde el guard de salida.\n`
      )
      fs.rmSync(dir, { recursive: true, force: true })
    }
    process.on('exit', onExitFile)
    return () => process.off('exit', onExitFile)
  }
  const conn: any = (connection as any).connection ?? {}
  const payload = JSON.stringify({
    engine,
    host: conn.host,
    port: conn.port,
    user: conn.user,
    password: conn.password,
    database,
  })
  const script = fileURLToPath(new URL('./drop_database.mjs', import.meta.url))
  const onExit = () => {
    if (isTorn()) return
    process.stderr.write(
      `\n[harness] el proceso salió SIN await app.teardown() (¿process.exit?): destruyendo '${database}' desde el guard de salida.\n`
    )
    const done = spawnSync(process.execPath, [script, payload], { stdio: 'inherit', timeout: 30_000 })
    if (done.status !== 0) {
      process.stderr.write(`[harness] NO se pudo destruir '${database}': bórrala a mano.\n`)
    }
  }
  process.on('exit', onExit)
  return () => process.off('exit', onExit)
}

export async function bootApp(options: BootOptions = {}): Promise<TestApp> {
  const engine = options.reuse?.engine ?? testEngine()
  const app = new AppFactory().create(new URL('../../', import.meta.url), () => {}) as any
  await app.init()
  setApp(app)
  bootedApp = app

  let connection: Record<string, unknown>
  let database: string
  let destroy: () => Promise<void> = async () => {}
  if (options.reuse) {
    connection = options.reuse.connection
    database = options.reuse.database
  } else if (engine === 'sqlite') {
    database = ':memory:'
    connection = {
      client: 'better-sqlite3',
      connection: { filename: ':memory:' },
      useNullAsDefault: true,
      // SQLite en memoria vive dentro de UNA conexión: con pool > 1 cada
      // conexión vería su propia base vacía.
      pool: { min: 1, max: 1 },
    }
  } else if (engine === 'sqlite-file') {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'authz-sqlite-'))
    database = path.join(dir, 'authz.sqlite')
    connection = {
      client: 'better-sqlite3',
      connection: { filename: database },
      useNullAsDefault: true,
      // Varias conexiones sobre el MISMO fichero: es lo que hace observable
      // la concurrencia (J4) y lo que un `{trx}` (2.6) necesita para no
      // colgarse esperando la única conexión del pool.
      pool: { min: 2, max: 5 },
    }
    destroy = async () => fs.rmSync(dir, { recursive: true, force: true })
  } else {
    const provisioned = await provisionServerDatabase(app, engine)
    connection = provisioned.connection
    database = provisioned.database
    destroy = provisioned.drop
  }

  const db = makeDatabase(app, connection)
  app.container.singleton(Database, () => db)

  // El middleware resuelve el manager del contenedor (services/main.ts), así
  // que el binding tiene que existir antes de que se importe.
  app.container.singleton('authz.manager', async () => {
    const { AuthorizationManager } = await import('../../src/manager.js')
    const { DatabaseAuthorizationDriver } = await import('../../src/drivers/database_driver.js')
    return new AuthorizationManager({
      default: 'database',
      drivers: { database: () => new DatabaseAuthorizationDriver() },
      warnOnOptInSecurity: false,
    } as any)
  })

  await app.boot()

  BaseModel.useAdapter(db.modelAdapter())

  if (engine === 'sqlite-file' && !options.reuse) {
    // WAL: lectores y un escritor a la vez sobre el fichero; `busy_timeout`
    // lo trae better-sqlite3 por defecto (5 s), así que un segundo escritor
    // espera en vez de fallar con SQLITE_BUSY.
    await db.rawQuery('PRAGMA journal_mode = WAL')
  }

  let torn = false
  // Solo la app que PROVISIONÓ la base la destruye: un hijo con `reuse` la
  // comparte y borrarla al salir se llevaría la del padre.
  const unregister = options.reuse ? () => {} : registerExitGuard(engine, connection, database, () => torn)
  return {
    db,
    engine,
    database,
    connection,
    teardown: async () => {
      if (torn) return
      torn = true
      unregister()
      await db.manager.closeAll()
      await destroy()
    },
  }
}
