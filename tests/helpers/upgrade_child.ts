/**
 * Proceso HIJO de `upgrade_recipe.spec` (2.5-B · K14, tester G5): sobre una
 * base de trabajo vacía (la `connection` que le llega por `AUTHZ_TEST_REUSE`)
 * ejecuta la migración de 1.1.0 (`tests/fixtures/migration-1.1.0.stub`),
 * aplica LITERALMENTE las sentencias SQL de la receta del README (llegan por
 * `AUTHZ_UPGRADE_SQL`, una por elemento) y encima corre el motor 2.x:
 * identidad que no es UUID, caducidad al milisegundo, comparación byte a
 * byte, versión del catálogo. Imprime UNA línea JSON con lo observado y la
 * descripción del esquema resultante (para compararla con la publicada).
 *
 * Es un hijo porque el driver `database` habla con el `db` global de Lucid:
 * la única forma de apuntarlo a otra base es otro proceso.
 *
 * Rotación 3 · R3-01: con `AUTHZ_UPGRADE_LEGACY_EXPIRY` (JSON `string[]` de
 * instantes ISO) siembra ANTES de la receta una asignación de 1.x con esa
 * caducidad por instante, escrita como la escribía 1.1.0 (`grant` de 1.x: el
 * query builder de Lucid con un `Date`, la conexión sin `timezone` ⇒ `mysql2`
 * con `'local'`, el `TZ` que el padre le pone a este proceso). Comprueba la
 * semántica de 1.x antes de la receta (`expires_at > new Date()`, su
 * `whereActive`) y la de 2.x después (el driver a 1 ms del instante y en él).
 *
 * Rotación 3 · cierre 2: la receta NO va en una transacción (en MySQL cada DDL
 * hace commit implícito: no sería todo-o-nada y aparentarlo era mentir). Va en
 * PASADAS (`AUTHZ_UPGRADE_PASSES`, JSON `[{ from, to }]`, por defecto el bloque
 * entero una vez): cada pasada ejecuta `statements[from, to)` por su PROPIA
 * sesión (una conexión cruda del pool, retenida hasta el final para que la
 * siguiente sea otra) y se para en el primer error, como una migración. Así se
 * escribe «falla tras la sentencia k y se re-ejecuta entero en otra sesión»
 * (`[{0,k},{0,n}]`) o «la conversión llega a otra sesión» (`[{0,u},{u,n}]`).
 * `AUTHZ_UPGRADE_PRELUDE` (JSON `string[]`) abre cada sesión de la receta (p. ej.
 * `sql_mode` no estricto, o una zona de sesión distinta de la global). Los
 * errores de cada pasada salen en `passes`; con `AUTHZ_UPGRADE_STOP=1` el hijo
 * imprime solo el estado (pasadas, caducidades guardadas, tipo de columna,
 * marcador) sin correr 2.x. `AUTHZ_UPGRADE_FIX_SQL` (JSON `string[]`, RR-5) se
 * ejecuta `AUTHZ_UPGRADE_FIX_RUNS` veces (sesiones nuevas) DESPUÉS de los grants
 * de 2.x, con la línea `SET @authz_upgraded_at = …` sustituida por el instante
 * en que terminó la receta (como la rellenaría el operador).
 *
 * Rotación 3 · cierre 3: en MySQL la subida es el COMANDO `authz:upgrade-1x` (el bloque SQL dejó de ser un camino).
 * `AUTHZ_UPGRADE_COMMAND` (JSON `string[][]`: argv de cada ejecución) lo corre por el KERNEL de ace en este proceso, en
 * lugar de `AUTHZ_UPGRADE_SQL`, sobre una conexión `upgrade` de la misma base cuyas sesiones nacen con `sql_mode = ''` y
 * `time_zone = '+05:00'` (el comando tiene que deshacer las dos). `AUTHZ_UPGRADE_FIX_COMMAND` (argv con `{upgradedAt}`
 * sustituido por el instante en que terminó la subida vieja, ISO) es la corrección `--fix-previous-upgrade` tras los
 * grants de 2.x. Cada ejecución sale en `commandRuns`/`fixRuns` como `{ error, exitCode, first }` (`error` = la salida si
 * el exit no es 0).
 */

import { readFile } from 'node:fs/promises'
import { bootApp } from './app.js'
import { describeAuthzSchema, runMigrationSource } from './schema.js'

const reuse = JSON.parse(process.env.AUTHZ_TEST_REUSE ?? 'null')
const statements: string[] = JSON.parse(process.env.AUTHZ_UPGRADE_SQL ?? '[]')
const commandRunsSpec: string[][] = JSON.parse(process.env.AUTHZ_UPGRADE_COMMAND ?? '[]')
if (!reuse || (statements.length === 0 && commandRunsSpec.length === 0)) {
  console.error('uso: AUTHZ_TEST_REUSE=<json> AUTHZ_UPGRADE_SQL=<json string[]> upgrade_child.ts')
  process.exit(2)
}

const app = await bootApp({ reuse })
try {
  const old = await readFile(new URL('../fixtures/migration-1.1.0.stub', import.meta.url), 'utf8')
  await runMigrationSource(app.db, old)
  // Un rol que YA existía en 1.x (3B · B1, tester §4): tras la receta tiene que
  // quedar global (`owner_scope_key = 'global'`) y el unique nuevo no puede
  // reventar; el sync 2.x lo reconoce como el mismo rol (mismo uuid).
  const legacyUuid = '0192a000-0000-7000-8000-00000000abcd'
  await app.db.table('authz_roles').insert({ uuid: legacyUuid, slug: 'legacy', name: 'legacy', scope_type: 'app', rank: 7, created_at: new Date(), updated_at: new Date() })
  // R3-01: asignaciones de 1.x con caducidad, escritas como las escribía 1.1.0 (un `Date` por Lucid, sin `timezone`).
  const legacyInstants: string[] = JSON.parse(process.env.AUTHZ_UPGRADE_LEGACY_EXPIRY ?? '[]')
  const legacyHolders = legacyInstants.map((iso, i) => ({ iso, holder: { type: 'users', uuid: `0192a000-0000-7000-8000-0000000100${String(i).padStart(2, '0')}` } }))
  const legacyV1: Array<{ iso: string; before: boolean; at: boolean }> = []
  for (const { iso, holder } of legacyHolders) {
    await app.db.table('authz_assignments').insert({
      uuid: `0192a000-0000-7000-8000-0000000200${holder.uuid.slice(-2)}`,
      holder_type: holder.type,
      holder_uuid: holder.uuid,
      role_uuid: legacyUuid,
      scope_type: 'app',
      scope_uuid: '00000000-0000-0000-0000-000000000000',
      expires_at: new Date(iso),
      created_at: new Date(),
    })
    // La regla de 1.x (`whereActive`): `expires_at > new Date()`, con el mismo cliente.
    const active = async (at: Date) =>
      Boolean(await app.db.from('authz_assignments').where('holder_uuid', holder.uuid).where('expires_at', '>', at).first())
    const t = Date.parse(iso)
    legacyV1.push({ iso, before: await active(new Date(t - 1000)), at: await active(new Date(t)) })
  }
  // Cierre 2: pasadas, cada una por su sesión (ver la cabecera).
  const knex: any = (app.db.connection() as any).getWriteClient()
  const held: any[] = []
  const session = async () => {
    const conn: any = await knex.client.acquireConnection()
    held.push(conn)
    return (sql: string) => knex.raw(sql).connection(conn)
  }
  const prelude: string[] = JSON.parse(process.env.AUTHZ_UPGRADE_PRELUDE ?? '[]')
  const runPass = async (sqls: string[]): Promise<{ error: string | null; at: number | null }> => {
    const q = await session()
    for (const sql of prelude) await q(sql)
    for (const [i, sql] of sqls.entries()) {
      try {
        await q(sql)
      } catch (error: any) {
        return { error: `${error?.code ?? ''} ${String(error?.sqlMessage ?? error?.message)}`.trim(), at: i }
      }
    }
    return { error: null, at: null }
  }
  const passSpec: Array<{ from: number; to: number }> = JSON.parse(process.env.AUTHZ_UPGRADE_PASSES ?? 'null') ?? [{ from: 0, to: statements.length }]
  const passes = []
  for (const { from, to } of passSpec) {
    const result = await runPass(statements.slice(from, to))
    passes.push({ from, to, error: result.error, at: result.at === null ? null : from + result.at })
    if (result.error && process.env.AUTHZ_UPGRADE_STOP_ON_ERROR === '1') break
  }
  // Cierre 3: el comando, por el kernel, sobre una conexión cuyas sesiones nacen en otra zona y sin sql_mode estricto.
  const commandRuns: Array<{ error: string | null; exitCode: number; first: string }> = []
  const runCommand = async (argv: string[]) => {
    const { aceFor } = await import('./ace.js')
    const { default: AuthzUpgrade1x } = await import('../../commands/authz_upgrade_1x.js')
    const lucid: any = (await import('@adonisjs/lucid/services/db')).default
    if (!lucid.manager.has('upgrade')) {
      lucid.manager.add('upgrade', {
        ...reuse.connection,
        pool: {
          min: 0,
          max: 2,
          afterCreate: (conn: any, done: any) => conn.query("SET SESSION sql_mode = '', time_zone = '+05:00'", (error: any) => done(error, conn)),
        },
      })
    }
    const ace = await aceFor(AuthzUpgrade1x)
    const run = await ace.exec([...argv, '--connection=upgrade'])
    const logs = run.logs.map((l) => l.replace(/^\[ [a-z]+\([a-z]+\) \] /, ''))
    const exitCode = run.exitCode ?? (run.error ? 1 : 0)
    return { error: exitCode === 0 ? null : logs.join(' | '), exitCode, first: logs[0] ?? '' }
  }
  for (const argv of commandRunsSpec) commandRuns.push(await runCommand(argv))
  const recipeDoneAt = new Date()
  // Las sesiones se retuvieron para que cada pasada fuera OTRA; se devuelven antes de que 2.x use el pool (máx. 5).
  // En MySQL, antes de devolverlas, se deshace lo que el preludio o la receta dejaron en la sesión (zona, `sql_mode`):
  // una conexión del pool con `time_zone = '+05:00'` cambiaría lo que el resto del hijo lee de un TIMESTAMP.
  const releaseHeld = async () => {
    for (const conn of held.splice(0)) {
      if (app.engine === 'mysql') {
        await knex.raw('SET time_zone = @@global.time_zone').connection(conn)
        await knex.raw('SET SESSION sql_mode = @@global.sql_mode').connection(conn)
      }
      await knex.client.releaseConnection(conn)
    }
  }
  await releaseHeld()
  const isMysql = app.engine === 'mysql'
  const stored = async () =>
    isMysql
      ? (
          await app.db
            .from('authz_assignments')
            .whereIn('holder_uuid', legacyHolders.map((h) => h.holder.uuid))
            .orderBy('holder_uuid')
            .select(app.db.raw("DATE_FORMAT(expires_at, '%Y-%m-%d %H:%i:%s.%f') as e"))
        ).map((r: any) => r.e)
      : null
  const marker = async () => {
    if (!isMysql) return null
    const rows: any = await app.db.rawQuery(
      "select count(*) as n from information_schema.tables where table_schema = database() and table_name = 'authz_upgrade_1x'"
    )
    if (Number(rows[0][0].n) === 0) return null
    return (await app.db.from('authz_upgrade_1x').select('step', 'zone', app.db.raw('done_at is not null as done'))).map((r: any) => ({
      step: r.step,
      zone: r.zone,
      done: Boolean(Number(r.done)),
    }))
  }
  const expiresType = async () => {
    if (!isMysql) return null
    const rows: any = await app.db.rawQuery(
      "select column_type as t from information_schema.columns where table_schema = database() and table_name = 'authz_assignments' and column_name = 'expires_at'"
    )
    return rows[0][0].t
  }
  if (process.env.AUTHZ_UPGRADE_STOP === '1') {
    console.log(JSON.stringify({ passes, commandRuns, stored: await stored(), expiresType: await expiresType(), marker: await marker() }))
  } else {
    const legacyRow: any = (await app.db.from('authz_roles').where('uuid', legacyUuid).select('owner_scope_key'))[0]

    const { DatabaseAuthorizationDriver } = await import('../../src/drivers/database_driver.js')
    const { syncAuthzCatalog } = await import('../../src/catalog/catalog.js')
    const { APP_SCOPE } = await import('../../src/types.js')
    const { v7: uuidv7 } = await import('uuid')
    await syncAuthzCatalog({
      permissions: [{ slug: 'docs:read' }],
      roles: [
        { slug: 'editor', scopeType: 'app', permissions: ['docs:read'] },
        { slug: 'legacy', scopeType: 'app', permissions: ['docs:read'] },
      ],
    })
    const legacyAfterSync: any[] = await app.db.from('authz_roles').where('slug', 'legacy').select('uuid', 'owner_scope_key')
    const T0 = new Date('2030-01-01T00:00:00.000Z')
    const soon = new Date(T0.getTime() + 600)
    const clocked = new DatabaseAuthorizationDriver({ now: () => T0 })
    const alice = { type: 'users', uuid: 'user-42' } // no es un UUID: en 1.x (uuid) era un 503 en PG
    const bob = { type: 'users', uuid: 'x'.repeat(36) }
    await clocked.grant(alice, 'editor', APP_SCOPE, { expiresAt: soon })
    await clocked.grant(bob, 'editor', APP_SCOPE, { expiresAt: new Date('2040-01-01T00:00:00.000Z') })
    const reread = await clocked.grant(alice, 'editor', APP_SCOPE)
    // RR-5: la corrección para quien ya subió con el bloque anterior, DESPUÉS de que 2.x haya escrito sus filas.
    const fixSql: string[] = JSON.parse(process.env.AUTHZ_UPGRADE_FIX_SQL ?? '[]')
    const fixRuns = []
    const fixCommand: string[] | null = JSON.parse(process.env.AUTHZ_UPGRADE_FIX_COMMAND ?? 'null')
    for (let run = 0; fixCommand && run < Number(process.env.AUTHZ_UPGRADE_FIX_RUNS ?? 1); run++) {
      fixRuns.push(await runCommand(fixCommand.map((arg) => arg.replace('{upgradedAt}', recipeDoneAt.toISOString()))))
    }
    for (let run = 0; !fixCommand && run < Number(process.env.AUTHZ_UPGRADE_FIX_RUNS ?? (fixSql.length ? 1 : 0)); run++) {
      const upgradedAt = recipeDoneAt.toISOString().slice(0, 23).replace('T', ' ')
      fixRuns.push(await runPass(fixSql.map((sql) => (sql.startsWith('SET @authz_upgraded_at = ') ? `SET @authz_upgraded_at = '${upgradedAt}'` : sql))))
    }
    await releaseHeld()
    const at = (ms: number) => new DatabaseAuthorizationDriver({ now: () => new Date(T0.getTime() + ms) })
    // Comparación byte a byte: una fila con el id en minúsculas no casa con el mismo id en MAYÚSCULAS.
    const count = async (uuid: string) => {
      const rows: any = await app.db.from('authz_assignments').where('holder_uuid', uuid).count('* as n')
      return Number(rows[0].n ?? Object.values(rows[0])[0])
    }
    const { readAuthzCatalogVersion } = await import('../../src/catalog/catalog_cache.js')
    // R3-01: la caducidad de 1.x leída por 2.x tras la receta, a 1 ms del instante y en él.
    const legacy = []
    for (const [i, { iso, holder }] of legacyHolders.entries()) {
      const t = Date.parse(iso)
      const v2 = (ms: number) => new DatabaseAuthorizationDriver({ now: () => new Date(t + ms) }).authorize(holder, 'docs:read', APP_SCOPE)
      legacy.push({ iso, v1Before: legacyV1[i].before, v1At: legacyV1[i].at, v2Before: await v2(-1), v2At: await v2(0) })
    }
    console.log(
      JSON.stringify({
        nonUuidGranted: await at(0).authorize(alice, 'docs:read', APP_SCOPE),
        msExact: reread.previousExpiresAt?.toISOString() ?? null,
        beforeSoon: await at(599).authorize(alice, 'docs:read', APP_SCOPE),
        atSoon: await at(600).authorize(alice, 'docs:read', APP_SCOPE),
        beyond2038: await at(0).authorize(bob, 'docs:read', APP_SCOPE),
        lowerRows: await count('user-42'),
        upperRows: await count('USER-42'),
        version: await readAuthzCatalogVersion(),
        legacyOwner: legacyRow?.owner_scope_key ?? null,
        legacyAfterSync: legacyAfterSync.map((r) => ({ uuid: r.uuid, owner: r.owner_scope_key })),
        legacy,
        passes,
        commandRuns,
        fixRuns,
        stored: await stored(),
        marker: await marker(),
        schema: await describeAuthzSchema(app.db),
      })
    )
  }
} finally {
  await app.teardown()
}
