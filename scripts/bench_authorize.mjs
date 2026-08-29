/**
 * Benchmark de `authorize` (Fase 2, lote 2A): latencia real del driver
 * `openfga` contra un servidor vivo, con el catálogo en SQL (SQLite en
 * memoria, como la suite) y el árbol del consumidor vía `resolveChain`.
 *
 *   OPENFGA_TEST_URL=http://localhost:8101 node --import @poppinss/ts-exec scripts/bench_authorize.mjs
 *
 * Topología (la del panel 2, §4): cadena de 3 (unit → organization → app),
 * 5 roles por nivel, 20 permisos, 4 permisos por rol. Alice tiene los 15
 * roles. Permiso TRUE = solo lo concede un rol de la raíz (hay que subir
 * toda la cadena); permiso FALSE = no lo concede nadie (recorrido exhaustivo
 * sin corto-circuito). N medidas tras un warmup; round-trip HTTP incluido.
 *
 * Además de los tiempos imprime la FACTURA de cada `authorize`: llamadas al
 * cliente FGA y consultas SQL. Es lo que el lote 2A cambia (memo del
 * catálogo + un solo batchCheck) sin cambiar ninguna respuesta, y lo que 2D
 * (F1) añade: una revalidación del memo por pregunta.
 *
 * Variables: N (200), WARMUP (30), OPENFGA_TEST_URL. Sin servidor solo se
 * mide el driver `database`. El store se borra al terminar.
 */

import { execSync } from 'node:child_process'

const N = Number(process.env.N || 200)
const WARMUP = Number(process.env.WARMUP || 30)
const apiUrl = process.env.OPENFGA_TEST_URL
const ROLES = 5
const NPERM = 20
const PER_ROLE = 4
const LEVELS = ['app', 'organization', 'unit']
const PERMS = Array.from({ length: NPERM }, (_, i) => `p${String(i).padStart(2, '0')}`)
const TARGET = 'p00' // solo lo concede l0-r0 (raíz)
const MISS = 'p16' // nadie lo concede

const permsOfRole = (level, i) =>
  level === 0
    ? Array.from({ length: PER_ROLE }, (_, k) => PERMS[i + k])
    : Array.from({ length: PER_ROLE }, (_, k) => PERMS[8 + ((level - 1) * ROLES + i + k) % 8])

function stats(ms) {
  const s = [...ms].sort((a, b) => a - b)
  const q = (p) => s[Math.min(s.length - 1, Math.floor(s.length * p))]
  const mean = s.reduce((a, b) => a + b, 0) / s.length
  return { p50: q(0.5), p95: q(0.95), max: s[s.length - 1], mean }
}

const fmt = (n) => `${n.toFixed(2)} ms`.padStart(10)

async function bench(label, fn) {
  for (let i = 0; i < WARMUP; i++) await fn()
  const ms = []
  for (let i = 0; i < N; i++) {
    const t = performance.now()
    await fn()
    ms.push(performance.now() - t)
  }
  const st = stats(ms)
  console.log(`  ${label.padEnd(44)} p50=${fmt(st.p50)}  p95=${fmt(st.p95)}  media=${fmt(st.mean)}`)
  return st
}

function gitLabel() {
  try {
    const head = execSync('git rev-parse --short HEAD', { encoding: 'utf8' }).trim()
    const dirty = execSync('git status --porcelain -- src', { encoding: 'utf8' }).trim() ? ' (src modificado)' : ''
    return `${head}${dirty}`
  } catch {
    return 'sin git'
  }
}

const { bootApp } = await import('../tests/helpers/app.js')
const { createAuthzSchema } = await import('../tests/helpers/schema.js')
// `bootApp` devuelve el `TestApp` del harness (2.5 · J2), no el `db` (2.5-B · K8).
const app = await bootApp()
await createAuthzSchema(app.db)

const { v7: uuidv7 } = await import('uuid')
const { syncAuthzCatalog } = await import('../src/catalog.js')
const { memoryScopeTree, resolveChainFrom } = await import('../src/testing/main.js')
const { APP_SCOPE } = await import('../src/types.js')
const { DatabaseAuthorizationDriver } = await import('../src/drivers/database_driver.js')
const { countCalls, countQueries } = await import('../tests/helpers/spies.js')

const catalog = {
  permissions: PERMS.map((slug) => ({ slug })),
  roles: LEVELS.flatMap((scopeType, level) =>
    Array.from({ length: ROLES }, (_, i) => ({
      slug: `l${level}-r${i}`,
      scopeType,
      permissions: permsOfRole(level, i),
    }))
  ),
}
await syncAuthzCatalog(catalog)

const tree = memoryScopeTree()
const org = { type: 'organization', uuid: uuidv7() }
const unit = { type: 'unit', uuid: uuidv7() }
await tree.attach(org, APP_SCOPE)
await tree.attach(unit, org)
const scopes = [APP_SCOPE, org, unit]
const resolveChain = resolveChainFrom(tree)
const alice = { type: 'users', uuid: uuidv7() }

async function seed(driver) {
  for (const [level, scope] of scopes.entries()) {
    for (let i = 0; i < ROLES; i++) await driver.grant(alice, `l${level}-r${i}`, scope)
  }
  if ((await driver.authorize(alice, TARGET, unit)) !== true) throw new Error('sanity TRUE falló')
  if ((await driver.authorize(alice, MISS, unit)) !== false) throw new Error('sanity FALSE falló')
}

/** Factura de un `authorize`: consultas SQL y llamadas al cliente FGA. */
async function bill(driver, permission) {
  const client = driver.client
  const counter = client ? countCalls(client, ['batchCheck', 'check', 'read']) : null
  try {
    const { queries } = await countQueries(() => driver.authorize(alice, permission, unit))
    const fga = counter ? Object.values(counter.counts).reduce((a, b) => a + b, 0) : 0
    // Lecturas del catálogo (`from authz_*` de catálogo); el join de hechos con los vínculos no cuenta.
    const catalogSql = queries.filter((q) => /from\s+[`"]?authz_(permissions|roles|role_permissions)[`"]?/i.test(q.sql)).length
    // Revalidación del memo contra `authz_catalog_version` (2D · F1): un SELECT por clave primaria por pregunta.
    const versionSql = queries.filter((q) => /from\s+[`"]?authz_catalog_version[`"]?/i.test(q.sql)).length
    return `${queries.length} SQL (${catalogSql} de catálogo, ${versionSql} de versión) + ${fga} FGA`
  } finally {
    counter?.restore()
  }
}

console.log(`# bench_authorize · ${gitLabel()} · node ${process.version}`)
console.log(`# cadena de ${LEVELS.length} (${LEVELS.join(' → ')}), ${ROLES} roles/nivel, ${NPERM} permisos, ${PER_ROLE}/rol; N=${N}, warmup=${WARMUP}`)
console.log(`# TRUE = ${TARGET} (solo la raíz concede) · FALSE = ${MISS} (nadie concede)\n`)

const results = {}
let storeId
try {
  const database = new DatabaseAuthorizationDriver({ resolveChain })
  await seed(database)
  console.log(`database (${app.engine}) · factura: TRUE ${await bill(database, TARGET)} · FALSE ${await bill(database, MISS)}`)
  results.database = {
    TRUE: await bench('database · authorize · TRUE', () => database.authorize(alice, TARGET, unit)),
    FALSE: await bench('database · authorize · FALSE', () => database.authorize(alice, MISS, unit)),
  }

  if (apiUrl) {
    const { OpenFgaAuthorizationDriver, provisionOpenFgaStore } = await import('../src/openfga.js')
    const holderTypes = { users: 'user' }
    const provisioned = await provisionOpenFgaStore(apiUrl, `bench-${uuidv7()}`, holderTypes)
    storeId = provisioned.storeId
    const openfga = new OpenFgaAuthorizationDriver({
      apiUrl,
      storeId,
      modelId: provisioned.modelId,
      holderTypes,
      resolveChain,
    })
    await seed(openfga)
    console.log(`\nopenfga (${apiUrl}) · factura: TRUE ${await bill(openfga, TARGET)} · FALSE ${await bill(openfga, MISS)}`)
    results.openfga = {
      TRUE: await bench('openfga · authorize · TRUE', () => openfga.authorize(alice, TARGET, unit)),
      FALSE: await bench('openfga · authorize · FALSE', () => openfga.authorize(alice, MISS, unit)),
    }
  } else {
    console.log('\n(sin OPENFGA_TEST_URL: solo database)')
  }
} finally {
  if (storeId) {
    const { OpenFgaClient } = await import('@openfga/sdk')
    await new OpenFgaClient({ apiUrl, storeId }).deleteStore()
    console.log(`\nstore borrado: ${storeId}`)
  }
  await app.teardown()
}
