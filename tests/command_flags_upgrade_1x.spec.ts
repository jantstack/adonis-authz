/**
 * **`authz:upgrade-1x`** (rotación 3 · cierre 3, ESTRUCTURAL): la subida 1.x → 2.x de MySQL como CÓDIGO que inspecciona
 * el estado (brief `rotacion-3-cierre3-brief.md`). Tres capas:
 *
 *  1. `upgrade1xPlan` PURA: la tabla de verdad entera, en todos los motores.
 *  2. Fuera de MySQL, por el KERNEL con las banderas de verdad: exit 0, cero sentencias, y la letra nombra cada bandera
 *     recibida (es lo que mata el mutante «bandera inerte» de cada una en el job `flag-mutants`, que corre en `:memory:`).
 *  3. En MySQL, por el KERNEL con las banderas de verdad, sobre una base de trabajo con el esquema de 1.1.0 y caducidades
 *     escritas como las escribía 1.x: la PARED del proceso 1.x en la columna `TIMESTAMP`, convertida con la zona de la
 *     sesión (medido en `mysql84`, tabla de evidencia del informe del cierre 1). La conexión que usa el comando
 *     (`--connection`) abre cada sesión con `sql_mode = ''` y `time_zone = '+05:00'`: el comando tiene que deshacer las
 *     dos cosas (RR-3, RR-7). Cada estado del brief con su salida y su exit; Madrid (verano/invierno) y Caracas exactos;
 *     corte tras CADA paso + re-ejecución; receta vieja ⇒ negativa y `--fix-previous-upgrade` exacto sin tocar filas de
 *     2.x; restauración de 1.x tras «hecho» ⇒ negativa; fecha cero ⇒ negativa y `--zero-dates=expire` ⇒ caducada; zona
 *     desconocida ⇒ cero cambios; `--dry-run` = cero escrituras.
 *
 * El e2e con el CLIENTE de 1.x de verdad (procesos hijos en `Europe/Madrid`/`America/Caracas`, `mysql2` con `'local'`) y
 * la decisión de 2.x a T−1 ms / T vive en `upgrade_recipe.spec.ts`, que corre este mismo comando en el hijo.
 */

import { test } from '@japa/runner'
import { readFile } from 'node:fs/promises'
import { v7 as uuidv7 } from 'uuid'
import { DateTime } from 'luxon'
import db from '@adonisjs/lucid/services/db'
import { aceFor } from './helpers/ace.js'
import { openScratchDatabase, testEngine } from './helpers/app.js'
import { AUTHZ_TABLES, describeAuthzSchema, runMigrationSource } from './helpers/schema.js'
import AuthzUpgrade1x, {
  parseUpgradedAt,
  runUpgrade1xStep,
  upgrade1xPlan,
  v7Prefix,
  type Upgrade1xFlags,
  type Upgrade1xState,
} from '../commands/authz_upgrade_1x.js'

const ENGINE = testEngine()
const IS_MYSQL = ENGINE === 'mysql'
const RECIPE_TABLES = AUTHZ_TABLES.filter((t) => t !== 'authz_relations' && t !== 'authz_relations_config')
const ALL_PRE = ['collation-roles', 'collation-permissions', 'assignments', 'collation-denies'] as const
const ALL_POST = ['catalog-version', 'roles-owner', 'permissions-assignable'] as const
const NOW = Date.parse('2026-10-26T12:00:00.000Z')

/* ── 1 · La función PURA ───────────────────────────────────────────────────── */

/** Un MySQL 1.x sin tocar: `timestamp`, sin marcador, todo el DDL pendiente, 3 caducidades legibles. */
function v1(over: Partial<Upgrade1xState> = {}): Upgrade1xState {
  return {
    connection: 'primary',
    dialect: 'mysql',
    missingTables: [],
    expiresType: 'timestamp',
    marker: null,
    pendingDdl: [...ALL_PRE, ...ALL_POST],
    schemaOdd: [],
    catalogVersionTable: false,
    expiring: 3,
    unreadable: 0,
    zones: { 'Europe/Madrid': true, '-04:00': true, 'Europe/Nowhere': false },
    oldestV7Ms: Date.parse('2026-08-01T00:00:00.000Z'),
    nonV7: 0,
    fixBefore: null,
    fixCandidates: null,
    nowMs: NOW,
    nonTransactional: [],
    ...over,
  }
}
/** La misma base subida con el bloque viejo (2.4.0-alpha.1 … rc.1): `datetime(3)`, sin marcador, sin DDL pendiente. */
const oldRecipe = (over: Partial<Upgrade1xState> = {}) => v1({ expiresType: 'datetime(3)', pendingDdl: [], catalogVersionTable: true, ...over })
const armed = (zone = 'Europe/Madrid') => [{ step: 'expires_at', state: 'armed', mode: 'upgrade', zone, upgradedAt: null }]
const doneMarker = (zone = 'Europe/Madrid', mode = 'upgrade') => [{ step: 'expires_at', state: 'done', mode, zone, upgradedAt: null }]
/** C1: la confirmación de que todos los procesos 1.x están parados. */
const OK = { confirmLegacyStopped: true }

interface Row {
  name: string
  state: Upgrade1xState
  flags: Upgrade1xFlags
  key: string
  action: 'noop' | 'refuse' | 'run'
  exit: 0 | 1
  write?: boolean
  steps?: string[]
  text?: RegExp
  /** Lo que la salida NO puede decir (cierre 5: `receta-vieja` con rastro de 1.x no ofrece born). */
  notText?: RegExp
}
const FULL_STEPS = ['marker-table', 'marker-arm', ...ALL_PRE, 'convert', ...ALL_POST]
const FIX = { fixPreviousUpgrade: true, zone: 'Europe/Madrid', upgradedAt: '2026-09-01T10:00:00Z' }

const TABLE: Row[] = [
  // Fuera de MySQL
  { name: 'pg', state: v1({ dialect: 'postgres' }), flags: { zone: 'x', force: true }, key: 'no-mysql', action: 'noop', exit: 0, text: /Banderas recibidas y sin efecto fuera de MySQL: --zone=x, --force\./ },
  { name: 'sqlite', state: v1({ dialect: 'better-sqlite3' }), flags: {}, key: 'no-mysql', action: 'noop', exit: 0 },
  // Sin tablas
  { name: 'sin authz_assignments', state: v1({ missingTables: ['authz_assignments'] }), flags: { zone: '+00:00' }, key: 'sin-tablas', action: 'refuse', exit: 1 },
  // 1.x sin subir
  { name: '1.x sin --zone', state: v1(), flags: { force: true }, key: '1x-sin-subir', action: 'refuse', exit: 1, text: /--zone es obligatoria/ },
  { name: '1.x zona desconocida', state: v1(), flags: { zone: 'Europe/Nowhere', force: true }, key: '1x-sin-subir', action: 'refuse', exit: 1, text: /no convierte la zona 'Europe\/Nowhere'/ },
  { name: '1.x simulación', state: v1(), flags: { zone: 'Europe/Madrid' }, key: '1x-sin-subir', action: 'run', exit: 0, write: false, steps: FULL_STEPS, text: /Simulación/ },
  { name: '1.x --force', state: v1(), flags: { zone: 'Europe/Madrid', force: true, ...OK }, key: '1x-sin-subir', action: 'run', exit: 0, write: true, steps: FULL_STEPS, text: /Precondición \(C1\).*Confirmada con --confirm-legacy-stopped/ },
  { name: '1.x --dry-run --force', state: v1(), flags: { zone: 'Europe/Madrid', force: true, dryRun: true }, key: '1x-sin-subir', action: 'refuse', exit: 1, text: /--force y --dry-run a la vez/ },
  { name: '1.x fecha cero', state: v1({ unreadable: 2 }), flags: { zone: 'Europe/Madrid', force: true }, key: '1x-sin-subir', action: 'refuse', exit: 1, text: /2 fila\(s\).*PERMANENTE/ },
  { name: '1.x fecha cero + expire', state: v1({ unreadable: 2 }), flags: { zone: 'Europe/Madrid', force: true, zeroDates: 'expire', ...OK }, key: '1x-sin-subir', action: 'run', exit: 0, write: true, steps: ['zero-dates', ...FULL_STEPS] },
  { name: '1.x --zero-dates=null', state: v1({ unreadable: 2 }), flags: { zone: 'Europe/Madrid', zeroDates: 'null' }, key: '1x-sin-subir', action: 'refuse', exit: 1, text: /el único valor es 'expire'/ },
  { name: '1.x --fix-previous-upgrade', state: v1(), flags: FIX, key: '1x-sin-subir', action: 'refuse', exit: 1, text: /solo vale para una base subida con el bloque viejo/ },
  { name: '1.x --upgraded-at sin fix', state: v1(), flags: { zone: 'Europe/Madrid', upgradedAt: '2026-09-01T10:00:00Z' }, key: '1x-sin-subir', action: 'refuse', exit: 1, text: /--upgraded-at solo tiene sentido/ },
  { name: '1.x con authz_catalog_version', state: v1({ catalogVersionTable: true }), flags: { zone: 'Europe/Madrid' }, key: 'incoherente', action: 'refuse', exit: 1, text: /un proceso 2.x puede haber escrito/ },
  { name: '1.x offset fijo avisa', state: v1(), flags: { zone: '-04:00' }, key: '1x-sin-subir', action: 'run', exit: 0, write: false, steps: FULL_STEPS, text: /offset FIJO/ },
  // A medias
  { name: 'timestamp + armed', state: v1({ marker: armed(), pendingDdl: ['assignments', 'collation-denies', ...ALL_POST] }), flags: { force: true, ...OK }, key: 'a-medias', action: 'run', exit: 0, write: true, steps: ['assignments', 'collation-denies', 'convert', ...ALL_POST] },
  { name: 'timestamp + armed, otra --zone', state: v1({ marker: armed() }), flags: { zone: '-04:00', force: true }, key: 'a-medias', action: 'refuse', exit: 1, text: /se reanuda SIEMPRE con la zona del marcador/ },
  { name: 'timestamp + armed, misma --zone', state: v1({ marker: armed() }), flags: { zone: 'Europe/Madrid' }, key: 'a-medias', action: 'run', exit: 0, write: false, steps: [...ALL_PRE, 'convert', ...ALL_POST] },
  { name: 'datetime + armed', state: oldRecipe({ marker: armed(), catalogVersionTable: false, pendingDdl: ['collation-denies', ...ALL_POST] }), flags: { force: true, ...OK }, key: 'a-medias', action: 'run', exit: 0, write: true, steps: ['collation-denies', 'convert', ...ALL_POST] },
  { name: 'datetime + armed, zona ya no convierte', state: oldRecipe({ marker: armed('Europe/Nowhere'), catalogVersionTable: false, pendingDdl: ALL_POST.slice() }), flags: { force: true }, key: 'a-medias', action: 'refuse', exit: 1, text: /no convierte la zona/ },
  { name: 'datetime + armed + authz_catalog_version', state: oldRecipe({ marker: armed() }), flags: { force: true }, key: 'incoherente', action: 'refuse', exit: 1 },
  { name: 'datetime + done + DDL pendiente', state: oldRecipe({ marker: doneMarker(), pendingDdl: ['roles-owner', 'permissions-assignable'] }), flags: { force: true }, key: 'a-medias', action: 'run', exit: 0, write: true, steps: ['roles-owner', 'permissions-assignable'] },
  // Receta vieja
  { name: 'receta vieja, sin bandera', state: oldRecipe(), flags: { zone: 'Europe/Madrid', force: true }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /no convierte nada por defecto.*--fix-previous-upgrade/ },
  { name: 'receta vieja, fix sin zona', state: oldRecipe(), flags: { ...FIX, zone: undefined }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /exige --zone/ },
  { name: 'receta vieja, fix sin instante', state: oldRecipe(), flags: { ...FIX, upgradedAt: undefined }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /exige --upgraded-at/ },
  { name: 'receta vieja, instante sin zona horaria', state: oldRecipe(), flags: { ...FIX, upgradedAt: '2026-09-01T10:00:00' }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /no es un instante ISO con zona explícita/ },
  { name: 'receta vieja, instante futuro', state: oldRecipe(), flags: { ...FIX, upgradedAt: '2027-01-01T00:00:00Z' }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /FUTURO/ },
  { name: 'receta vieja, instante anterior a toda fila (B1)', state: oldRecipe(), flags: { ...FIX, upgradedAt: '2026-01-01T00:00:00Z' }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /anterior \(o igual\) a la fila más antigua.*\(B1\)/ },
  { name: 'receta vieja, sin uuid v7', state: oldRecipe({ oldestV7Ms: null }), flags: FIX, key: 'receta-vieja', action: 'refuse', exit: 1, text: /ningún.*uuid v7|ninguna fila.*uuid v7/ },
  { name: 'receta vieja, zona desconocida', state: oldRecipe(), flags: { ...FIX, zone: 'Europe/Nowhere' }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /no convierte la zona/ },
  { name: 'receta vieja, fix fecha cero', state: oldRecipe({ unreadable: 1 }), flags: FIX, key: 'receta-vieja', action: 'refuse', exit: 1, text: /PERMANENTE/ },
  { name: 'receta vieja, fix', state: oldRecipe({ fixBefore: 3, fixCandidates: 3 }), flags: { ...FIX, force: true, ...OK }, key: 'receta-vieja', action: 'run', exit: 0, write: true, steps: ['marker-table', 'fix-previous'], text: /3 fila\(s\) con caducidad insertadas antes de 2026-09-01T10:00:00.000Z/ },
  { name: 'receta vieja, fix oeste', state: oldRecipe({ fixBefore: 3, fixCandidates: 0 }), flags: { ...FIX, zone: '-04:00' }, key: 'receta-vieja', action: 'run', exit: 0, write: false, steps: ['marker-table', 'fix-previous'], text: /al oeste de UTC no mueve nada/ },
  { name: 'receta vieja con DDL pendiente, fix', state: oldRecipe({ pendingDdl: ['permissions-assignable'] }), flags: FIX, key: 'receta-vieja', action: 'run', exit: 0, write: false, steps: ['marker-table', 'permissions-assignable', 'fix-previous'] },
  // Hecho
  { name: 'datetime sin marcador ni caducidades', state: oldRecipe({ expiring: 0 }), flags: {}, key: 'hecho', action: 'noop', exit: 0, text: /ninguna fila tiene caducidad/ },
  { name: 'hecho', state: oldRecipe({ marker: doneMarker() }), flags: { force: true }, key: 'hecho', action: 'noop', exit: 0, text: /Nada que hacer/ },
  { name: 'hecho, misma zona (re-ejecución idéntica)', state: oldRecipe({ marker: doneMarker() }), flags: { zone: 'Europe/Madrid', force: true }, key: 'hecho', action: 'noop', exit: 0 },
  { name: 'hecho de una corrección, mismas banderas', state: oldRecipe({ marker: doneMarker('Europe/Madrid', 'fix-previous') }), flags: { ...FIX, force: true }, key: 'hecho', action: 'noop', exit: 0 },
  { name: 'hecho, otra zona', state: oldRecipe({ marker: doneMarker() }), flags: { zone: '-04:00' }, key: 'hecho', action: 'refuse', exit: 1, text: /no convierte dos veces/ },
  // Incoherente
  { name: 'timestamp + done (B2: volcado de 1.x restaurado)', state: v1({ marker: doneMarker() }), flags: { zone: 'Europe/Madrid', force: true }, key: 'incoherente', action: 'refuse', exit: 1, text: /\(B2\)/ },
  { name: 'marcador con otra forma', state: v1({ marker: 'malformed' }), flags: { zone: 'Europe/Madrid' }, key: 'incoherente', action: 'refuse', exit: 1 },
  { name: 'marcador con dos filas', state: v1({ marker: [...armed(), { ...armed()[0], step: 'otro' }] }), flags: { zone: 'Europe/Madrid' }, key: 'incoherente', action: 'refuse', exit: 1 },
  { name: 'marcador con estado desconocido', state: v1({ marker: [{ ...armed()[0], state: 'half' }] }), flags: {}, key: 'incoherente', action: 'refuse', exit: 1 },
  { name: 'corrección a medias (no existe)', state: oldRecipe({ marker: [{ ...armed()[0], mode: 'fix-previous' }], catalogVersionTable: false }), flags: {}, key: 'incoherente', action: 'refuse', exit: 1 },
  { name: 'expires_at de otro tipo', state: v1({ expiresType: 'datetime' }), flags: { zone: 'Europe/Madrid' }, key: 'incoherente', action: 'refuse', exit: 1, text: /expires_at es datetime/ },
  { name: 'índices de roles a medias', state: oldRecipe({ schemaOdd: ['authz_roles tiene owner_scope_key pero sus índices no son los de 2.x'] }), flags: {}, key: 'incoherente', action: 'refuse', exit: 1 },
  { name: 'marcador born a medias', state: oldRecipe({ marker: [{ ...armed()[0], mode: 'born' }], catalogVersionTable: false }), flags: {}, key: 'incoherente', action: 'refuse', exit: 1, text: /nacida en 2.x está a medias/ },

  // C1 · cierre 4: --force que CONVIERTE sin --confirm-legacy-stopped ⇒ negativa (y la simulación lo dice)
  { name: 'C1 · 1.x --force sin confirmar', state: v1(), flags: { zone: 'Europe/Madrid', force: true }, key: '1x-sin-subir', action: 'refuse', exit: 1, text: /falta --confirm-legacy-stopped.*rolling deploy.*no lo puede detectar después/s },
  { name: 'C1 · 1.x fecha cero + expire sin confirmar', state: v1({ unreadable: 2 }), flags: { zone: 'Europe/Madrid', force: true, zeroDates: 'expire' }, key: '1x-sin-subir', action: 'refuse', exit: 1, text: /falta --confirm-legacy-stopped/ },
  { name: 'C1 · timestamp + armed sin confirmar', state: v1({ marker: armed() }), flags: { force: true }, key: 'a-medias', action: 'refuse', exit: 1, text: /falta --confirm-legacy-stopped/ },
  { name: 'C1 · datetime + armed sin confirmar', state: oldRecipe({ marker: armed(), catalogVersionTable: false, pendingDdl: ALL_POST.slice() }), flags: { force: true }, key: 'a-medias', action: 'refuse', exit: 1, text: /falta --confirm-legacy-stopped/ },
  { name: 'C1 · fix sin confirmar', state: oldRecipe({ fixBefore: 3, fixCandidates: 3 }), flags: { ...FIX, force: true }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /falta --confirm-legacy-stopped/ },
  { name: 'C1 · done + DDL pendiente no convierte: no la pide', state: oldRecipe({ marker: doneMarker(), pendingDdl: ['permissions-assignable'] }), flags: { force: true }, key: 'a-medias', action: 'run', exit: 0, write: true, steps: ['permissions-assignable'] },
  { name: 'C1 · la simulación la menciona', state: v1(), flags: { zone: 'Europe/Madrid' }, key: '1x-sin-subir', action: 'run', exit: 0, write: false, steps: FULL_STEPS, text: /Precondición \(C1\): para TODOS los procesos 1.x antes de --force.*--force exige --confirm-legacy-stopped/ },
  { name: 'C1 · la simulación de la corrección la menciona', state: oldRecipe({ fixBefore: 3, fixCandidates: 3 }), flags: FIX, key: 'receta-vieja', action: 'run', exit: 0, write: false, steps: ['marker-table', 'fix-previous'], text: /Precondición \(C1\)/ },

  // C2 · cierre 4: motor no transaccional ⇒ negativa ANTES de clasificar, con la receta
  { name: 'C2 · authz_assignments MyISAM', state: v1({ nonTransactional: ['authz_assignments (MyISAM)'] }), flags: { zone: 'Europe/Madrid', force: true, ...OK }, key: 'motor-no-transaccional', action: 'refuse', exit: 1, text: /ALTER TABLE authz_assignments ENGINE=InnoDB;/ },
  { name: 'C2 · marcador MyISAM (a medias)', state: v1({ marker: armed(), nonTransactional: ['authz_upgrade_1x (MyISAM)'] }), flags: { force: true, ...OK }, key: 'motor-no-transaccional', action: 'refuse', exit: 1, text: /ALTER TABLE authz_upgrade_1x ENGINE=InnoDB;/ },
  { name: 'C2 · también sobre una base hecha', state: oldRecipe({ marker: doneMarker(), nonTransactional: ['authz_assignments (MyISAM)'] }), flags: {}, key: 'motor-no-transaccional', action: 'refuse', exit: 1 },

  // P1 · cierre 4: --declare-born-in-2
  { name: 'P1 · receta-vieja, declarada nacida en 2.x', state: oldRecipe(), flags: { declareBornIn2: true, force: true }, key: 'receta-vieja', action: 'run', exit: 0, write: true, steps: ['marker-table', 'born'], text: /Declaras que esta base NACIÓ en 2.x.*NO puede demostrarlo/s },
  { name: 'P1 · simulación', state: oldRecipe(), flags: { declareBornIn2: true }, key: 'receta-vieja', action: 'run', exit: 0, write: false, steps: ['marker-table', 'born'] },
  // Cierre 5 · B1: esta fila fijaba lo contrario (born aceptado con DDL de 1.x pendiente, y el comando ejecutaba ese DDL).
  { name: 'P1 · no pide la confirmación de C1 (no convierte)', state: oldRecipe(), flags: { declareBornIn2: true, force: true }, key: 'receta-vieja', action: 'run', exit: 0, write: true, steps: ['marker-table', 'born'] },
  { name: 'B1 · born con DDL de 1.x pendiente (solo permissions-assignable) se niega', state: oldRecipe({ pendingDdl: ['permissions-assignable'] }), flags: { declareBornIn2: true, force: true }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /--declare-born-in-2: hay rastro de 1.x, born no aplica — DDL de 1.x pendiente \(permissions-assignable\)/ },
  { name: 'P1 · hecho sin marcador ni caducidades: se puede declarar', state: oldRecipe({ expiring: 0 }), flags: { declareBornIn2: true, force: true }, key: 'hecho', action: 'run', exit: 0, write: true, steps: ['marker-table', 'born'] },
  { name: 'P1 · timestamp = señal de 1.x', state: v1(), flags: { declareBornIn2: true, force: true }, key: '1x-sin-subir', action: 'refuse', exit: 1, text: /todavía el TIMESTAMP de 1.x/ },
  { name: 'P1 · marcador existente (subida hecha)', state: oldRecipe({ marker: doneMarker() }), flags: { declareBornIn2: true, force: true }, key: 'hecho', action: 'refuse', exit: 1, text: /ya hay un marcador/ },
  { name: 'P1 · marcador existente (a medias)', state: oldRecipe({ marker: armed(), catalogVersionTable: false }), flags: { declareBornIn2: true, force: true }, key: 'a-medias', action: 'refuse', exit: 1, text: /ya hay un marcador/ },
  { name: 'P1 · con --zone', state: oldRecipe(), flags: { declareBornIn2: true, zone: 'Europe/Madrid', force: true }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /va sin --zone y sin --fix-previous-upgrade/ },
  { name: 'P1 · con --fix-previous-upgrade', state: oldRecipe(), flags: { ...FIX, declareBornIn2: true, force: true, ...OK }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /salidas OPUESTAS/ },
  { name: 'P1 · hecho (born)', state: oldRecipe({ marker: doneMarker('+00:00', 'born') }), flags: { force: true }, key: 'hecho', action: 'noop', exit: 0, text: /DECLARADA nacida en 2.x/ },
  { name: 'P1 · hecho (born) con --zone', state: oldRecipe({ marker: doneMarker('+00:00', 'born') }), flags: { zone: 'Europe/Madrid' }, key: 'hecho', action: 'refuse', exit: 1, text: /DECLARADA nacida en 2.x/ },
  { name: 'P1 · receta-vieja ofrece las DOS salidas sin empujar a la corrección', state: oldRecipe(), flags: {}, key: 'receta-vieja', action: 'refuse', exit: 1, text: /DOS salidas.*--declare-born-in-2 --force.*--fix-previous-upgrade.*no la uses «para ponerlo en verde»/s },

  // Cierre 5 · B1/B1-bis: born se NIEGA donde el comando ve 1.x (DDL de 1.x pendiente, fechas cero), y receta-vieja deja de ofrecerlo
  { name: 'B1 · born con el DDL de una subida cortada antes de authz_catalog_version', state: oldRecipe({ pendingDdl: [...ALL_POST], catalogVersionTable: false }), flags: { declareBornIn2: true, force: true }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /hay rastro de 1.x, born no aplica — DDL de 1.x pendiente \(catalog-version, roles-owner, permissions-assignable\).*--fix-previous-upgrade/s },
  { name: 'B1 · born con catalog-version pendiente', state: oldRecipe({ pendingDdl: ['catalog-version'] }), flags: { declareBornIn2: true, force: true }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /hay rastro de 1.x, born no aplica/ },
  { name: 'B1 · born con roles-owner pendiente', state: oldRecipe({ pendingDdl: ['roles-owner'] }), flags: { declareBornIn2: true, force: true }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /hay rastro de 1.x, born no aplica/ },
  { name: 'B1 · born con un paso de collation pendiente', state: oldRecipe({ pendingDdl: ['collation-denies'] }), flags: { declareBornIn2: true, force: true }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /DDL de 1.x pendiente \(collation-denies\)/ },
  { name: 'B1 · born con DDL pendiente, sin --force: también negativa (no simula un camino cerrado)', state: oldRecipe({ pendingDdl: [...ALL_POST] }), flags: { declareBornIn2: true }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /hay rastro de 1.x, born no aplica/ },
  { name: 'B1-bis · born con caducidades ilegibles (fecha cero)', state: oldRecipe({ unreadable: 3 }), flags: { declareBornIn2: true, force: true }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /hay rastro de 1.x, born no aplica — 3 caducidad\(es\) ilegible\(s\)/ },
  { name: 'B1-bis · born con DDL pendiente Y fechas cero: nombra los dos rastros', state: oldRecipe({ pendingDdl: ['roles-owner'], unreadable: 1 }), flags: { declareBornIn2: true, force: true }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /DDL de 1.x pendiente \(roles-owner\); 1 caducidad\(es\) ilegible\(s\)/ },
  { name: 'B1 · receta-vieja con DDL pendiente NO ofrece born', state: oldRecipe({ pendingDdl: [...ALL_POST] }), flags: {}, key: 'receta-vieja', action: 'refuse', exit: 1, text: /Esta base vino de 1.x \(DDL de 1.x pendiente.*hay rastro de 1.x, born no aplica.*--fix-previous-upgrade --zone=/s, notText: /--declare-born-in-2 --force|DOS salidas/ },
  { name: 'B1-bis · receta-vieja con fechas cero NO ofrece born y pide --zero-dates', state: oldRecipe({ unreadable: 2 }), flags: {}, key: 'receta-vieja', action: 'refuse', exit: 1, text: /hay rastro de 1.x, born no aplica.*--zero-dates=expire/s, notText: /--declare-born-in-2 --force|DOS salidas/ },
  { name: 'B1 · la línea de estado nombra el rastro (y no dice que no puede distinguir)', state: oldRecipe({ pendingDdl: ['catalog-version'] }), flags: {}, key: 'receta-vieja', action: 'refuse', exit: 1, text: /^estado: receta-vieja · .*Hay rastro de 1.x: DDL de 1.x pendiente \(catalog-version\) — no nació en 2.x/, notText: /no puede distinguir/ },
  { name: 'B1 · sin rastro, la línea de estado dice qué rastros busca y que born es una declaración', state: oldRecipe(), flags: {}, key: 'receta-vieja', action: 'refuse', exit: 1, text: /^estado: receta-vieja · .*Sin rastro de 1.x que el comando detecte \(DDL de 1.x pendiente, caducidades ilegibles\).*solo el operador puede declarar/ },
  { name: 'B1 · con rastro, la corrección sigue abierta (y termina el DDL)', state: oldRecipe({ pendingDdl: [...ALL_POST], fixBefore: 3, fixCandidates: 3 }), flags: { ...FIX, force: true, ...OK }, key: 'receta-vieja', action: 'run', exit: 0, write: true, steps: ['marker-table', ...ALL_POST, 'fix-previous'] },

  // Cierre 5 · H4: con born, las banderas de la conversión se rechazan (como --zone), no se tragan
  { name: 'H4 · born + --zero-dates=expire', state: oldRecipe(), flags: { declareBornIn2: true, force: true, zeroDates: 'expire' }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /--declare-born-in-2 no convierte nada: --zero-dates=expire no tiene\(n\) efecto/ },
  { name: 'H4 · born + --confirm-legacy-stopped', state: oldRecipe(), flags: { declareBornIn2: true, force: true, confirmLegacyStopped: true }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /--confirm-legacy-stopped no tiene\(n\) efecto/ },
  { name: 'H4 · born + las dos, en simulación', state: oldRecipe({ unreadable: 2 }), flags: { declareBornIn2: true, zeroDates: 'expire', confirmLegacyStopped: true }, key: 'receta-vieja', action: 'refuse', exit: 1, text: /--zero-dates=expire, --confirm-legacy-stopped no tiene\(n\) efecto/ },
  { name: 'H4 · born + --confirm-legacy-stopped en hecho sin marcador', state: oldRecipe({ expiring: 0 }), flags: { declareBornIn2: true, force: true, confirmLegacyStopped: true }, key: 'hecho', action: 'refuse', exit: 1, text: /no tiene\(n\) efecto/ },
  { name: 'H4 · born + --upgraded-at (sin fix)', state: oldRecipe(), flags: { declareBornIn2: true, force: true, upgradedAt: '2026-09-01T10:00:00Z' }, key: 'receta-vieja', action: 'refuse', exit: 1 },
]

test.group('authz:upgrade-1x · upgrade1xPlan PURA: tabla de verdad (todos los motores)', () => {
  for (const row of TABLE) {
    test(`${row.name} ⇒ ${row.key} · ${row.action} · exit ${row.exit}`, ({ assert }) => {
      const plan = upgrade1xPlan(row.state, row.flags)
      const text = plan.lines.map((l) => l.message).join('\n')
      assert.match(plan.lines[0].message, new RegExp(`^estado: ${row.key} · `), 'la PRIMERA línea es el estado detectado')
      assert.equal(plan.state, row.key, text)
      assert.equal(plan.action, row.action, text)
      assert.equal(plan.exitCode, row.exit, text)
      if (row.write !== undefined) assert.equal(plan.write, row.write)
      if (row.action !== 'run') assert.isFalse(plan.write, 'solo `run` escribe')
      if (row.steps) assert.deepEqual(plan.steps, row.steps)
      if (row.text) assert.match(text, row.text)
      if (row.notText) assert.notMatch(text, row.notText)
      if (row.action === 'refuse') assert.include(text, 'No se ha escrito nada.')
    })
  }

  test('ningún camino convierte una base en datetime sin marcador salvo la corrección (A1), y la conversión completa siempre va ANTES de crear authz_catalog_version', ({ assert }) => {
    for (const row of TABLE) {
      const plan = upgrade1xPlan(row.state, row.flags)
      const text = plan.lines.map((l) => l.message).join('\n')
      if (plan.steps.includes('convert')) {
        const marker = row.state.marker
        assert.isTrue(row.state.expiresType === 'timestamp' || (Array.isArray(marker) && marker[0]?.state === 'armed'), `${row.name}: convert solo con timestamp o marcador armado`)
        if (plan.steps.includes('catalog-version')) assert.isBelow(plan.steps.indexOf('convert'), plan.steps.indexOf('catalog-version'), row.name)
        if (plan.steps.includes('marker-arm')) assert.isBelow(plan.steps.indexOf('marker-arm'), plan.steps.indexOf('assignments'), `${row.name}: se arma antes del MODIFY`)
      }
      if (plan.steps.includes('zero-dates')) assert.equal(plan.steps[0], 'zero-dates', `${row.name}: las fechas cero se arreglan antes de todo`)
      // C1: ningún plan que ESCRIBE y convierte sin la confirmación; P1: `born` nunca va con un paso que toque datos.
      if (plan.write && (plan.steps.includes('convert') || plan.steps.includes('fix-previous'))) {
        assert.isTrue(row.flags.confirmLegacyStopped === true, `${row.name}: --force convierte sin --confirm-legacy-stopped`)
      }
      if (plan.steps.includes('born')) {
        for (const s of ['zero-dates', 'marker-arm', 'convert', 'fix-previous']) assert.notInclude(plan.steps, s, `${row.name}: born no toca datos`)
        // Cierre 5 · B1/B1-bis/H4: born solo sin rastro de 1.x (ni DDL pendiente ni fechas cero) y sin banderas de la conversión.
        assert.deepEqual(plan.steps, ['marker-table', 'born'], `${row.name}: born no ejecuta DDL de 1.x`)
        assert.isEmpty(row.state.pendingDdl, `${row.name}: born con DDL de 1.x pendiente`)
        assert.equal(row.state.unreadable, 0, `${row.name}: born con fechas cero`)
        for (const f of ['zone', 'zeroDates', 'confirmLegacyStopped', 'fixPreviousUpgrade', 'upgradedAt'] as const) {
          assert.isTrue(row.flags[f] === undefined || row.flags[f] === false, `${row.name}: born con --${f}`)
        }
      }
      // Cierre 5 · B1: con rastro de 1.x, receta-vieja nunca ofrece born.
      if (plan.state === 'receta-vieja' && (row.state.pendingDdl.length > 0 || row.state.unreadable > 0)) {
        assert.notInclude(text, '--declare-born-in-2 --force', `${row.name}: ofrece born con rastro de 1.x`)
      }
      if (plan.state === 'motor-no-transaccional') assert.isEmpty(plan.steps)
    }
  })

  test('parseUpgradedAt exige zona explícita; v7Prefix es el prefijo por bytes del milisegundo', ({ assert }) => {
    assert.equal(parseUpgradedAt('2026-09-01T10:00:00Z'), Date.parse('2026-09-01T10:00:00Z'))
    assert.equal(parseUpgradedAt('2026-09-01T12:00:00.250+02:00'), Date.parse('2026-09-01T10:00:00.250Z'))
    assert.isNull(parseUpgradedAt('2026-09-01T10:00:00'))
    assert.isNull(parseUpgradedAt('2026-09-01 10:00:00Z'))
    assert.isNull(parseUpgradedAt('ayer'))
    const ms = Date.parse('2026-07-29T15:47:39.000Z')
    const u = uuidv7({ msecs: ms })
    assert.equal(u.slice(0, 13), v7Prefix(ms))
    assert.isTrue(Buffer.from(u) < Buffer.from(v7Prefix(ms + 1)) || u < v7Prefix(ms + 1))
  })
})

/* ── 2 · Fuera de MySQL, por el kernel ─────────────────────────────────────── */

const CONNECTION = 'upgrade1x'

/** Cuenta cada sentencia que knex manda por la conexión del comando. */
function countQueries(name: string): { count: () => number; stop: () => void } {
  let n = 0
  const on = () => n++
  const clients = [db.connection(name).getWriteClient(), db.connection(name).getReadClient()] as any[]
  for (const c of clients) c.on('query', on)
  return { count: () => n, stop: () => clients.forEach((c) => c.off('query', on)) }
}

test.group('authz:upgrade-1x · fuera de MySQL, por el kernel: exit 0, cero sentencias, y la letra nombra lo recibido', () => {
  test('todas las banderas ⇒ «estado: no-mysql» con la conexión pedida, exit 0, cero sentencias y la lista exacta de banderas sin efecto', async ({ assert }) => {
    const scratch = await openScratchDatabase()
    db.manager.add(CONNECTION, scratch.connection as any)
    const spy = countQueries(CONNECTION)
    try {
      const ace = await aceFor(AuthzUpgrade1x)
      const run = await ace.exec([
        '--zone=Europe/Madrid',
        '--force',
        '--dry-run',
        '--fix-previous-upgrade',
        '--upgraded-at=2026-09-01T10:00:00Z',
        '--zero-dates=expire',
        '--confirm-legacy-stopped',
        '--declare-born-in-2',
        `--connection=${CONNECTION}`,
      ])
      assert.isUndefined(run.error)
      assert.equal(run.exitCode ?? 0, 0)
      assert.match(run.logs[0], new RegExp(`estado: no-mysql · la conexión '${CONNECTION}' es (better-sqlite3|postgres): este comando solo sube MySQL`))
      assert.include(run.logs[0], 'No se ha ejecutado ninguna sentencia.')
      assert.include(
        run.logs.join('\n'),
        'Banderas recibidas y sin efecto fuera de MySQL: --zone=Europe/Madrid, --force, --dry-run, --fix-previous-upgrade, --upgraded-at=2026-09-01T10:00:00Z, --zero-dates=expire, --confirm-legacy-stopped, --declare-born-in-2.'
      )
      assert.equal(spy.count(), 0, 'cero sentencias')
    } finally {
      spy.stop()
      await db.manager.close(CONNECTION, true)
      await scratch.drop()
    }
  }).skip(IS_MYSQL, 'fuera de MySQL')
})

/* ── 3 · En MySQL, por el kernel ───────────────────────────────────────────── */

const LEGACY_ROLE = '0192a000-0000-7000-8000-00000000abcd'
/** UUIDv7 de 2024-10 (como los del hijo de `upgrade_recipe`): filas de 1.x. */
const legacyUuid = (i: number) => `0192a000-0000-7000-8000-0000000200${String(i).padStart(2, '0')}`
const holderOf = (i: number) => `0192a000-0000-7000-8000-0000000100${String(i).padStart(2, '0')}`
const utc = (iso: string) => new Date(iso).toISOString().slice(0, 23).replace('T', ' ') + '000'

/** El bloque publicado de 2.4.0-alpha.1 a 2.5.0-rc.1 (literal de `git show v2.5.0-rc.1:README.md`): no convertía. */
const PUBLISHED_MYSQL_BLOCK_2_4_TO_RC1 = [
  `ALTER TABLE authz_roles MODIFY slug varchar(100) COLLATE utf8mb4_bin NOT NULL, MODIFY scope_type varchar(20) COLLATE utf8mb4_bin NOT NULL`,
  `ALTER TABLE authz_permissions MODIFY slug varchar(100) COLLATE utf8mb4_bin NOT NULL`,
  `ALTER TABLE authz_assignments MODIFY holder_type varchar(50) COLLATE utf8mb4_bin NOT NULL, MODIFY holder_uuid varchar(64) COLLATE utf8mb4_bin NOT NULL, MODIFY scope_type varchar(20) COLLATE utf8mb4_bin NOT NULL, MODIFY scope_uuid varchar(64) COLLATE utf8mb4_bin NOT NULL, MODIFY expires_at datetime(3) NULL`,
  `ALTER TABLE authz_denies MODIFY holder_type varchar(50) COLLATE utf8mb4_bin NOT NULL, MODIFY holder_uuid varchar(64) COLLATE utf8mb4_bin NOT NULL, MODIFY scope_type varchar(20) COLLATE utf8mb4_bin NOT NULL, MODIFY scope_uuid varchar(64) COLLATE utf8mb4_bin NOT NULL`,
  `CREATE TABLE authz_catalog_version (id int NOT NULL PRIMARY KEY, version bigint NOT NULL DEFAULT 0, updated_at timestamp NOT NULL, freeze_reason varchar(255) NULL, freeze_holder varchar(120) NULL, freeze_until_ms bigint NULL, freeze_fence bigint NOT NULL DEFAULT 0)`,
  'INSERT INTO authz_catalog_version (id, version, updated_at) VALUES (1, 0, CURRENT_TIMESTAMP)',
  'INSERT INTO authz_catalog_version (id, version, updated_at) VALUES (2, 0, CURRENT_TIMESTAMP)',
  `ALTER TABLE authz_roles ADD COLUMN owner_scope_key varchar(80) COLLATE utf8mb4_bin NOT NULL DEFAULT 'global', DROP INDEX authz_roles_slug_scope_uq, ADD UNIQUE INDEX authz_roles_slug_scope_owner_uq (slug, scope_type, owner_scope_key), ADD INDEX authz_roles_owner_idx (owner_scope_key)`,
  'ALTER TABLE authz_permissions ADD COLUMN assignable_at varchar(500) NULL',
]

interface Legacy {
  scratch: Awaited<ReturnType<typeof openScratchDatabase>>
  raw(sql: string, bindings?: unknown[]): Promise<any[]>
  /** `expires_at` de cada fila, en orden de uuid (DATE_FORMAT, sin depender del cliente). */
  stored(): Promise<Array<string | null>>
  expiresType(): Promise<string>
  marker(): Promise<any[] | null>
  /** Foto de TODO lo observable (esquema + datos + marcador): «cero escrituras» se compara con esto. */
  snapshot(): Promise<string>
  exec(args: string[]): Promise<{ exitCode: number; logs: string[]; error: any }>
  close(): Promise<void>
}

/**
 * Una base de trabajo con el esquema de 1.1.0 y una asignación de 1.x por instante, escrita como la escribía 1.x desde
 * un proceso en `processZone`: la pared del proceso, por una sesión en la zona global (la regla medida en el cierre 1).
 * `--connection=upgrade1x` apunta a ella con sesiones que nacen en `sql_mode = ''` y `time_zone = '+05:00'`.
 */
async function legacyDatabase(processZone: string, instants: string[], options: { session?: string } = {}): Promise<Legacy> {
  const scratch = await openScratchDatabase()
  const raw = async (sql: string, bindings: unknown[] = []) => ((await scratch.db.rawQuery(sql, bindings as any)) as any)[0]
  const old = await readFile(new URL('./fixtures/migration-1.1.0.stub', import.meta.url), 'utf8')
  await runMigrationSource(scratch.db, old)
  const now = '2024-10-18 00:00:00'
  await raw('INSERT INTO authz_roles (uuid, slug, name, scope_type, `rank`, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)', [LEGACY_ROLE, 'legacy', 'legacy', 'app', 7, now, now])
  for (const [i, iso] of instants.entries()) {
    const wall = DateTime.fromISO(iso, { zone: 'utc' }).setZone(processZone).toFormat('yyyy-LL-dd HH:mm:ss')
    await raw(
      'INSERT INTO authz_assignments (uuid, holder_type, holder_uuid, role_uuid, scope_type, scope_uuid, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [legacyUuid(i), 'users', holderOf(i), LEGACY_ROLE, 'app', '00000000-0000-0000-0000-000000000000', wall, now]
    )
  }
  const pool = { ...((scratch.connection as any).pool ?? {}) }
  db.manager.add(CONNECTION, {
    ...(scratch.connection as any),
    pool: {
      ...pool,
      afterCreate: (conn: any, done: any) =>
        conn.query(`SET SESSION sql_mode = '', time_zone = '+05:00'${options.session ? `, ${options.session}` : ''}`, (error: any) => done(error, conn)),
    },
  })
  // Control del harness: las sesiones de la conexión del comando nacen de verdad en otra zona y sin sql_mode estricto.
  const [session] = ((await db.connection(CONNECTION).rawQuery('SELECT @@session.time_zone AS tz, @@session.sql_mode AS m')) as any)[0]
  if (session.tz !== '+05:00' || session.m !== '') throw new Error(`harness: la sesión del comando no nace en +05:00 / sql_mode '': ${JSON.stringify(session)}`)
  const ace = await aceFor(AuthzUpgrade1x)
  const self: Legacy = {
    scratch,
    raw,
    stored: async () =>
      (await raw("SELECT DATE_FORMAT(expires_at, '%Y-%m-%d %H:%i:%s.%f') AS e FROM authz_assignments ORDER BY uuid")).map((r: any) => r.e),
    expiresType: async () =>
      (await raw("SELECT column_type AS t FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'authz_assignments' AND column_name = 'expires_at'"))[0].t,
    marker: async () => {
      const t = await raw("SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'authz_upgrade_1x'")
      if (Number(t[0].n) === 0) return null
      return (await raw('SELECT step, state, mode, zone, done_at IS NOT NULL AS done FROM authz_upgrade_1x')).map((r: any) => ({
        step: r.step,
        state: r.state,
        mode: r.mode,
        zone: r.zone,
        done: Boolean(Number(r.done)),
      }))
    },
    snapshot: async () => {
      const columns = await raw(
        'SELECT table_name, column_name, column_type, collation_name, is_nullable, column_default FROM information_schema.columns WHERE table_schema = DATABASE() ORDER BY table_name, column_name'
      )
      const indexes = await raw('SELECT table_name, index_name, column_name, seq_in_index FROM information_schema.statistics WHERE table_schema = DATABASE() ORDER BY 1, 2, 4')
      const engines = await raw('SELECT table_name, engine FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY 1')
      return JSON.stringify({ columns, indexes, engines, stored: await self.stored(), marker: await self.marker() })
    },
    exec: async (args) => {
      // Pool nuevo en cada ejecución: el comando devuelve su sesión limpia (zona y sql_mode del servidor), así que sin esto
      // la ejecución siguiente heredaría esa limpieza y no probaría que el comando la hace él.
      await db.manager.close(CONNECTION)
      const seen = ace.kernel.ui.logger.getLogs().length
      const run = await ace.exec([...args, `--connection=${CONNECTION}`])
      return { exitCode: run.exitCode ?? 0, logs: run.logs.slice(seen).map((l) => l.replace(/^\[ [a-z]+\([a-z]+\) \] /, '')), error: run.error }
    },
    close: async () => {
      AuthzUpgrade1x.afterStep = undefined
      await db.manager.close(CONNECTION, true)
      await scratch.drop()
    },
  }
  return self
}

const MADRID = ['2030-07-01T00:00:00.000Z', '2030-01-01T00:00:00.000Z']
const CARACAS = ['2030-01-01T00:00:00.000Z']

/** Exacto en T−1 ms / T: el instante guardado (UTC, leído como lo lee 2.x) ES el instante que 1.x quiso. */
function assertExact(assert: any, stored: Array<string | null>, instants: string[]) {
  assert.deepEqual(stored, instants.map(utc), 'cada caducidad de 1.x guardada en su instante UTC')
  for (const [i, iso] of instants.entries()) {
    const expiry = Date.parse(stored[i]!.slice(0, 23).replace(' ', 'T') + 'Z')
    const t = Date.parse(iso)
    assert.isTrue(expiry > t - 1, `${iso}: a T−1 ms concede (expires_at > now)`)
    assert.isFalse(expiry > t, `${iso}: en T ya no concede`)
  }
}

if (IS_MYSQL) test.group('authz:upgrade-1x · MySQL, por el kernel con las banderas de verdad', (group) => {
  group.each.timeout(120_000)

  for (const { zone, processZone, instants, label } of [
    { zone: 'Europe/Madrid', processZone: 'Europe/Madrid', instants: MADRID, label: 'Madrid (verano +02:00 e invierno +01:00, zona por nombre)' },
    { zone: '-04:00', processZone: 'America/Caracas', instants: CARACAS, label: 'Caracas (−04:00, offset)' },
  ]) {
    test(`1x-sin-subir · ${label}: simulación = cero escrituras; --force sube y convierte EXACTO; el esquema es el publicado; la 3.ª ejecución es «hecho»`, async ({ assert }) => {
      const legacy = await legacyDatabase(processZone, instants)
      try {
        const before = await legacy.snapshot()
        const dry = await legacy.exec([`--zone=${zone}`])
        assert.equal(dry.exitCode, 0)
        assert.match(dry.logs[0], /^estado: 1x-sin-subir · expires_at es el TIMESTAMP de 1.x y no hay marcador/)
        assert.include(dry.logs.join('\n'), 'Simulación (--dry-run por defecto): no se ha escrito nada.')
        const explicit = await legacy.exec([`--zone=${zone}`, '--dry-run'])
        assert.equal(explicit.exitCode, 0)
        assert.equal(await legacy.snapshot(), before, '--dry-run (implícito o explícito) no escribe NADA')

        const run = await legacy.exec([`--zone=${zone}`, '--confirm-legacy-stopped', '--force'])
        assert.equal(run.exitCode, 0, run.logs.join('\n'))
        assert.match(run.logs.at(-1)!, /^Subida 1.x → 2.x hecha/)
        assertExact(assert, await legacy.stored(), instants)
        assert.deepEqual(await legacy.marker(), [{ step: 'expires_at', state: 'done', mode: 'upgrade', zone, done: true }])
        assert.deepEqual(await describeAuthzSchema(legacy.scratch.db, RECIPE_TABLES), await describeAuthzSchema(db, RECIPE_TABLES), 'el esquema subido es el publicado')
        const roles = await legacy.raw('SELECT owner_scope_key AS o FROM authz_roles WHERE uuid = ?', [LEGACY_ROLE])
        assert.equal(roles[0].o, 'global', 'el rol de 1.x queda global')

        const again = await legacy.exec([`--zone=${zone}`, '--force'])
        assert.equal(again.exitCode, 0)
        assert.match(again.logs[0], /^estado: hecho · subida hecha/)
        assertExact(assert, await legacy.stored(), instants)
      } finally {
        await legacy.close()
      }
    })
  }

  test('1x-sin-subir sin --zone, con una zona que MySQL no convierte, o con --dry-run y --force a la vez: exit 1 y CERO cambios (también con sesiones en sql_mode = \'\')', async ({ assert }) => {
    const legacy = await legacyDatabase('America/Caracas', CARACAS)
    try {
      const before = await legacy.snapshot()
      const noZone = await legacy.exec(['--force'])
      assert.equal(noZone.exitCode, 1)
      assert.match(noZone.logs[0], /^estado: 1x-sin-subir/)
      assert.include(noZone.logs.join('\n'), '--zone es obligatoria (sin default)')
      const unknown = await legacy.exec(['--zone=Europe/Nowhere', '--force'])
      assert.equal(unknown.exitCode, 1)
      assert.include(unknown.logs.join('\n'), "MySQL no convierte la zona 'Europe/Nowhere'")
      const both = await legacy.exec(['--zone=-04:00', '--dry-run', '--force'])
      assert.equal(both.exitCode, 1, '--dry-run con --force se niega: ninguna de las dos gana en silencio')
      assert.include(both.logs.join('\n'), '--force y --dry-run a la vez')
      assert.equal(await legacy.snapshot(), before)
      assert.equal(await legacy.expiresType(), 'timestamp')
    } finally {
      await legacy.close()
    }
  })

  const FULL = ['marker-table', 'marker-arm', 'collation-roles', 'collation-permissions', 'assignments', 'collation-denies', 'convert', 'catalog-version', 'roles-owner', 'permissions-assignable']
  test('corte tras CADA paso (k = 1…10) + re-ejecución del mismo comando: reanuda («a-medias»), la caducidad de Caracas en su instante UNA vez, marcador hecho, esquema publicado', async ({ assert }) => {
    const published = await describeAuthzSchema(db, RECIPE_TABLES)
    for (const cut of FULL) {
      const legacy = await legacyDatabase('America/Caracas', CARACAS)
      try {
        AuthzUpgrade1x.afterStep = (step) => {
          if (step === cut) throw new Error(`corte inyectado tras ${cut}`)
        }
        const first = await legacy.exec(['--zone=-04:00', '--confirm-legacy-stopped', '--force'])
        assert.equal(first.exitCode, 1, cut)
        assert.match(first.logs.join('\n'), new RegExp(`corte en el paso \\d+/10 · ${cut}: corte inyectado`), cut)
        AuthzUpgrade1x.afterStep = undefined
        const second = await legacy.exec(['--zone=-04:00', '--confirm-legacy-stopped', '--force'])
        assert.equal(second.exitCode, 0, `${cut}: ${second.logs.join('\n')}`)
        assert.match(second.logs[0], cut === 'permissions-assignable' ? /^estado: hecho/ : cut === 'marker-table' ? /^estado: 1x-sin-subir/ : /^estado: a-medias/, cut)
        assertExact(assert, await legacy.stored(), CARACAS)
        assert.deepEqual(await legacy.marker(), [{ step: 'expires_at', state: 'done', mode: 'upgrade', zone: '-04:00', done: true }], cut)
        assert.deepEqual(await describeAuthzSchema(legacy.scratch.db, RECIPE_TABLES), published, cut)
        const third = await legacy.exec(['--zone=-04:00', '--force'])
        assert.match(third.logs[0], /^estado: hecho/, cut)
        assertExact(assert, await legacy.stored(), CARACAS)
      } finally {
        await legacy.close()
      }
    }
  }).timeout(600_000)

  test('a-medias con OTRA --zone: negativa, cero cambios (la conversión armada se reanuda con su zona)', async ({ assert }) => {
    const legacy = await legacyDatabase('America/Caracas', CARACAS)
    try {
      AuthzUpgrade1x.afterStep = (step) => {
        if (step === 'assignments') throw new Error('corte')
      }
      assert.equal((await legacy.exec(['--zone=-04:00', '--confirm-legacy-stopped', '--force'])).exitCode, 1)
      AuthzUpgrade1x.afterStep = undefined
      const before = await legacy.snapshot()
      const other = await legacy.exec(['--zone=+00:00', '--force'])
      assert.equal(other.exitCode, 1)
      assert.match(other.logs[0], /^estado: a-medias/)
      assert.include(other.logs.join('\n'), 'se reanuda SIEMPRE con la zona del marcador')
      assert.equal(await legacy.snapshot(), before)
      const resumed = await legacy.exec(['--confirm-legacy-stopped', '--force'])
      assert.equal(resumed.exitCode, 0, 'sin --zone reanuda con la del marcador')
      assertExact(assert, await legacy.stored(), CARACAS)
    } finally {
      await legacy.close()
    }
  })

  for (const { zone, processZone, instants, fixed } of [
    { zone: 'Europe/Madrid', processZone: 'Europe/Madrid', instants: MADRID, fixed: true },
    { zone: '-04:00', processZone: 'America/Caracas', instants: CARACAS, fixed: false },
  ]) {
    test(`receta-vieja (${processZone}): el camino normal se NIEGA (A1) sin tocar nada; --fix-previous-upgrade valida el instante (B1, futuro) y ${fixed ? 'pone las filas de 1.x en su instante' : 'no mueve nada (oeste)'}, sin tocar la fila de 2.x; re-ejecutarla es «hecho»`, async ({ assert }) => {
      const legacy = await legacyDatabase(processZone, instants)
      try {
        for (const sql of PUBLISHED_MYSQL_BLOCK_2_4_TO_RC1) await legacy.raw(sql)
        const shifted = await legacy.stored()
        // Una fila de 2.x escrita después de la subida (UTC, uuid v7 de ahora).
        const alice = uuidv7()
        await legacy.raw(
          "INSERT INTO authz_assignments (uuid, holder_type, holder_uuid, role_uuid, scope_type, scope_uuid, expires_at, created_at) VALUES (?, 'users', 'user-42', ?, 'app', '00000000-0000-0000-0000-000000000000', '2030-01-01 00:00:00.600', CURRENT_TIMESTAMP)",
          [alice, LEGACY_ROLE]
        )
        const before = await legacy.snapshot()

        const plain = await legacy.exec([`--zone=${zone}`, '--force'])
        assert.equal(plain.exitCode, 1)
        assert.match(plain.logs[0], /^estado: receta-vieja · expires_at ya es datetime\(3\) y no hay marcador/)
        assert.include(plain.logs.join('\n'), 'no convierte nada por defecto')
        assert.equal(await legacy.snapshot(), before, 'A1: el camino normal no convierte NADA sobre una base ya subida')

        const early = await legacy.exec(['--fix-previous-upgrade', `--zone=${zone}`, '--upgraded-at=2024-01-01T00:00:00Z', '--force'])
        assert.equal(early.exitCode, 1)
        assert.include(early.logs.join('\n'), '(B1)')
        const future = await legacy.exec(['--fix-previous-upgrade', `--zone=${zone}`, '--upgraded-at=2099-01-01T00:00:00Z', '--force'])
        assert.equal(future.exitCode, 1)
        assert.include(future.logs.join('\n'), 'FUTURO')
        assert.equal(await legacy.snapshot(), before)

        // Cuándo corrió el bloque: después de las filas de 1.x (2024) y antes de la de 2.x (ahora).
        const upgradedAt = new Date(Date.parse(new Date().toISOString()) - 60_000).toISOString()
        const fix = await legacy.exec(['--fix-previous-upgrade', `--zone=${zone}`, `--upgraded-at=${upgradedAt}`, '--confirm-legacy-stopped', '--force'])
        assert.equal(fix.exitCode, 0, fix.logs.join('\n'))
        const after = await legacy.stored()
        const aliceRow = await legacy.raw("SELECT DATE_FORMAT(expires_at, '%Y-%m-%d %H:%i:%s.%f') AS e FROM authz_assignments WHERE uuid = ?", [alice])
        assert.equal(aliceRow[0].e, '2030-01-01 00:00:00.600000', 'la fila de 2.x no se mueve')
        const legacyRows = after.slice(0, instants.length)
        if (fixed) assertExact(assert, legacyRows, instants)
        else assert.deepEqual(legacyRows, shifted, 'oeste: nada se mueve (ya caducaban antes: fail-closed)')
        assert.deepEqual(await legacy.marker(), [{ step: 'expires_at', state: 'done', mode: 'fix-previous', zone, done: true }])

        const twice = await legacy.exec(['--fix-previous-upgrade', `--zone=${zone}`, `--upgraded-at=${upgradedAt}`, '--force'])
        assert.equal(twice.exitCode, 0)
        assert.match(twice.logs[0], /^estado: hecho · subida hecha: marcador de la corrección/)
        assert.deepEqual(await legacy.stored(), after, 'dos veces = una')
      } finally {
        await legacy.close()
      }
    })
  }

  test('B2 · se restaura el volcado de 1.x de authz_* tras «hecho» (el marcador sobrevive): incoherente, exit 1, cero cambios', async ({ assert }) => {
    const legacy = await legacyDatabase('Europe/Madrid', MADRID)
    try {
      assert.equal((await legacy.exec(['--zone=Europe/Madrid', '--confirm-legacy-stopped', '--force'])).exitCode, 0)
      for (const t of ['authz_denies', 'authz_assignments', 'authz_role_permissions', 'authz_permissions', 'authz_roles', 'authz_catalog_version']) {
        await legacy.raw(`DROP TABLE ${t}`)
      }
      const old = await readFile(new URL('./fixtures/migration-1.1.0.stub', import.meta.url), 'utf8')
      await runMigrationSource(legacy.scratch.db, old)
      await legacy.raw("INSERT INTO authz_roles (uuid, slug, name, scope_type, `rank`, created_at, updated_at) VALUES (?, 'legacy', 'legacy', 'app', 7, NOW(), NOW())", [LEGACY_ROLE])
      await legacy.raw(
        "INSERT INTO authz_assignments (uuid, holder_type, holder_uuid, role_uuid, scope_type, scope_uuid, expires_at, created_at) VALUES (?, 'users', ?, ?, 'app', '00000000-0000-0000-0000-000000000000', '2030-07-01 02:00:00', NOW())",
        [legacyUuid(0), holderOf(0), LEGACY_ROLE]
      )
      const before = await legacy.snapshot()
      const run = await legacy.exec(['--zone=Europe/Madrid', '--force'])
      assert.equal(run.exitCode, 1)
      assert.match(run.logs[0], /^estado: incoherente · .*\(B2\)/)
      assert.equal(await legacy.snapshot(), before)
    } finally {
      await legacy.close()
    }
  })

  test('A2 · fecha cero de 1.x: negativa listando cuántas, cero cambios; --zero-dates=expire la deja en un instante PASADO (nunca NULL) y convierte el resto', async ({ assert }) => {
    const legacy = await legacyDatabase('Europe/Madrid', MADRID)
    try {
      // Lo que dejaba 1.x con sql_mode no estricto al escribir una caducidad > 2038 en TIMESTAMP: la fecha cero.
      const conn = await legacy.scratch.db.connection().getWriteClient().client.acquireConnection()
      const knex: any = legacy.scratch.db.connection().getWriteClient()
      await knex.raw("SET SESSION sql_mode = ''").connection(conn)
      await knex.raw('UPDATE authz_assignments SET expires_at = ? WHERE uuid = ?', ['2040-01-01 00:00:00', legacyUuid(1)]).connection(conn)
      await knex.raw('SET SESSION sql_mode = @@global.sql_mode').connection(conn)
      await knex.client.releaseConnection(conn)
      assert.equal((await legacy.stored())[1], '0000-00-00 00:00:00.000000')
      const before = await legacy.snapshot()
      const refused = await legacy.exec(['--zone=Europe/Madrid', '--force'])
      assert.equal(refused.exitCode, 1)
      assert.include(refused.logs.join('\n'), '1 fila(s) de authz_assignments tienen una caducidad que MySQL no puede leer')
      assert.equal(await legacy.snapshot(), before)

      const run = await legacy.exec(['--zone=Europe/Madrid', '--zero-dates=expire', '--confirm-legacy-stopped', '--force'])
      assert.equal(run.exitCode, 0, run.logs.join('\n'))
      const stored = await legacy.stored()
      assert.equal(stored[0], utc(MADRID[0]), 'la legible, convertida exacta')
      assert.isNotNull(stored[1], 'nunca NULL (= permanente)')
      assert.isBelow(Date.parse(stored[1]!.slice(0, 19).replace(' ', 'T') + 'Z'), Date.parse('1970-01-03T00:00:00Z'), 'un instante PASADO: caducada')
    } finally {
      await legacy.close()
    }
  })

  test('defensa en profundidad del paso convert (por debajo del plan): sin marcador ARMADO, o con una caducidad que CONVERT_TZ no convierte, se niega dentro de su transacción y no toca nada', async ({ assert }) => {
    const legacy = await legacyDatabase('Europe/Madrid', MADRID)
    try {
      for (const sql of PUBLISHED_MYSQL_BLOCK_2_4_TO_RC1.slice(0, 4)) await legacy.raw(sql)
      await legacy.raw("CREATE TABLE authz_upgrade_1x (step varchar(40) COLLATE utf8mb4_bin NOT NULL PRIMARY KEY, state varchar(10) NOT NULL, mode varchar(20) NOT NULL, zone varchar(64) NOT NULL, upgraded_at datetime(3) NULL, armed_at datetime(3) NOT NULL, done_at datetime(3) NULL)")
      await legacy.raw("INSERT INTO authz_upgrade_1x (step, state, mode, zone, armed_at, done_at) VALUES ('expires_at', 'done', 'upgrade', 'Europe/Madrid', UTC_TIMESTAMP(3), UTC_TIMESTAMP(3))")
      const knex: any = legacy.scratch.db.connection().getWriteClient()
      const conn = await knex.client.acquireConnection()
      const q = async (sql: string, bindings: unknown[] = []) => (await knex.raw(sql, bindings).connection(conn))[0]
      const plan: any = { zone: 'Europe/Madrid', upgradedAtMs: null }
      try {
        const before = await legacy.snapshot()
        const notArmed = await runUpgrade1xStep(q, 'convert', plan).then(() => null, (e) => e)
        assert.match(String(notArmed?.message), /el marcador no está armado/)
        assert.equal(await legacy.snapshot(), before, 'marcador hecho ⇒ no convierte (nunca dos veces)')
        await legacy.raw("UPDATE authz_upgrade_1x SET state = 'armed', done_at = NULL")
        await knex.raw("SET SESSION sql_mode = ''").connection(conn)
        await knex.raw('UPDATE authz_assignments SET expires_at = ? WHERE uuid = ?', ['0000-00-00 00:00:00', legacyUuid(1)]).connection(conn)
        const armedBefore = await legacy.snapshot()
        const zero = await runUpgrade1xStep(q, 'convert', plan).then(() => null, (e) => e)
        assert.match(String(zero?.message), /convertirlas daría NULL/)
        assert.equal(await legacy.snapshot(), armedBefore, 'ni la legible se convirtió: la transacción entera se deshizo')
      } finally {
        await knex.raw('SET SESSION sql_mode = @@global.sql_mode').connection(conn)
        await knex.client.releaseConnection(conn)
      }
    } finally {
      await legacy.close()
    }
  })

  test('otra ejecución con el cerrojo: «estado: ocupado», exit 1, cero cambios', async ({ assert }) => {
    const legacy = await legacyDatabase('America/Caracas', CARACAS)
    const knex: any = legacy.scratch.db.connection().getWriteClient()
    const conn = await knex.client.acquireConnection()
    try {
      await knex.raw("SELECT GET_LOCK(CONCAT('authz_upgrade_1x:', DATABASE()), 0)").connection(conn)
      const before = await legacy.snapshot()
      const run = await legacy.exec(['--zone=-04:00', '--force'])
      assert.equal(run.exitCode, 1)
      assert.match(run.logs[0], /^estado: ocupado/)
      assert.equal(await legacy.snapshot(), before)
    } finally {
      await knex.raw("SELECT RELEASE_LOCK(CONCAT('authz_upgrade_1x:', DATABASE()))").connection(conn)
      await knex.client.releaseConnection(conn)
      await legacy.close()
    }
  })
  /* ── Cierre 4 de la rotación 3 ─────────────────────────────────────────── */

  test('C1 · sin --confirm-legacy-stopped, cada estado que CONVIERTE se niega con --force: exit 1 y CERO cambios (1x-sin-subir, a-medias armado en timestamp y en datetime, --fix-previous-upgrade); la simulación nombra la precondición; con ella, igual que antes', async ({ assert }) => {
    // 1x-sin-subir
    {
      const legacy = await legacyDatabase('America/Caracas', CARACAS)
      try {
        const before = await legacy.snapshot()
        const dry = await legacy.exec(['--zone=-04:00'])
        assert.equal(dry.exitCode, 0)
        assert.include(dry.logs.join('\n'), 'Precondición (C1): para TODOS los procesos 1.x antes de --force (y no hagas un rolling deploy 1.x → 2.x sobre MySQL)')
        assert.include(dry.logs.join('\n'), '--force exige --confirm-legacy-stopped')
        const refused = await legacy.exec(['--zone=-04:00', '--force'])
        assert.equal(refused.exitCode, 1)
        assert.match(refused.logs[0], /^estado: 1x-sin-subir/)
        assert.include(refused.logs.join('\n'), 'falta --confirm-legacy-stopped')
        assert.include(refused.logs.join('\n'), 'No se ha escrito nada.')
        assert.equal(await legacy.snapshot(), before, '1x-sin-subir: cero cambios')
        assert.equal(await legacy.expiresType(), 'timestamp')
        const run = await legacy.exec(['--zone=-04:00', '--confirm-legacy-stopped', '--force'])
        assert.equal(run.exitCode, 0, run.logs.join('\n'))
        assertExact(assert, await legacy.stored(), CARACAS)
      } finally {
        await legacy.close()
      }
    }
    // a-medias: armado con la columna aún timestamp (corte tras marker-arm) y ya datetime (corte tras collation-denies)
    for (const cut of ['marker-arm', 'collation-denies'] as const) {
      const legacy = await legacyDatabase('America/Caracas', CARACAS)
      try {
        AuthzUpgrade1x.afterStep = (step) => {
          if (step === cut) throw new Error('corte')
        }
        assert.equal((await legacy.exec(['--zone=-04:00', '--confirm-legacy-stopped', '--force'])).exitCode, 1, cut)
        AuthzUpgrade1x.afterStep = undefined
        const before = await legacy.snapshot()
        const refused = await legacy.exec(['--force'])
        assert.equal(refused.exitCode, 1, cut)
        assert.match(refused.logs[0], /^estado: a-medias/, cut)
        assert.include(refused.logs.join('\n'), 'falta --confirm-legacy-stopped', cut)
        assert.equal(await legacy.snapshot(), before, `${cut}: cero cambios`)
        const resumed = await legacy.exec(['--confirm-legacy-stopped', '--force'])
        assert.equal(resumed.exitCode, 0, `${cut}: ${resumed.logs.join('\n')}`)
        assertExact(assert, await legacy.stored(), CARACAS)
      } finally {
        await legacy.close()
      }
    }
    // --fix-previous-upgrade sobre receta-vieja
    {
      const legacy = await legacyDatabase('Europe/Madrid', MADRID)
      try {
        for (const sql of PUBLISHED_MYSQL_BLOCK_2_4_TO_RC1) await legacy.raw(sql)
        const before = await legacy.snapshot()
        const upgradedAt = new Date(Date.now() - 60_000).toISOString()
        const refused = await legacy.exec(['--fix-previous-upgrade', '--zone=Europe/Madrid', `--upgraded-at=${upgradedAt}`, '--force'])
        assert.equal(refused.exitCode, 1)
        assert.match(refused.logs[0], /^estado: receta-vieja/)
        assert.include(refused.logs.join('\n'), 'falta --confirm-legacy-stopped')
        assert.equal(await legacy.snapshot(), before, 'corrección: cero cambios, ni la tabla del marcador')
        assert.isNull(await legacy.marker())
        const fix = await legacy.exec(['--fix-previous-upgrade', '--zone=Europe/Madrid', `--upgraded-at=${upgradedAt}`, '--confirm-legacy-stopped', '--force'])
        assert.equal(fix.exitCode, 0, fix.logs.join('\n'))
        assertExact(assert, await legacy.stored(), MADRID)
      } finally {
        await legacy.close()
      }
    }
  }).timeout(300_000)

  test('C2 · authz_assignments en MyISAM: «motor-no-transaccional», exit 1, CERO cambios y la receta; tras el ALTER a InnoDB sube exacto. El marcador en MyISAM (a medias) también se niega', async ({ assert }) => {
    const legacy = await legacyDatabase('America/Caracas', CARACAS)
    try {
      for (const r of await legacy.raw("SELECT constraint_name AS c FROM information_schema.referential_constraints WHERE constraint_schema = DATABASE() AND table_name = 'authz_assignments'")) {
        await legacy.raw(`ALTER TABLE authz_assignments DROP FOREIGN KEY \`${r.c}\``)
      }
      await legacy.raw('ALTER TABLE authz_assignments ENGINE=MyISAM')
      const before = await legacy.snapshot()
      const refused = await legacy.exec(['--zone=-04:00', '--confirm-legacy-stopped', '--force'])
      assert.equal(refused.exitCode, 1)
      assert.match(refused.logs[0], /^estado: motor-no-transaccional · authz_assignments \(MyISAM\)/)
      assert.include(refused.logs.join('\n'), 'ALTER TABLE authz_assignments ENGINE=InnoDB;')
      assert.equal(await legacy.snapshot(), before, 'cero cambios: ni la tabla del marcador')
      await legacy.raw('ALTER TABLE authz_assignments ENGINE=InnoDB')
      const run = await legacy.exec(['--zone=-04:00', '--confirm-legacy-stopped', '--force'])
      assert.equal(run.exitCode, 0, run.logs.join('\n'))
      assertExact(assert, await legacy.stored(), CARACAS)
    } finally {
      await legacy.close()
    }
    const half = await legacyDatabase('America/Caracas', CARACAS)
    try {
      AuthzUpgrade1x.afterStep = (step) => {
        if (step === 'marker-arm') throw new Error('corte')
      }
      assert.equal((await half.exec(['--zone=-04:00', '--confirm-legacy-stopped', '--force'])).exitCode, 1)
      AuthzUpgrade1x.afterStep = undefined
      await half.raw('ALTER TABLE authz_upgrade_1x ENGINE=MyISAM')
      const before = await half.snapshot()
      const refused = await half.exec(['--confirm-legacy-stopped', '--force'])
      assert.equal(refused.exitCode, 1)
      assert.match(refused.logs[0], /^estado: motor-no-transaccional · authz_upgrade_1x \(MyISAM\)/)
      assert.equal(await half.snapshot(), before)
    } finally {
      await half.close()
    }
  }).timeout(300_000)

  test('C2 · con default_storage_engine = MyISAM en la sesión del comando, las tablas que CREA (marcador y authz_catalog_version) quedan en InnoDB (ENGINE explícito)', async ({ assert }) => {
    const legacy = await legacyDatabase('America/Caracas', CARACAS, { session: "default_storage_engine = 'MyISAM'" })
    try {
      const [ctl] = ((await db.connection(CONNECTION).rawQuery('SELECT @@session.default_storage_engine AS e')) as any)[0]
      assert.equal(ctl.e, 'MyISAM', 'control del harness: la sesión del comando crea en MyISAM por defecto')
      const run = await legacy.exec(['--zone=-04:00', '--confirm-legacy-stopped', '--force'])
      assert.equal(run.exitCode, 0, run.logs.join('\n'))
      const engines = await legacy.raw(
        "SELECT table_name AS t, engine AS e FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name IN ('authz_upgrade_1x', 'authz_catalog_version') ORDER BY 1"
      )
      assert.deepEqual(engines.map((r: any) => [r.t, r.e]), [['authz_catalog_version', 'InnoDB'], ['authz_upgrade_1x', 'InnoDB']])
      assertExact(assert, await legacy.stored(), CARACAS)
    } finally {
      await legacy.close()
    }
  })

  test('P1 · --declare-born-in-2: la simulación no escribe; con --force escribe el marcador done/born SIN tocar una fila, y la siguiente ejecución es «hecho»; con señales de 1.x (timestamp, o un marcador) se niega sin cambios', async ({ assert }) => {
    const born = await legacyDatabase('Europe/Madrid', MADRID)
    try {
      for (const sql of PUBLISHED_MYSQL_BLOCK_2_4_TO_RC1) await born.raw(sql)
      await born.raw(
        "INSERT INTO authz_assignments (uuid, holder_type, holder_uuid, role_uuid, scope_type, scope_uuid, expires_at, created_at) VALUES (?, 'users', 'user-42', ?, 'app', '00000000-0000-0000-0000-000000000000', '2030-01-01 00:00:00.600', CURRENT_TIMESTAMP)",
        [uuidv7(), LEGACY_ROLE]
      )
      const plain = await born.exec([])
      assert.equal(plain.exitCode, 1)
      assert.match(plain.logs[0], /^estado: receta-vieja/)
      assert.include(plain.logs.join('\n'), '--declare-born-in-2 --force')
      const before = await born.snapshot()
      const rows = await born.stored()
      const dry = await born.exec(['--declare-born-in-2'])
      assert.equal(dry.exitCode, 0)
      assert.include(dry.logs.join('\n'), 'Declaras que esta base NACIÓ en 2.x')
      assert.equal(await born.snapshot(), before, 'simulación: cero escrituras')
      const run = await born.exec(['--declare-born-in-2', '--force'])
      assert.equal(run.exitCode, 0, run.logs.join('\n'))
      assert.match(run.logs.at(-1)!, /^Base declarada nacida en 2.x/)
      assert.deepEqual(await born.stored(), rows, 'ninguna fila tocada')
      assert.deepEqual(await born.marker(), [{ step: 'expires_at', state: 'done', mode: 'born', zone: '+00:00', done: true }])
      const next = await born.exec([])
      assert.equal(next.exitCode, 0)
      assert.match(next.logs[0], /^estado: hecho · base DECLARADA nacida en 2.x/)
      const again = await born.exec(['--declare-born-in-2', '--force'])
      assert.equal(again.exitCode, 1, 'no se declara encima de un marcador')
      assert.deepEqual(await born.stored(), rows)
    } finally {
      await born.close()
    }
    const v1db = await legacyDatabase('Europe/Madrid', MADRID)
    try {
      const before = await v1db.snapshot()
      const refused = await v1db.exec(['--declare-born-in-2', '--force'])
      assert.equal(refused.exitCode, 1)
      assert.match(refused.logs[0], /^estado: 1x-sin-subir/)
      assert.include(refused.logs.join('\n'), 'todavía el TIMESTAMP de 1.x')
      assert.equal(await v1db.snapshot(), before, 'timestamp: cero cambios')
      assert.equal((await v1db.exec(['--zone=Europe/Madrid', '--confirm-legacy-stopped', '--force'])).exitCode, 0)
      const upgraded = await v1db.snapshot()
      const onMarker = await v1db.exec(['--declare-born-in-2', '--force'])
      assert.equal(onMarker.exitCode, 1)
      assert.include(onMarker.logs.join('\n'), 'ya hay un marcador')
      assert.equal(await v1db.snapshot(), upgraded, 'marcador existente: cero cambios')
    } finally {
      await v1db.close()
    }
  }).timeout(300_000)

  test('B1 · cierre 5: born se NIEGA con rastro de 1.x — bloque viejo CORTADO antes de authz_catalog_version (DDL de 1.x pendiente) y fechas cero —, exit 1 y CERO cambios; receta-vieja no lo ofrece; H4: born con banderas de la conversión ⇒ negativa sin cambios', async ({ assert }) => {
    const cut = await legacyDatabase('Europe/Madrid', MADRID)
    try {
      // El bloque publicado hasta los MODIFY (incluido el de expires_at) y cortado antes de CREATE TABLE authz_catalog_version.
      for (const sql of PUBLISHED_MYSQL_BLOCK_2_4_TO_RC1.slice(0, 4)) await cut.raw(sql)
      assert.equal(await cut.expiresType(), 'datetime(3)')
      const before = await cut.snapshot()
      const plain = await cut.exec([])
      assert.equal(plain.exitCode, 1)
      assert.match(plain.logs[0], /^estado: receta-vieja · .*Hay rastro de 1.x: DDL de 1.x pendiente \(catalog-version, roles-owner, permissions-assignable\)/)
      assert.notInclude(plain.logs.join('\n'), '--declare-born-in-2 --force', 'con rastro de 1.x receta-vieja no ofrece born')
      assert.include(plain.logs.join('\n'), '--fix-previous-upgrade --zone=')
      for (const args of [['--declare-born-in-2', '--force'], ['--declare-born-in-2']]) {
        const born = await cut.exec(args)
        assert.equal(born.exitCode, 1, `${args.join(' ')}: ${born.logs.join('\n')}`)
        assert.include(born.logs.join('\n'), 'hay rastro de 1.x, born no aplica')
        assert.include(born.logs.join('\n'), 'No se ha escrito nada.')
        assert.equal(await cut.snapshot(), before, `${args.join(' ')}: cero cambios (ni la tabla del marcador ni el DDL)`)
      }
      assert.isNull(await cut.marker())
    } finally {
      await cut.close()
    }

    const zero = await legacyDatabase('Europe/Madrid', MADRID)
    try {
      for (const sql of PUBLISHED_MYSQL_BLOCK_2_4_TO_RC1) await zero.raw(sql)
      // Una fecha cero en el datetime(3) (sql_mode no estricto, como la dejaba 1.x en su TIMESTAMP y la arrastró el MODIFY).
      const conn = await zero.scratch.db.connection().getWriteClient().client.acquireConnection()
      const knex: any = zero.scratch.db.connection().getWriteClient()
      await knex.raw("SET SESSION sql_mode = ''").connection(conn)
      await knex.raw("UPDATE authz_assignments SET expires_at = '0000-00-00 00:00:00' WHERE uuid = ?", [legacyUuid(1)]).connection(conn)
      await knex.raw('SET SESSION sql_mode = @@global.sql_mode').connection(conn)
      await knex.client.releaseConnection(conn)
      assert.equal((await zero.stored())[1], '0000-00-00 00:00:00.000000')
      const before = await zero.snapshot()
      const plain = await zero.exec([])
      assert.equal(plain.exitCode, 1)
      assert.match(plain.logs[0], /^estado: receta-vieja · .*Hay rastro de 1.x: 1 caducidad\(es\) ilegible\(s\)/)
      assert.notInclude(plain.logs.join('\n'), '--declare-born-in-2 --force')
      const born = await zero.exec(['--declare-born-in-2', '--force'])
      assert.equal(born.exitCode, 1, born.logs.join('\n'))
      assert.include(born.logs.join('\n'), 'hay rastro de 1.x, born no aplica — 1 caducidad(es) ilegible(s)')
      assert.equal(await zero.snapshot(), before, 'fechas cero: cero cambios')
    } finally {
      await zero.close()
    }

    const clean = await legacyDatabase('Europe/Madrid', MADRID)
    try {
      for (const sql of PUBLISHED_MYSQL_BLOCK_2_4_TO_RC1) await clean.raw(sql)
      const before = await clean.snapshot()
      for (const extra of [['--zero-dates=expire'], ['--confirm-legacy-stopped'], ['--zero-dates=expire', '--confirm-legacy-stopped']]) {
        const run = await clean.exec(['--declare-born-in-2', '--force', ...extra])
        assert.equal(run.exitCode, 1, `${extra.join(' ')}: ${run.logs.join('\n')}`)
        assert.include(run.logs.join('\n'), 'no tiene(n) efecto')
        assert.equal(await clean.snapshot(), before, `H4 ${extra.join(' ')}: cero cambios`)
      }
    } finally {
      await clean.close()
    }
  }).timeout(300_000)
})
