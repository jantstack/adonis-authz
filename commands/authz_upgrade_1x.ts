import { BaseCommand, flags } from '@adonisjs/core/ace'
import { CommandOptions } from '@adonisjs/core/types/ace'
import { systemClock } from '../src/clock.js'

/**
 * **`authz:upgrade-1x`** (rotación 3 · cierre 3, ESTRUCTURAL; firmado por el dueño el 2026-10-26).
 *
 * La subida 1.x → 2.x de MySQL deja de ser un bloque SQL que el operador copia y pasa a ser CÓDIGO que inspecciona el
 * estado antes de tocar nada. Es el tercer defecto del linaje «receta del operador que no aguanta su re-ejecución»
 * (R3-01 → RR-1 → A1/A2 del re-ataque 2, los tres confirmados en `mysql84`), y la regla de `CLAUDE.md` es que el
 * tercero no se parchea: se quita el camino manual.
 *
 * Reparto (mismo patrón que `unfreezePlan`/`reconcileLines`):
 *  - `readUpgrade1xState` LEE (information_schema, el marcador y los datos) por UNA sesión;
 *  - `upgrade1xPlan(estado, banderas)` es la función PURA que DECIDE: estado detectado, negativa o pasos;
 *  - `run()` imprime el plan y, solo con `--force`, ejecuta los pasos por esa misma sesión.
 *
 * Qué hace la subida (lo que era el bloque MySQL del README): los `MODIFY` de collation/tipo, `expires_at` de
 * `timestamp` a `datetime(3)` en la zona de sesión que tenía 1.x (`@@global.time_zone`), la CONVERSIÓN de cada
 * caducidad de 1.x desde la zona de sus procesos (`--zone`) a UTC, `authz_catalog_version` con sus dos filas, y las
 * columnas `owner_scope_key`/`assignable_at`. El marcador `authz_upgrade_1x` (fila `expires_at`) se ARMA antes del
 * `MODIFY` y SOLO si la columna sigue siendo `timestamp` (cierra A1/B2: una base ya en `datetime` sin marcador no se
 * convierte nunca por defecto); la conversión y el «hecho» van en UNA transacción (DML de InnoDB: todo o nada) y la
 * conversión va ANTES de crear `authz_catalog_version`, así que ningún proceso 2.x ha podido escribir una fila que se
 * convierta (sin esa tabla toda escritura de 2.x es 503).
 *
 * Cierre 4 de la rotación 3 (firmado 2026-10-26, «sí, firmo la a) con el 2 y el 3»), tres límites que el código solo no
 * podía ver:
 *  - C1 · un proceso 1.x VIVO tras la conversión sigue escribiendo la pared de su zona en el `datetime(3)` y nada lo
 *    detecta después (el marcador ya dice `done`). Precondición OBLIGATORIA y CONFIRMADA: todo `--force` que convierte
 *    (`1x-sin-subir`, `a-medias` antes de `convert`, `--fix-previous-upgrade`) exige `--confirm-legacy-stopped`; sin
 *    ella, negativa con cero sentencias de escritura. El esquema NO se cambia para romper las escrituras de 1.x (opción
 *    b descartada por el dueño).
 *  - C2 · «la conversión y el done en UNA transacción» solo es verdad en InnoDB: el comando lee
 *    `information_schema.tables.engine` de `authz_assignments` y del marcador y, si alguno no es InnoDB, se niega
 *    (`motor-no-transaccional`) antes de tocar nada; las tablas que crea llevan `ENGINE=InnoDB` explícito.
 *  - P1 · una base NACIDA en 2.x no se distingue de una subida ENTERA con el bloque viejo: `--declare-born-in-2` es la
 *    DECLARACIÓN del operador (el comando no puede demostrar que no hubo 1.x) y escribe el marcador `done`/`born` sin
 *    tocar datos.
 *
 * Cierre 5 de la rotación 3 (firmado 2026-10-27): born se NIEGA donde el comando SÍ ve 1.x (`upgrade1xLegacyTraces`:
 * DDL de 1.x pendiente o fechas cero, además de `timestamp` y del marcador), y `receta-vieja` deja de ofrecerlo ahí (B1,
 * B1-bis); las banderas de la conversión se rechazan con born en vez de tragarse (H4).
 */

/* ── Tipos ─────────────────────────────────────────────────────────────────── */

/** El estado detectado: la PRIMERA línea de la salida empieza por `estado: <clave>` (CLAUDE.md punto 7). */
export type Upgrade1xStateKey =
  | 'no-mysql'
  | 'sin-tablas'
  | '1x-sin-subir'
  | 'a-medias'
  | 'receta-vieja'
  | 'hecho'
  | 'incoherente'
  | 'motor-no-transaccional'

/** Los DDL de la subida que se detectan pendientes uno a uno (cada uno es idempotente por inspección). */
export const UPGRADE_1X_PRE_CONVERT_DDL = ['collation-roles', 'collation-permissions', 'assignments', 'collation-denies'] as const
export const UPGRADE_1X_POST_CONVERT_DDL = ['catalog-version', 'roles-owner', 'permissions-assignable'] as const
export type Upgrade1xDdl = (typeof UPGRADE_1X_PRE_CONVERT_DDL)[number] | (typeof UPGRADE_1X_POST_CONVERT_DDL)[number]

/** Un paso ejecutable, en el orden en que el plan los pone. */
export type Upgrade1xStep = 'zero-dates' | 'marker-table' | 'marker-arm' | 'convert' | 'fix-previous' | 'born' | Upgrade1xDdl

/** Los pasos que CONVIERTEN caducidades: con `--force` exigen `--confirm-legacy-stopped` (C1). */
export const UPGRADE_1X_CONVERTING_STEPS: readonly Upgrade1xStep[] = ['convert', 'fix-previous']

export interface Upgrade1xMarker {
  step: string
  /** `armed` (antes del MODIFY de `expires_at`, con la columna aún `timestamp`) o `done`. */
  state: string
  /**
   * `upgrade` (subida completa), `fix-previous` (corrección de quien subió con el bloque viejo) o `born` (el operador
   * DECLARÓ la base nacida en 2.x: `--declare-born-in-2`; zona `+00:00`, ningún dato tocado).
   */
  mode: string
  zone: string | null
  /** `--upgraded-at` de la corrección, ISO; `null` en `upgrade`. */
  upgradedAt: string | null
}

/** Lo que `readUpgrade1xState` lee. Las entradas de la tabla de verdad de `upgrade1xPlan`. */
export interface Upgrade1xState {
  /** Nombre de la conexión de Lucid sobre la que se lee. */
  connection: string
  /** `dialect.name` de esa conexión. Fuera de MySQL nada más se lee. */
  dialect: string
  /** Faltan tablas de 1.x (`authz_roles`, `authz_permissions`, `authz_assignments`, `authz_denies`). */
  missingTables: string[]
  /**
   * Tablas que la conversión escribe en UNA transacción (`authz_assignments` y, si existe, `authz_upgrade_1x`) con un
   * motor que NO es InnoDB, como `tabla (MOTOR)` (C2: en MyISAM el ROLLBACK no deshace nada). Ausente = ninguna.
   */
  nonTransactional?: string[]
  /** `COLUMN_TYPE` de `authz_assignments.expires_at` (`timestamp`, `datetime(3)`, …), o `null` si no existe. */
  expiresType: string | null
  /** Filas de `authz_upgrade_1x`; `null` si la tabla no existe; `'malformed'` si existe con otra forma. */
  marker: Upgrade1xMarker[] | null | 'malformed'
  /** DDL pendientes, en orden canónico. */
  pendingDdl: Upgrade1xDdl[]
  /** Combinaciones de esquema que ningún punto de corte de este comando produce (índices a medias, …). */
  schemaOdd: string[]
  /** ¿Existe `authz_catalog_version`? (con ella un proceso 2.x puede haber escrito). */
  catalogVersionTable: boolean
  /** Filas con `expires_at` no nulo. */
  expiring: number
  /** Caducidades presentes que MySQL no puede convertir (fecha cero, mes/día cero): `CONVERT_TZ` da `NULL` (A2). */
  unreadable: number
  /** Zonas sondeadas (`--zone`, la del marcador) → ¿`CONVERT_TZ` las convierte? (tablas de zonas cargadas). */
  zones: Record<string, boolean>
  /** Milisegundo del UUIDv7 más antiguo de `authz_assignments` (`null` si no hay ninguno v7). */
  oldestV7Ms: number | null
  /** Filas cuyo `uuid` no tiene forma de UUIDv7. */
  nonV7: number
  /** Con `--fix-previous-upgrade`: filas con caducidad insertadas antes de `--upgraded-at` (de 1.x). */
  fixBefore: number | null
  /** …y de ellas, las que la conversión ADELANTA (las únicas que la corrección mueve). */
  fixCandidates: number | null
  /** Reloj de pared (`systemClock`), para «`--upgraded-at` no es futuro». */
  nowMs: number
}

export interface Upgrade1xFlags {
  zone?: string
  force?: boolean
  dryRun?: boolean
  fixPreviousUpgrade?: boolean
  upgradedAt?: string
  zeroDates?: string
  /** C1: el operador CONFIRMA que todos los procesos 1.x están parados (obligatoria con `--force` donde se convierte). */
  confirmLegacyStopped?: boolean
  /** P1: el operador DECLARA que la base nació en 2.x (nunca tuvo datos de 1.x). */
  declareBornIn2?: boolean
}

export interface Upgrade1xLine {
  level: 'info' | 'warning' | 'error' | 'success'
  message: string
}

export interface Upgrade1xPlan {
  state: Upgrade1xStateKey
  /** `noop` (nada que hacer, exit 0), `refuse` (exit 1, nada escrito) o `run` (hay pasos). */
  action: 'noop' | 'refuse' | 'run'
  /** `run` con `--force`: se ejecutan los pasos. `run` sin él es la simulación (exit 0, cero escrituras). */
  write: boolean
  exitCode: 0 | 1
  /** La zona con la que se convierte (bandera o marcador). */
  zone: string | null
  upgradedAtMs: number | null
  steps: Upgrade1xStep[]
  /** La primera es SIEMPRE `estado: <clave> · …`. */
  lines: Upgrade1xLine[]
}

/* ── La función PURA ───────────────────────────────────────────────────────── */

/** Los modos del marcador que este comando escribe. */
const MARKER_MODES = new Set(['upgrade', 'fix-previous', 'born'])

/** La zona que guarda el marcador `born`: 2.x siempre escribió UTC (columna `zone` NOT NULL). */
export const UPGRADE_1X_BORN_ZONE = '+00:00'

/** La letra de la negativa de born con rastro de 1.x (rotación 3 · cierre 5, B1/B1-bis). */
export const UPGRADE_1X_BORN_TRACE_TEXT = 'hay rastro de 1.x, born no aplica'

/**
 * Los RASTROS de 1.x que el comando DETECTA en una base con `expires_at` ya `datetime(3)` y sin marcador (rotación 3 ·
 * cierre 5, B1/B1-bis). Ninguna migración publicada de 2.x deja un paso de esquema pendiente (crean `authz_catalog_version`
 * con sus dos filas, `owner_scope_key` con el unique de tres columnas, `assignable_at` y las columnas `utf8mb4_bin`), y el
 * codec de 2.x no escribe fechas cero. Sin ninguno de los dos, una base nacida en 2.x y una subida entera con el bloque
 * viejo tienen la misma forma: ahí `--declare-born-in-2` sigue siendo una DECLARACIÓN del operador.
 */
export function upgrade1xLegacyTraces(state: Pick<Upgrade1xState, 'pendingDdl' | 'unreadable'>): string[] {
  const traces: string[] = []
  if (state.pendingDdl.length > 0) traces.push(`DDL de 1.x pendiente (${state.pendingDdl.join(', ')})`)
  if (state.unreadable > 0) traces.push(`${state.unreadable} caducidad(es) ilegible(s) (fecha cero: el codec de 2.x no las escribe)`)
  return traces
}

/**
 * La precondición de C1, en una frase: la usan la negativa, la línea del plan y la simulación. Un proceso 1.x vivo tras
 * la conversión escribe la PARED de su zona en el `datetime(3)` que 2.x lee como UTC, y ya nada lo detecta.
 */
export const UPGRADE_1X_LEGACY_STOPPED_TEXT =
  'para TODOS los procesos 1.x antes de --force (y no hagas un rolling deploy 1.x → 2.x sobre MySQL): un proceso 1.x que ' +
  'siga vivo tras la conversión escribe su hora LOCAL en una columna que 2.x lee como UTC — al ESTE de UTC (Madrid) cada ' +
  'caducidad suya concede 1-2 h DESPUÉS de caducar (fail-open), al oeste 2.x la ve caducar antes — y este comando no lo ' +
  'puede detectar después: el marcador ya dice «hecho»'
const MARKER_STATES = new Set(['armed', 'done'])

/** El instante en el que `--zero-dates=expire` deja una caducidad ilegible: PASADO, nunca `NULL` (A2). */
export const UPGRADE_1X_EXPIRED_INSTANT = 86_400

/** `--upgraded-at` exige ISO con zona explícita (`Z` o `±hh:mm`): sin ella JavaScript la leería en la hora local. */
export function parseUpgradedAt(value: string | undefined): number | null {
  if (value === undefined) return null
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) return null
  const ms = Date.parse(value)
  return Number.isNaN(ms) ? null : ms
}

/** El prefijo de UUIDv7 de un milisegundo (`xxxxxxxx-xxxx`): las filas insertadas antes ordenan por debajo, por bytes. */
export function v7Prefix(ms: number): string {
  const hex = Math.floor(ms).toString(16).padStart(12, '0')
  return `${hex.slice(0, 8)}-${hex.slice(8)}`
}

const STEP_TEXT: Record<Upgrade1xStep, string> = {
  'zero-dates': 'las caducidades ilegibles (fecha cero) pasan a un instante PASADO (--zero-dates=expire): caducadas, nunca NULL',
  'marker-table': 'crea la tabla del marcador authz_upgrade_1x (si no existe), ENGINE=InnoDB',
  'marker-arm': 'ARMA el marcador (fila expires_at, estado armed, con la zona) — solo porque expires_at sigue siendo timestamp',
  'collation-roles': 'authz_roles: slug y scope_type a utf8mb4_bin',
  'collation-permissions': 'authz_permissions: slug a utf8mb4_bin',
  assignments: 'authz_assignments: identidad a varchar(64) utf8mb4_bin y expires_at a datetime(3), en la zona de sesión de 1.x (@@global.time_zone)',
  'collation-denies': 'authz_denies: identidad a varchar(64) utf8mb4_bin',
  convert: 'CONVIERTE cada caducidad de la zona de 1.x a UTC y marca el paso hecho, en UNA transacción',
  'fix-previous': 'CORRIGE solo las filas de 1.x (UUIDv7 anterior a --upgraded-at) y solo hacia ANTES, y marca hecho, en UNA transacción',
  born: 'escribe el marcador done/born (DECLARACIÓN del operador: la base nació en 2.x) — ninguna fila de datos se toca',
  'catalog-version': 'crea authz_catalog_version con las filas 1 y 2 (versión 0)',
  'roles-owner': 'authz_roles: owner_scope_key (default global) y el unique de tres columnas',
  'permissions-assignable': 'authz_permissions: assignable_at',
}

export function describeUpgrade1xStep(step: Upgrade1xStep): string {
  return STEP_TEXT[step]
}

/**
 * Decide, sin I/O, qué hacer con el estado detectado. Tabla de verdad (la fija `command_flags_upgrade_1x.spec.ts`):
 *
 * | `expires_at` | marcador | otras entradas | estado | acción |
 * |---|---|---|---|---|
 * | (no MySQL) | — | — | `no-mysql` | noop, exit 0, cero sentencias |
 * | falta una tabla de 1.x | — | — | `sin-tablas` | negativa |
 * | `timestamp` | ninguno | sin `authz_catalog_version` | `1x-sin-subir` | subida completa; exige `--zone` |
 * | `timestamp` | `armed` | sin `authz_catalog_version` | `a-medias` | reanuda con la zona del marcador |
 * | `timestamp` | `done` | — | `incoherente` (B2: volcado de 1.x restaurado) | negativa |
 * | `timestamp` | ninguno/`armed` | con `authz_catalog_version` | `incoherente` (2.x pudo escribir en la columna de 1.x) | negativa |
 * | `datetime(3)` | ninguno | alguna caducidad o DDL pendiente | `receta-vieja` | negativa; con `--fix-previous-upgrade` corrige |
 * | `datetime(3)` | ninguno | ninguna caducidad y nada pendiente | `hecho` | noop |
 * | `datetime(3)` | `armed` | sin `authz_catalog_version` | `a-medias` | convierte y termina |
 * | `datetime(3)` | `done` | DDL pendiente | `a-medias` | termina el DDL |
 * | `datetime(3)` | `done` | nada pendiente | `hecho` | noop (otra `--zone` ⇒ negativa) |
 * | otro tipo, marcador con otra forma, índices a medias | | | `incoherente` | negativa |
 * | (cualquiera) | (cualquiera) | `authz_assignments` o el marcador no son InnoDB | `motor-no-transaccional` (C2) | negativa |
 * | `datetime(3)` | ninguno | `--declare-born-in-2`, sin rastro de 1.x | `receta-vieja` / `hecho` | escribe el marcador `done`/`born`, cero datos (P1) |
 * | `datetime(3)` | ninguno | `--declare-born-in-2` + DDL pendiente o fechas cero | `receta-vieja` | negativa: «hay rastro de 1.x, born no aplica» (B1) |
 * | (cualquiera) | (cualquiera) | `--declare-born-in-2` + `--zero-dates`/`--confirm-legacy-stopped`/`--zone`/fix | | negativa (H4) |
 *
 * Y en todo estado que convierte: zona desconocida para MySQL ⇒ negativa ANTES de tocar nada; caducidades ilegibles ⇒
 * negativa salvo `--zero-dates=expire`; con `--force`, sin `--confirm-legacy-stopped` ⇒ negativa (C1). Escribir exige
 * `--force`; sin él es la simulación (que menciona la precondición).
 */
export function upgrade1xPlan(state: Upgrade1xState, flags: Upgrade1xFlags): Upgrade1xPlan {
  const lines: Upgrade1xLine[] = []
  const done = (
    key: Upgrade1xStateKey,
    action: Upgrade1xPlan['action'],
    extra: Partial<Pick<Upgrade1xPlan, 'zone' | 'upgradedAtMs' | 'steps' | 'write'>> = {}
  ): Upgrade1xPlan => ({
    state: key,
    action,
    write: extra.write ?? false,
    exitCode: action === 'refuse' ? 1 : 0,
    zone: extra.zone ?? null,
    upgradedAtMs: extra.upgradedAtMs ?? null,
    steps: extra.steps ?? [],
    lines,
  })
  const head = (key: Upgrade1xStateKey, text: string) => lines.unshift({ level: 'info', message: `estado: ${key} · ${text}` })
  const refuse = (key: Upgrade1xStateKey, message: string) => {
    lines.push({ level: 'error', message })
    lines.push({ level: 'error', message: 'No se ha escrito nada.' })
    return done(key, 'refuse')
  }

  /* 1 · Fuera de MySQL: nada que hacer, nada que leer. */
  if (state.dialect !== 'mysql' && state.dialect !== 'mysql2') {
    head(
      'no-mysql',
      `la conexión '${state.connection}' es ${state.dialect}: este comando solo sube MySQL. PostgreSQL sube con su receta ` +
        'SQL del README (1.x ya guardaba timestamptz: no hay nada que convertir) y SQLite no necesita nada. ' +
        'No se ha ejecutado ninguna sentencia.'
    )
    const ignored = [
      flags.zone !== undefined ? `--zone=${flags.zone}` : null,
      flags.force ? '--force' : null,
      flags.dryRun ? '--dry-run' : null,
      flags.fixPreviousUpgrade ? '--fix-previous-upgrade' : null,
      flags.upgradedAt !== undefined ? `--upgraded-at=${flags.upgradedAt}` : null,
      flags.zeroDates !== undefined ? `--zero-dates=${flags.zeroDates}` : null,
      flags.confirmLegacyStopped ? '--confirm-legacy-stopped' : null,
      flags.declareBornIn2 ? '--declare-born-in-2' : null,
    ].filter((x): x is string => x !== null)
    if (ignored.length > 0) lines.push({ level: 'info', message: `Banderas recibidas y sin efecto fuera de MySQL: ${ignored.join(', ')}.` })
    return done('no-mysql', 'noop')
  }

  /* 2 · Clasificar. */
  if (state.missingTables.length > 0) {
    head('sin-tablas', `faltan ${state.missingTables.join(', ')} en la base de la conexión '${state.connection}': no hay un esquema de 1.x que subir.`)
    return refuse('sin-tablas', 'Una instalación nueva usa la migración publicada (node ace configure), no este comando.')
  }
  /* C2 · antes de clasificar nada: sin InnoDB, «una transacción» no es todo o nada y una re-ejecución convertiría dos veces. */
  const nonTransactional = state.nonTransactional ?? []
  if (nonTransactional.length > 0) {
    head(
      'motor-no-transaccional',
      `${nonTransactional.join(', ')}: la conversión y su marcador van en UNA transacción, y fuera de InnoDB un ROLLBACK no ` +
        'deshace nada — un corte entre las dos escrituras dejaría las caducidades convertidas con el marcador sin cerrar, y la ' +
        're-ejecución las convertiría OTRA vez (o al revés: marcador hecho sin conversión).'
    )
    return refuse(
      'motor-no-transaccional',
      `Pasa esas tablas a InnoDB y repite: ${nonTransactional.map((t) => `ALTER TABLE ${t.split(' ')[0]} ENGINE=InnoDB;`).join(' ')} ` +
        '(MyISAM ignora en silencio las claves foráneas: tras el ALTER, compara las de authz_assignments con las de la migración de 1.x).'
    )
  }
  const odd: string[] = [...state.schemaOdd]
  let marker: Upgrade1xMarker | null = null
  if (state.marker === 'malformed') {
    odd.push('la tabla authz_upgrade_1x existe con otra forma (no la escribió este comando)')
  } else if (state.marker !== null) {
    const rows = state.marker
    if (rows.length > 1 || rows.some((r) => r.step !== 'expires_at' || !MARKER_STATES.has(r.state) || !MARKER_MODES.has(r.mode) || !r.zone)) {
      odd.push(`el marcador authz_upgrade_1x tiene filas que este comando no escribe: ${JSON.stringify(rows)}`)
    } else if (rows.length === 1) {
      marker = rows[0]
      if (marker.mode === 'fix-previous' && marker.state !== 'done') odd.push('el marcador de una corrección está a medias (la corrección es una sola transacción)')
      if (marker.mode === 'born' && marker.state !== 'done') odd.push('el marcador de una base declarada nacida en 2.x está a medias (se escribe ya hecho)')
    }
  }
  const type = state.expiresType
  const isTimestamp = type === 'timestamp'
  const isDatetime3 = type === 'datetime(3)'
  if (!isTimestamp && !isDatetime3) odd.push(`authz_assignments.expires_at es ${type ?? 'inexistente'} (ni el timestamp de 1.x ni el datetime(3) de 2.x)`)
  if (isTimestamp && marker?.state === 'done') {
    odd.push(
      'el marcador dice que la conversión ya se hizo, pero expires_at vuelve a ser el TIMESTAMP de 1.x: ¿se restauró un volcado de ' +
        '1.x de las tablas authz_* después de subir? Convertir con ese marcador dejaría la pared de 1.x sin convertir (B2)'
    )
  }
  if ((isTimestamp || marker?.state === 'armed') && state.catalogVersionTable && marker?.state !== 'done') {
    odd.push(
      'authz_catalog_version existe pero la conversión no se ha hecho: un proceso 2.x puede haber escrito caducidades en UTC que ' +
        'la conversión movería (este comando crea esa tabla DESPUÉS de convertir)'
    )
  }

  if (odd.length > 0) {
    head('incoherente', `una combinación que ningún punto de corte de este comando produce: ${odd.join('; ')}.`)
    return refuse(
      'incoherente',
      'El comando no adivina: revisa la base (y, si restauraste 1.x, borra authz_upgrade_1x para volver a subir desde cero) y repite.'
    )
  }

  const traces = upgrade1xLegacyTraces(state)
  let key: Upgrade1xStateKey
  if (isTimestamp) key = marker === null ? '1x-sin-subir' : 'a-medias'
  else if (marker === null) key = state.expiring === 0 && state.pendingDdl.length === 0 ? 'hecho' : 'receta-vieja'
  else if (marker.state === 'armed') key = 'a-medias'
  else key = state.pendingDdl.length === 0 ? 'hecho' : 'a-medias'

  const describe: Record<Exclude<Upgrade1xStateKey, 'no-mysql' | 'sin-tablas' | 'incoherente' | 'motor-no-transaccional'>, () => string> = {
    '1x-sin-subir': () =>
      `expires_at es el TIMESTAMP de 1.x y no hay marcador: subida completa (${state.expiring} caducidad(es) que convertir).`,
    'a-medias': () =>
      `una ejecución anterior de este comando se cortó: marcador ${marker!.state} (zona ${marker!.zone}), expires_at ${type}` +
        (state.pendingDdl.length ? `, DDL pendiente: ${state.pendingDdl.join(', ')}` : '') +
        '. Se reanuda desde donde se quedó.',
    'receta-vieja': () =>
      'expires_at ya es datetime(3) y no hay marcador: esta base se subió de 1.x con el bloque SQL publicado de 2.4.0-alpha.1 a ' +
      '2.5.0-rc.1 (que no convertía) — o nació en 2.x. ' +
      (traces.length > 0
        ? `Hay rastro de 1.x: ${traces.join('; ')} — no nació en 2.x. `
        : 'Sin rastro de 1.x que el comando detecte (DDL de 1.x pendiente, caducidades ilegibles): con esa forma las dos son ' +
          'iguales y nacer en 2.x es algo que solo el operador puede declarar. ') +
      `${state.expiring} fila(s) con caducidad.`,
    hecho: () =>
      marker === null
        ? 'expires_at ya es datetime(3), no hay marcador y ninguna fila tiene caducidad: no hay nada que convertir.'
        : marker.mode === 'born'
          ? 'base DECLARADA nacida en 2.x (marcador born, --declare-born-in-2): no hay nada que convertir, y el esquema es el de 2.x.'
          : `subida hecha: marcador ${marker.mode === 'fix-previous' ? 'de la corrección' : 'de la subida'} con la zona ${marker.zone}` +
            (marker.upgradedAt ? ` y --upgraded-at=${marker.upgradedAt}` : '') +
            ', y el esquema es el de 2.x.',
  }
  head(key, describe[key as keyof typeof describe]())

  /* 3 · Errores de uso (cualquier estado de MySQL). */
  if (flags.force && flags.dryRun) return refuse(key, '--force y --dry-run a la vez: elige uno (sin --force ya es la simulación).')
  if (flags.zeroDates !== undefined && flags.zeroDates !== 'expire') {
    return refuse(key, `--zero-dates=${flags.zeroDates}: el único valor es 'expire' (las caducidades ilegibles quedan en un instante PASADO).`)
  }
  if (flags.upgradedAt !== undefined && !flags.fixPreviousUpgrade) {
    return refuse(key, '--upgraded-at solo tiene sentido con --fix-previous-upgrade.')
  }
  if (flags.declareBornIn2 && (flags.fixPreviousUpgrade || flags.zone !== undefined)) {
    return refuse(
      key,
      '--declare-born-in-2 no convierte nada: va sin --zone y sin --fix-previous-upgrade (son las dos salidas OPUESTAS de ' +
        'receta-vieja; elige una).'
    )
  }
  /* H4 (cierre 5) · con born, las banderas de la conversión no tienen efecto: se rechazan, no se tragan en silencio. */
  if (flags.declareBornIn2) {
    const inert = [
      flags.zeroDates !== undefined ? `--zero-dates=${flags.zeroDates}` : null,
      flags.confirmLegacyStopped ? '--confirm-legacy-stopped' : null,
      flags.upgradedAt !== undefined ? `--upgraded-at=${flags.upgradedAt}` : null,
    ].filter((x): x is string => x !== null)
    if (inert.length > 0) {
      return refuse(
        key,
        `--declare-born-in-2 no convierte nada: ${inert.join(', ')} no tiene(n) efecto con ella (son banderas de la ` +
          'conversión). Quítala(s) y repite; born solo admite --force o --dry-run.'
      )
    }
  }

  /* P1 · la DECLARACIÓN del operador: solo sin rastro de 1.x (columna timestamp, un marcador, DDL pendiente, fechas cero). */
  if (flags.declareBornIn2) {
    if (isTimestamp) {
      return refuse(
        key,
        '--declare-born-in-2: expires_at es todavía el TIMESTAMP de 1.x — esta base tiene el esquema de 1.x, no nació en 2.x. ' +
          'Súbela con --zone (y --confirm-legacy-stopped).'
      )
    }
    if (marker !== null) {
      return refuse(
        key,
        `--declare-born-in-2: ya hay un marcador (${marker.mode}, ${marker.state}): este comando ya trabajó sobre esta base, así ` +
          'que vino de 1.x o ya está declarada. No se declara encima.'
      )
    }
    /* B1/B1-bis (cierre 5) · el comando SÍ ve 1.x: DDL de 1.x pendiente o fechas cero ⇒ la declaración es refutable. */
    if (traces.length > 0) {
      return refuse(
        key,
        `--declare-born-in-2: ${UPGRADE_1X_BORN_TRACE_TEXT} — ${traces.join('; ')}. Ninguna migración publicada de 2.x deja ` +
          'un paso de esquema pendiente ni escribe fechas cero, así que esta base vino de 1.x: su salida es la corrección ' +
          '(--fix-previous-upgrade; sin --force, la simulación te dice qué movería).'
      )
    }
    lines.push({
      level: 'warning',
      message:
        'Declaras que esta base NACIÓ en 2.x: ninguna fila la escribió un proceso 1.x. El comando NO puede demostrarlo (no ve ' +
        'rastro de 1.x —ni DDL de 1.x pendiente ni fechas cero—, pero una base subida entera con el bloque viejo tiene la misma ' +
        'forma); si es falso, las caducidades de 1.x quedan desplazadas el offset ' +
        'de su zona para siempre (al este, fail-open) y este comando dirá «hecho». Ningún dato se toca.',
    })
    return planned(key, ['marker-table', 'born'], UPGRADE_1X_BORN_ZONE, null)
  }

  /* 4 · Por estado. */
  if (key === 'hecho') {
    if (marker?.mode === 'born' && flags.zone !== undefined && flags.zone !== marker.zone) {
      return refuse(
        key,
        `pediste --zone=${flags.zone} y esta base está DECLARADA nacida en 2.x (marcador born): no hay nada de 1.x que convertir. ` +
          'Si la declaración era falsa, la corrección se aplica a mano a las filas de 1.x (README, «If the zone was wrong»).'
      )
    }
    if (marker !== null && flags.zone !== undefined && flags.zone !== marker.zone) {
      return refuse(
        key,
        `pediste --zone=${flags.zone} y la conversión ya se hizo con ${marker.zone}: este comando no convierte dos veces. Si la zona ` +
          'de entonces era errónea, la diferencia se aplica a mano a las filas de 1.x (README, «If the zone was wrong»).'
      )
    }
    lines.push({ level: 'success', message: 'Nada que hacer.' })
    return done(key, 'noop', { zone: marker?.zone ?? null })
  }

  const unreadableGuard = (): Upgrade1xPlan | null => {
    if (state.unreadable === 0 || flags.zeroDates === 'expire') return null
    return refuse(
      key,
      `${state.unreadable} fila(s) de authz_assignments tienen una caducidad que MySQL no puede leer (fecha cero 0000-00-00 o un mes/día ` +
        'cero, lo que 1.x dejaba con un sql_mode no estricto al escribir más allá de 2038). En 1.x esas filas NO concedían; convertirlas ' +
        'daría NULL, que en 2.x es «sin caducidad» = PERMANENTE (A2). Repite con --zero-dates=expire para dejarlas caducadas (un ' +
        'instante pasado, nunca NULL), o corrígelas tú antes.'
    )
  }
  const zoneGuard = (zone: string): Upgrade1xPlan | null => {
    if (state.zones[zone] === true) {
      if (/^[+-]\d{2}:\d{2}$/.test(zone) && zone !== '+00:00' && zone !== '-00:00') {
        lines.push({
          level: 'warning',
          message: `--zone=${zone} es un offset FIJO: si la zona de los procesos 1.x tenía horario de verano, usa su nombre (Europe/Madrid) o las caducidades del otro lado del cambio quedan una hora mal.`,
        })
      }
      return null
    }
    return refuse(
      key,
      `MySQL no convierte la zona '${zone}' (CONVERT_TZ da NULL): o no existe, o es un nombre y el servidor no tiene cargadas las ` +
        "tablas de zonas (mysql_tzinfo_to_sql). 'Z' se escribe '+00:00'. Nada se ha tocado: carga las tablas o usa la zona correcta."
    )
  }

  if (key === 'receta-vieja') {
    if (!flags.fixPreviousUpgrade && traces.length > 0) {
      return refuse(
        key,
        `Esta base vino de 1.x (${traces.join('; ')}): ${UPGRADE_1X_BORN_TRACE_TEXT}, y la conversión no se hace por defecto. ` +
          'Si tus procesos 1.x no serializaban las fechas en UTC, cada caducidad que escribió 1.x quedó desplazada el offset de ' +
          'su zona (al ESTE de UTC, Madrid +1/+2 h, concede ese tiempo DESPUÉS de caducar: fail-open; al oeste caduca antes) y la ' +
          'corrección es --fix-previous-upgrade --zone=<zona de los procesos 1.x> --upgraded-at=<ISO: el instante en que dejó de ' +
          'escribir el ÚLTIMO proceso 1.x; mejor tarde que pronto> --confirm-legacy-stopped --force (solo filas anteriores a ese ' +
          'instante, solo hacia ANTES; termina también el DDL pendiente).' +
          (state.unreadable > 0 ? ' Con fechas cero, añade --zero-dates=expire.' : '')
      )
    }
    if (!flags.fixPreviousUpgrade) {
      return refuse(
        key,
        'El comando no ve rastro de 1.x (ni DDL de 1.x pendiente ni fechas cero) y no puede saber si esta base vino de 1.x, ' +
          'y por eso no convierte nada por defecto. Hay DOS salidas, y la ' +
          'elección es tuya: (1) si la base NACIÓ en 2.x (ningún proceso 1.x escribió nunca en ella): --declare-born-in-2 --force ' +
          '— escribe el marcador y no toca ningún dato; es tu declaración. (2) si vino de 1.x y la subiste con el bloque viejo, ' +
          'y tus procesos 1.x no serializaban las fechas en UTC: cada caducidad que escribió 1.x quedó desplazada el offset de su ' +
          'zona (al ESTE de UTC, Madrid +1/+2 h, concede ese tiempo DESPUÉS de caducar: fail-open; al oeste caduca antes) y la ' +
          'corrección es --fix-previous-upgrade --zone=<zona de los procesos 1.x> --upgraded-at=<ISO: el instante en que dejó de ' +
          'escribir el ÚLTIMO proceso 1.x; mejor tarde que pronto> --confirm-legacy-stopped --force (solo filas anteriores a ese ' +
          'instante, solo hacia ANTES). La corrección sobre una base que nació en 2.x adelantaría sus caducidades (fail-closed ' +
          'masivo): no la uses «para ponerlo en verde».'
      )
    }
    if (flags.zone === undefined) return refuse(key, '--fix-previous-upgrade exige --zone (la zona de tus procesos 1.x; no hay default).')
    if (flags.upgradedAt === undefined) {
      return refuse(
        key,
        '--fix-previous-upgrade exige --upgraded-at=<ISO con Z u offset> (el instante en que dejó de escribir el último proceso 1.x; no hay default).'
      )
    }
    const at = parseUpgradedAt(flags.upgradedAt)
    if (at === null) {
      return refuse(key, `--upgraded-at=${flags.upgradedAt} no es un instante ISO con zona explícita (p. ej. 2026-08-01T10:00:00Z).`)
    }
    if (at > state.nowMs) {
      return refuse(key, `--upgraded-at=${flags.upgradedAt} está en el FUTURO: no es el instante en que dejó de escribir el último proceso 1.x.`)
    }
    if (state.oldestV7Ms === null) {
      return refuse(key, 'ninguna fila de authz_assignments tiene un uuid v7: no se puede saber cuáles escribió 1.x. Nada que corregir con certeza.')
    }
    if (at <= state.oldestV7Ms) {
      return refuse(
        key,
        `--upgraded-at=${flags.upgradedAt} es anterior (o igual) a la fila más antigua (${new Date(state.oldestV7Ms).toISOString()}): no ` +
          'corregiría ninguna y dejaría el marcador «hecho» (B1). Da el instante en que dejó de escribir el último proceso 1.x, mejor ' +
          'tarde que pronto.'
      )
    }
    const guard = zoneGuard(flags.zone) ?? unreadableGuard()
    if (guard) return guard
    lines.push({
      level: 'info',
      message:
        `Corrección: ${state.fixBefore ?? '?'} fila(s) con caducidad insertadas antes de ${new Date(at).toISOString()} (de 1.x); ` +
        `${state.fixCandidates ?? '?'} se adelantan de ${flags.zone} a UTC y las demás no se tocan` +
        (state.fixCandidates === 0 ? ' (una zona al oeste de UTC no mueve nada: esas filas ya caducan antes, fail-closed).' : '.') +
        ' Una fila de 1.x que 2.x reescribió después también se adelanta (caduca antes: fail-closed; re-concédela).',
    })
    if (state.nonV7 > 0) {
      lines.push({ level: 'warning', message: `${state.nonV7} fila(s) sin uuid v7: se comparan por bytes y, si caen antes, solo se adelantan.` })
    }
    const steps: Upgrade1xStep[] = [
      ...(state.unreadable > 0 ? (['zero-dates'] as const) : []),
      'marker-table',
      ...state.pendingDdl,
      'fix-previous',
    ]
    return planned(key, steps, flags.zone, at)
  }

  if (flags.fixPreviousUpgrade) {
    return refuse(key, `--fix-previous-upgrade solo vale para una base subida con el bloque viejo (estado receta-vieja), y esta está en ${key}.`)
  }

  if (key === '1x-sin-subir') {
    if (flags.zone === undefined) {
      return refuse(
        key,
        '--zone es obligatoria (sin default): la zona en la que tus procesos 1.x serializaban las fechas — la opción timezone de su ' +
          "conexión MySQL si la fijaron ('Z' es '+00:00'), si no el TZ del proceso Node. Con horario de verano, por nombre " +
          "(Europe/Madrid). Un proceso en UTC: --zone=+00:00."
      )
    }
    const guard = zoneGuard(flags.zone) ?? unreadableGuard()
    if (guard) return guard
    const steps: Upgrade1xStep[] = [
      ...(state.unreadable > 0 ? (['zero-dates'] as const) : []),
      'marker-table',
      'marker-arm',
      ...state.pendingDdl.filter((s) => (UPGRADE_1X_PRE_CONVERT_DDL as readonly string[]).includes(s)),
      'convert',
      ...state.pendingDdl.filter((s) => (UPGRADE_1X_POST_CONVERT_DDL as readonly string[]).includes(s)),
    ]
    return planned(key, steps, flags.zone, null)
  }

  // a-medias
  const zone = marker!.zone!
  if (flags.zone !== undefined && flags.zone !== zone) {
    return refuse(
      key,
      `la ejecución cortada armó la conversión con --zone=${zone} y ahora pides ${flags.zone}: se reanuda SIEMPRE con la zona del ` +
        'marcador (o sin --zone). Si la de entonces era errónea, todavía no se ha convertido nada: borra la fila de authz_upgrade_1x ' +
        'SOLO si expires_at sigue siendo timestamp.'
    )
  }
  if (marker!.state === 'armed') {
    const guard = zoneGuard(zone) ?? unreadableGuard()
    if (guard) return guard
  }
  const steps: Upgrade1xStep[] =
    marker!.state === 'armed'
      ? [
          ...(state.unreadable > 0 ? (['zero-dates'] as const) : []),
          ...state.pendingDdl.filter((s) => (UPGRADE_1X_PRE_CONVERT_DDL as readonly string[]).includes(s)),
          'convert',
          ...state.pendingDdl.filter((s) => (UPGRADE_1X_POST_CONVERT_DDL as readonly string[]).includes(s)),
        ]
      : [...state.pendingDdl]
  return planned(key, steps, zone, null)

  function planned(key: Upgrade1xStateKey, steps: Upgrade1xStep[], zone: string, upgradedAtMs: number | null): Upgrade1xPlan {
    const converts = steps.some((s) => UPGRADE_1X_CONVERTING_STEPS.includes(s))
    // C1 · la precondición, en el plan: antes de los pasos, para que se lea ANTES de decidir el --force.
    if (converts) {
      lines.push({
        level: flags.confirmLegacyStopped ? 'info' : 'warning',
        message:
          `Precondición (C1): ${UPGRADE_1X_LEGACY_STOPPED_TEXT}. ` +
          (flags.confirmLegacyStopped
            ? 'Confirmada con --confirm-legacy-stopped.'
            : '--force exige --confirm-legacy-stopped, que es TU confirmación de que no queda ninguno.'),
      })
    }
    steps.forEach((step, i) => lines.push({ level: 'info', message: `plan ${i + 1}/${steps.length} · ${step}: ${STEP_TEXT[step]}` }))
    if (!flags.force) {
      lines.push({ level: 'warning', message: 'Simulación (--dry-run por defecto): no se ha escrito nada. Repite con --force para ejecutarlo.' })
      return done(key, 'run', { zone, upgradedAtMs, steps, write: false })
    }
    if (converts && !flags.confirmLegacyStopped) {
      return refuse(
        key,
        `--force convierte caducidades y falta --confirm-legacy-stopped. Precondición: ${UPGRADE_1X_LEGACY_STOPPED_TEXT}. Para ` +
          'todos los procesos 1.x, comprueba que ninguno escribe, y repite la MISMA línea con --confirm-legacy-stopped.'
      )
    }
    return done(key, 'run', { zone, upgradedAtMs, steps, write: true })
  }
}

/* ── Lectura del estado (MySQL, una sesión) ───────────────────────────────── */

type Query = (sql: string, bindings?: unknown[]) => Promise<any[]>

/** Columnas que la subida deja en `utf8mb4_bin` con este tipo (lo que produce el ALTER y la migración publicada). */
const BIN_COLUMNS: Array<{ table: string; column: string; type: string; step: Upgrade1xDdl }> = [
  { table: 'authz_roles', column: 'slug', type: 'varchar(100)', step: 'collation-roles' },
  { table: 'authz_roles', column: 'scope_type', type: 'varchar(20)', step: 'collation-roles' },
  { table: 'authz_permissions', column: 'slug', type: 'varchar(100)', step: 'collation-permissions' },
  { table: 'authz_assignments', column: 'holder_type', type: 'varchar(50)', step: 'assignments' },
  { table: 'authz_assignments', column: 'holder_uuid', type: 'varchar(64)', step: 'assignments' },
  { table: 'authz_assignments', column: 'scope_type', type: 'varchar(20)', step: 'assignments' },
  { table: 'authz_assignments', column: 'scope_uuid', type: 'varchar(64)', step: 'assignments' },
  { table: 'authz_denies', column: 'holder_type', type: 'varchar(50)', step: 'collation-denies' },
  { table: 'authz_denies', column: 'holder_uuid', type: 'varchar(64)', step: 'collation-denies' },
  { table: 'authz_denies', column: 'scope_type', type: 'varchar(20)', step: 'collation-denies' },
  { table: 'authz_denies', column: 'scope_uuid', type: 'varchar(64)', step: 'collation-denies' },
]
const LEGACY_TABLES = ['authz_roles', 'authz_permissions', 'authz_assignments', 'authz_denies']
const MARKER_COLUMNS = ['armed_at', 'done_at', 'mode', 'state', 'step', 'upgraded_at', 'zone']
/** «Ilegible» = presente y `CONVERT_TZ` (la función que convierte) da NULL: fecha cero, mes o día cero (medido en 8.4). */
const UNREADABLE = "expires_at IS NOT NULL AND CONVERT_TZ(expires_at, '+00:00', '+00:00') IS NULL"
const V7 = "LOWER(uuid) REGEXP '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'"

export async function readUpgrade1xState(q: Query, connection: string, flags: Upgrade1xFlags, nowMs: number): Promise<Upgrade1xState> {
  const columns = await q(
    `SELECT table_name AS t, column_name AS c, column_type AS ty, collation_name AS co
       FROM information_schema.columns
      WHERE table_schema = DATABASE()
        AND table_name IN ('authz_roles', 'authz_permissions', 'authz_assignments', 'authz_denies', 'authz_catalog_version', 'authz_upgrade_1x')`
  )
  const col = (table: string, column: string) => columns.find((r: any) => r.t === table && r.c === column) as any
  const tables = new Set(columns.map((r: any) => r.t))
  const missingTables = LEGACY_TABLES.filter((t) => !tables.has(t))
  const base: Omit<Upgrade1xState, 'missingTables'> = {
    connection,
    dialect: 'mysql',
    expiresType: null,
    marker: null,
    pendingDdl: [],
    schemaOdd: [],
    catalogVersionTable: tables.has('authz_catalog_version'),
    expiring: 0,
    unreadable: 0,
    zones: {},
    oldestV7Ms: null,
    nonV7: 0,
    fixBefore: null,
    fixCandidates: null,
    nowMs,
  }
  if (missingTables.length > 0) return { ...base, missingTables }

  // C2 · el motor de las dos tablas que la conversión escribe en UNA transacción (el marcador, solo si existe).
  const engines = await q(
    `SELECT table_name AS t, engine AS e FROM information_schema.tables
      WHERE table_schema = DATABASE() AND table_name IN ('authz_assignments', 'authz_upgrade_1x')`
  )
  const nonTransactional = engines
    .filter((r: any) => String(r.e ?? '').toLowerCase() !== 'innodb')
    .map((r: any) => `${r.t} (${r.e ?? 'sin motor'})`)
    .sort()

  const pending = new Set<Upgrade1xDdl>()
  for (const spec of BIN_COLUMNS) {
    const c = col(spec.table, spec.column)
    if (!c || c.ty !== spec.type || c.co !== 'utf8mb4_bin') pending.add(spec.step)
  }
  const expiresType: string | null = col('authz_assignments', 'expires_at')?.ty ?? null
  if (expiresType !== 'datetime(3)') pending.add('assignments')
  const schemaOdd: string[] = []
  if (base.catalogVersionTable) {
    const [{ n }] = await q('SELECT COUNT(*) AS n FROM authz_catalog_version WHERE id IN (1, 2)')
    if (Number(n) < 2) pending.add('catalog-version')
  } else {
    pending.add('catalog-version')
  }
  const indexes = await q(
    "SELECT DISTINCT index_name AS i FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'authz_roles'"
  )
  const hasIndex = (name: string) => indexes.some((r: any) => r.i === name)
  if (!col('authz_roles', 'owner_scope_key')) {
    pending.add('roles-owner')
    if (!hasIndex('authz_roles_slug_scope_uq')) schemaOdd.push('authz_roles no tiene ni el unique de 1.x ni owner_scope_key')
  } else if (!hasIndex('authz_roles_slug_scope_owner_uq') || hasIndex('authz_roles_slug_scope_uq') || !hasIndex('authz_roles_owner_idx')) {
    schemaOdd.push('authz_roles tiene owner_scope_key pero sus índices no son los de 2.x')
  }
  if (!col('authz_permissions', 'assignable_at')) pending.add('permissions-assignable')

  let marker: Upgrade1xState['marker'] = null
  if (tables.has('authz_upgrade_1x')) {
    const have = columns.filter((r: any) => r.t === 'authz_upgrade_1x').map((r: any) => r.c).sort()
    if (JSON.stringify(have) !== JSON.stringify(MARKER_COLUMNS)) {
      marker = 'malformed'
    } else {
      marker = (
        await q("SELECT step, state, mode, zone, DATE_FORMAT(upgraded_at, '%Y-%m-%dT%H:%i:%s.%fZ') AS up FROM authz_upgrade_1x ORDER BY step")
      ).map((r: any) => ({ step: r.step, state: r.state, mode: r.mode, zone: r.zone, upgradedAt: r.up ? String(r.up).replace(/(\.\d{3})\d{3}Z$/, '$1Z') : null }))
    }
  }

  const [{ expiring, unreadable, nonV7 }] = await q(
    `SELECT COALESCE(SUM(expires_at IS NOT NULL), 0) AS expiring,
            COALESCE(SUM(${UNREADABLE}), 0) AS unreadable,
            COALESCE(SUM(NOT (${V7})), 0) AS nonV7
       FROM authz_assignments`
  )
  const oldest = await q(`SELECT LOWER(uuid) AS u FROM authz_assignments WHERE ${V7} ORDER BY CAST(LOWER(uuid) AS BINARY) LIMIT 1`)
  const oldestV7Ms = oldest.length ? Number.parseInt(String(oldest[0].u).replace('-', '').slice(0, 12), 16) : null

  const zones: Record<string, boolean> = {}
  const markerZones = Array.isArray(marker) ? marker.map((m) => m.zone) : []
  for (const zone of [flags.zone, ...markerZones]) {
    if (zone === undefined || zone === null || zone in zones) continue
    const [{ v }] = await q("SELECT CONVERT_TZ('2030-01-01 00:00:00', ?, '+00:00') AS v", [zone])
    zones[zone] = v !== null
  }

  let fixBefore: number | null = null
  let fixCandidates: number | null = null
  const at = parseUpgradedAt(flags.upgradedAt)
  if (flags.fixPreviousUpgrade && flags.zone !== undefined && zones[flags.zone] && at !== null) {
    const [r] = await q(
      `SELECT COALESCE(SUM(expires_at IS NOT NULL), 0) AS before1x,
              COALESCE(SUM(expires_at IS NOT NULL AND CONVERT_TZ(expires_at, ?, '+00:00') < expires_at), 0) AS moved
         FROM authz_assignments
        WHERE CAST(LOWER(uuid) AS BINARY) < CAST(? AS BINARY)`,
      [flags.zone, v7Prefix(at)]
    )
    fixBefore = Number(r.before1x)
    fixCandidates = Number(r.moved)
  }

  return {
    ...base,
    missingTables,
    nonTransactional,
    expiresType,
    marker,
    pendingDdl: [...UPGRADE_1X_PRE_CONVERT_DDL, ...UPGRADE_1X_POST_CONVERT_DDL].filter((s) => pending.has(s)),
    schemaOdd,
    expiring: Number(expiring),
    unreadable: Number(unreadable),
    zones,
    oldestV7Ms,
    nonV7: Number(nonV7),
    fixBefore,
    fixCandidates,
  }
}

/* ── Ejecución de un paso (MySQL, la misma sesión) ─────────────────────────── */

/** Las sentencias DDL de cada paso: las del bloque MySQL del README hasta 2.5.0-rc.1 (K14 las compara con la migración publicada). */
const DDL: Record<Upgrade1xDdl, string[]> = {
  'collation-roles': [
    `ALTER TABLE authz_roles
       MODIFY slug varchar(100) COLLATE utf8mb4_bin NOT NULL,
       MODIFY scope_type varchar(20) COLLATE utf8mb4_bin NOT NULL`,
  ],
  'collation-permissions': ['ALTER TABLE authz_permissions MODIFY slug varchar(100) COLLATE utf8mb4_bin NOT NULL'],
  assignments: [
    `ALTER TABLE authz_assignments
       MODIFY holder_type varchar(50) COLLATE utf8mb4_bin NOT NULL,
       MODIFY holder_uuid varchar(64) COLLATE utf8mb4_bin NOT NULL,
       MODIFY scope_type varchar(20) COLLATE utf8mb4_bin NOT NULL,
       MODIFY scope_uuid varchar(64) COLLATE utf8mb4_bin NOT NULL,
       MODIFY expires_at datetime(3) NULL`,
  ],
  'collation-denies': [
    `ALTER TABLE authz_denies
       MODIFY holder_type varchar(50) COLLATE utf8mb4_bin NOT NULL,
       MODIFY holder_uuid varchar(64) COLLATE utf8mb4_bin NOT NULL,
       MODIFY scope_type varchar(20) COLLATE utf8mb4_bin NOT NULL,
       MODIFY scope_uuid varchar(64) COLLATE utf8mb4_bin NOT NULL`,
  ],
  'catalog-version': [
    `CREATE TABLE IF NOT EXISTS authz_catalog_version (
       id int NOT NULL PRIMARY KEY,
       version bigint NOT NULL DEFAULT 0,
       updated_at timestamp NOT NULL,
       freeze_reason varchar(255) NULL,
       freeze_holder varchar(120) NULL,
       freeze_until_ms bigint NULL,
       freeze_fence bigint NOT NULL DEFAULT 0
     ) ENGINE=InnoDB`,
    `INSERT INTO authz_catalog_version (id, version, updated_at)
       VALUES (1, 0, CURRENT_TIMESTAMP), (2, 0, CURRENT_TIMESTAMP)
       ON DUPLICATE KEY UPDATE id = id`,
  ],
  'roles-owner': [
    `ALTER TABLE authz_roles
       ADD COLUMN owner_scope_key varchar(80) COLLATE utf8mb4_bin NOT NULL DEFAULT 'global',
       DROP INDEX authz_roles_slug_scope_uq,
       ADD UNIQUE INDEX authz_roles_slug_scope_owner_uq (slug, scope_type, owner_scope_key),
       ADD INDEX authz_roles_owner_idx (owner_scope_key)`,
  ],
  'permissions-assignable': ['ALTER TABLE authz_permissions ADD COLUMN assignable_at varchar(500) NULL'],
}

class StepRefused extends Error {}

/** Una transacción de DML en la sesión: todo o nada (InnoDB; dentro no hay DDL, que haría commit implícito). */
async function inTransaction(q: Query, body: () => Promise<void>): Promise<void> {
  await q('START TRANSACTION')
  try {
    await body()
    await q('COMMIT')
  } catch (error) {
    await q('ROLLBACK').catch(() => {})
    throw error
  }
}

export async function runUpgrade1xStep(q: Query, step: Upgrade1xStep, plan: Upgrade1xPlan): Promise<string> {
  const zone = plan.zone!
  if (step in DDL) {
    for (const sql of DDL[step as Upgrade1xDdl]) await q(sql)
    return 'hecho'
  }
  switch (step) {
    case 'zero-dates': {
      const r: any = await q(`UPDATE authz_assignments SET expires_at = FROM_UNIXTIME(?) WHERE ${UNREADABLE}`, [UPGRADE_1X_EXPIRED_INSTANT])
      return `${r?.affectedRows ?? '?'} fila(s) caducadas`
    }
    case 'marker-table':
      await q(
        `CREATE TABLE IF NOT EXISTS authz_upgrade_1x (
           step varchar(40) COLLATE utf8mb4_bin NOT NULL PRIMARY KEY,
           state varchar(10) NOT NULL,
           mode varchar(20) NOT NULL,
           zone varchar(64) NOT NULL,
           upgraded_at datetime(3) NULL,
           armed_at datetime(3) NOT NULL,
           done_at datetime(3) NULL
         ) ENGINE=InnoDB`
      )
      return 'hecho'
    case 'marker-arm': {
      // Se re-comprueba en la sesión que la columna sigue siendo la de 1.x: armar sobre un datetime sería A1.
      const [{ ty }] = await q(
        "SELECT column_type AS ty FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'authz_assignments' AND column_name = 'expires_at'"
      )
      if (ty !== 'timestamp') throw new StepRefused(`expires_at ya no es timestamp (${ty}): no se arma la conversión`)
      await q(
        "INSERT INTO authz_upgrade_1x (step, state, mode, zone, armed_at) VALUES ('expires_at', 'armed', 'upgrade', ?, UTC_TIMESTAMP(3))",
        [zone]
      )
      return `armado con la zona ${zone}`
    }
    case 'convert': {
      let moved = 0
      await inTransaction(q, async () => {
        const rows = await q("SELECT state, zone FROM authz_upgrade_1x WHERE step = 'expires_at' FOR UPDATE")
        if (rows.length !== 1 || rows[0].state !== 'armed' || rows[0].zone !== zone) {
          throw new StepRefused(`el marcador no está armado con ${zone} (${JSON.stringify(rows)}): no se convierte`)
        }
        const [{ ty }] = await q(
          "SELECT column_type AS ty FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'authz_assignments' AND column_name = 'expires_at'"
        )
        if (ty !== 'datetime(3)') throw new StepRefused(`expires_at es ${ty}, no datetime(3): no se convierte`)
        const [{ n }] = await q(
          "SELECT COUNT(*) AS n FROM authz_assignments WHERE expires_at IS NOT NULL AND CONVERT_TZ(expires_at, ?, '+00:00') IS NULL FOR UPDATE",
          [zone]
        )
        if (Number(n) > 0) throw new StepRefused(`${n} caducidad(es) que CONVERT_TZ no convierte: convertirlas daría NULL (permanente)`)
        const r: any = (await q(
          "UPDATE authz_assignments SET expires_at = CONVERT_TZ(expires_at, ?, '+00:00') WHERE expires_at IS NOT NULL AND CONVERT_TZ(expires_at, ?, '+00:00') IS NOT NULL",
          [zone, zone]
        ))
        moved = Number(r?.affectedRows ?? 0)
        await q("UPDATE authz_upgrade_1x SET state = 'done', done_at = UTC_TIMESTAMP(3) WHERE step = 'expires_at' AND state = 'armed'")
      })
      return `${moved} caducidad(es) convertidas de ${zone} a UTC; marcador hecho`
    }
    case 'born': {
      // P1 · la declaración: un INSERT en el marcador y nada más. Re-comprueba en la sesión lo que el plan ya vio.
      await inTransaction(q, async () => {
        const rows = await q("SELECT state FROM authz_upgrade_1x WHERE step = 'expires_at' FOR UPDATE")
        if (rows.length !== 0) throw new StepRefused(`el marcador ya existe (${JSON.stringify(rows)}): no se declara encima`)
        const [{ ty }] = await q(
          "SELECT column_type AS ty FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'authz_assignments' AND column_name = 'expires_at'"
        )
        if (ty !== 'datetime(3)') throw new StepRefused(`expires_at es ${ty}, no datetime(3): no es una base nacida en 2.x`)
        await q(
          `INSERT INTO authz_upgrade_1x (step, state, mode, zone, armed_at, done_at)
             VALUES ('expires_at', 'done', 'born', ?, UTC_TIMESTAMP(3), UTC_TIMESTAMP(3))`,
          [UPGRADE_1X_BORN_ZONE]
        )
      })
      return 'base declarada nacida en 2.x; ningún dato tocado'
    }
    case 'fix-previous': {
      let moved = 0
      const prefix = v7Prefix(plan.upgradedAtMs!)
      await inTransaction(q, async () => {
        const rows = await q("SELECT state FROM authz_upgrade_1x WHERE step = 'expires_at' FOR UPDATE")
        if (rows.length !== 0) throw new StepRefused(`el marcador ya existe (${JSON.stringify(rows)}): no se corrige dos veces`)
        await q(
          `INSERT INTO authz_upgrade_1x (step, state, mode, zone, upgraded_at, armed_at, done_at)
             VALUES ('expires_at', 'done', 'fix-previous', ?, ?, UTC_TIMESTAMP(3), UTC_TIMESTAMP(3))`,
          [zone, new Date(plan.upgradedAtMs!).toISOString().slice(0, 23).replace('T', ' ')]
        )
        const r: any = (await q(
          `UPDATE authz_assignments SET expires_at = CONVERT_TZ(expires_at, ?, '+00:00')
            WHERE expires_at IS NOT NULL
              AND CAST(LOWER(uuid) AS BINARY) < CAST(? AS BINARY)
              AND CONVERT_TZ(expires_at, ?, '+00:00') IS NOT NULL
              AND CONVERT_TZ(expires_at, ?, '+00:00') < expires_at`,
          [zone, prefix, zone, zone]
        ))
        moved = Number(r?.affectedRows ?? 0)
      })
      return `${moved} caducidad(es) de 1.x adelantadas de ${zone} a UTC; marcador hecho`
    }
  }
  throw new Error(`paso desconocido: ${step}`)
}

/* ── El comando ────────────────────────────────────────────────────────────── */

/**
 *   node ace authz:upgrade-1x --zone=Europe/Madrid             # simulación: estado detectado + plan, cero escrituras
 *   node ace authz:upgrade-1x --zone=Europe/Madrid --confirm-legacy-stopped --force     # sube (re-ejecutable tras un corte)
 *   node ace authz:upgrade-1x --fix-previous-upgrade --zone=Europe/Madrid --upgraded-at=2026-09-01T10:00:00Z --confirm-legacy-stopped --force
 *   node ace authz:upgrade-1x --declare-born-in-2 --force     # base nacida en 2.x: marcador, cero datos
 */
export default class AuthzUpgrade1x extends BaseCommand {
  static commandName = 'authz:upgrade-1x'
  static description = 'Upgrade a 1.x MySQL schema to 2.x (schema + expires_at converted to UTC); dry run unless --force, re-runnable after a cut'

  static options: CommandOptions = {
    startApp: true,
  }

  /**
   * Gancho de TEST (cortes): se llama tras cada paso confirmado; si lanza, el comando se comporta como un proceso
   * cortado ahí (exit 1, lo hecho queda hecho). Nadie lo pone en producción.
   */
  static afterStep: ((step: Upgrade1xStep) => void | Promise<void>) | undefined

  @flags.string({
    description: "Zone your 1.x processes serialised dates in (their mysql2 'timezone' option, else the process TZ; by name if it has DST). Required, no default",
  })
  declare zone: string | undefined

  @flags.boolean({ description: 'Actually write (the default is a dry run that prints the detected state and the plan)' })
  declare force: boolean | undefined

  @flags.boolean({ description: 'Print the detected state and the plan without writing (the default; refused together with --force)' })
  declare dryRun: boolean | undefined

  @flags.boolean({
    description: 'For a database upgraded with the MySQL block of 2.4.0-alpha.1 … 2.5.0-rc.1: correct only the 1.x rows, only earlier',
  })
  declare fixPreviousUpgrade: boolean | undefined

  @flags.string({
    description: 'With --fix-previous-upgrade: when the LAST 1.x process stopped writing (ISO with Z or an offset; later rather than earlier)',
  })
  declare upgradedAt: string | undefined

  @flags.string({ description: "What to do with unreadable 1.x expiries (zero dates): only 'expire' (a past instant, never NULL)" })
  declare zeroDates: string | undefined

  @flags.boolean({
    description:
      'Confirm that EVERY 1.x process is stopped (no rolling deploy 1.x -> 2.x on MySQL). Required with --force wherever expiries are converted',
  })
  declare confirmLegacyStopped: boolean | undefined

  @flags.boolean({
    description:
      'Declare that this database was born on 2.x (no 1.x process ever wrote it): writes the marker, touches no data. Refused where the command sees 1.x (pending 1.x DDL, zero dates). Your declaration, not a proof',
  })
  declare declareBornIn2: boolean | undefined

  @flags.string({ description: 'Lucid connection to upgrade (default: the primary one)' })
  declare connection: string | undefined

  async run() {
    // Perezosos (como los demás comandos): el loader de ace importa este módulo sin app; `sql_expiry` arrastra el `db`.
    const { default: db } = await import('@adonisjs/lucid/services/db')
    const { dialectOf, isMysqlDialect } = await import('../src/shared/sql_expiry.js')
    const name = this.connection ?? db.primaryConnectionName
    const client: any = db.connection(name)
    const flagsIn: Upgrade1xFlags = {
      zone: this.zone,
      force: this.force === true,
      dryRun: this.dryRun === true,
      fixPreviousUpgrade: this.fixPreviousUpgrade === true,
      upgradedAt: this.upgradedAt,
      zeroDates: this.zeroDates,
      confirmLegacyStopped: this.confirmLegacyStopped === true,
      declareBornIn2: this.declareBornIn2 === true,
    }
    const print = (lines: Upgrade1xLine[]) => {
      for (const { level, message } of lines) this.logger[level](message)
    }

    if (!isMysqlDialect(client)) {
      // Ni una sentencia: el estado es solo el dialecto.
      const plan = upgrade1xPlan({ ...emptyState(name, nowMs()), dialect: dialectOf(client) }, flagsIn)
      print(plan.lines)
      this.exitCode = plan.exitCode
      return
    }

    // UNA sesión para todo: `time_zone` y `sql_mode` son de sesión, y el cerrojo con nombre también.
    const knex: any = client.getWriteClient()
    const conn: any = await knex.client.acquireConnection()
    const q: Query = async (sql, bindings = []) => (await knex.raw(sql, bindings).connection(conn))[0]
    let locked = false
    try {
      // La zona de sesión que tenían las conexiones de 1.x (la del servidor) — el MODIFY de expires_at renderiza la pared
      // con ella — y un sql_mode ESTRICTO: nada se trunca en silencio a la fecha cero (RR-3).
      await q('SET time_zone = @@global.time_zone')
      await q("SET SESSION sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'")
      if (flagsIn.force && !flagsIn.dryRun) {
        const [{ l }] = await q("SELECT GET_LOCK(CONCAT('authz_upgrade_1x:', DATABASE()), 0) AS l")
        locked = Number(l) === 1
        if (!locked) {
          this.logger.error('estado: ocupado · otra ejecución de authz:upgrade-1x sobre esta base tiene el cerrojo. No se ha escrito nada.')
          this.exitCode = 1
          return
        }
      }
      const state = await readUpgrade1xState(q, name, flagsIn, nowMs())
      const plan = upgrade1xPlan(state, flagsIn)
      print(plan.lines)
      this.exitCode = plan.exitCode
      if (plan.action !== 'run' || !plan.write) return

      for (const [i, step] of plan.steps.entries()) {
        try {
          const outcome = await runUpgrade1xStep(q, step, plan)
          this.logger.success(`paso ${i + 1}/${plan.steps.length} · ${step}: ${outcome}`)
          await AuthzUpgrade1x.afterStep?.(step)
        } catch (error: any) {
          const message = error?.sqlMessage ?? error?.message ?? String(error)
          this.logger.error(
            `corte en el paso ${i + 1}/${plan.steps.length} · ${step}: ${message}. Lo confirmado hasta aquí queda (en MySQL el DDL no se ` +
              'deshace; la conversión es una transacción: entera o nada). Arregla la causa y repite EL MISMO comando: reanuda desde aquí ' +
              'y nunca convierte dos veces.'
          )
          this.exitCode = 1
          return
        }
      }
      // Autocomprobación: lo que queda tiene que ser «hecho».
      const after = upgrade1xPlan(await readUpgrade1xState(q, name, {}, nowMs()), {})
      if (after.state !== 'hecho') {
        this.logger.error(`tras los pasos la base no está «hecha» sino ${after.lines[0]?.message}. Repórtalo con esta línea.`)
        this.exitCode = 1
        return
      }
      this.logger.success(
        plan.steps.includes('born')
          ? 'Base declarada nacida en 2.x: marcador authz_upgrade_1x escrito (born), ningún dato tocado. Re-ejecutar este comando ' +
              'dice «hecho». No lo borres.'
          : `Subida 1.x → 2.x hecha (${plan.state === 'receta-vieja' ? 'corrección de la subida anterior' : 'esquema + caducidades'}, zona ` +
              `${plan.zone}). El marcador authz_upgrade_1x lo recuerda: re-ejecutar este comando no convierte nada. No lo borres.`
      )
      this.exitCode = 0
    } finally {
      if (locked) await q("SELECT RELEASE_LOCK(CONCAT('authz_upgrade_1x:', DATABASE()))").catch(() => {})
      // La conexión vuelve al pool como llegó (zona y sql_mode del servidor); si no se puede, se destruye.
      try {
        await q('SET time_zone = @@global.time_zone')
        await q('SET SESSION sql_mode = @@global.sql_mode')
        await knex.client.releaseConnection(conn)
      } catch {
        await knex.client.destroyRawConnection?.(conn)?.catch?.(() => {})
      }
    }
  }
}

function nowMs(): number {
  return systemClock().getTime()
}

function emptyState(connection: string, now: number): Upgrade1xState {
  return {
    connection,
    dialect: 'desconocido',
    missingTables: [],
    nonTransactional: [],
    expiresType: null,
    marker: null,
    pendingDdl: [],
    schemaOdd: [],
    catalogVersionTable: false,
    expiring: 0,
    unreadable: 0,
    zones: {},
    oldestV7Ms: null,
    nonV7: 0,
    fixBefore: null,
    fixCandidates: null,
    nowMs: now,
  }
}
