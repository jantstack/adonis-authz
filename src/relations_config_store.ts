/**
 * **La config de relaciones PERSISTIDA** (Fase 4, lote 4-5 · 🟡3) — vive en la
 * tabla `authz_relations_config`, bajo el gate de versión (invariante 14), como
 * el catálogo. Es la copia de la config de relaciones en la BASE, para que
 * cualquier proceso —también uno SIN `defineRelationsConfig` en memoria— lea
 * los tipos declarados. Hoy la CONSUME `authz:relations:reconcile` (la config
 * del DESTINO, para vigilar la deriva del modelo fusionado en `--dry-run`).
 *
 * Este módulo vive en `src/` (NO en `src/relations/`, que la regla 2 de pureza
 * mantiene aislado del `db`): es la ruta que TOCA la base, como `catalog.ts`.
 * Importa el TIPO y el validador de `src/relations/` (la dirección permitida:
 * `relations/` no importa hacia afuera; los demás sí importan de él).
 *
 * **Nota (Fase 4-8):** el modelo fusionado del store lo publica
 * `openfga:provision` leyendo los tipos de relación del CONFIG estático
 * (`relations.config`, como `permissions` sale de `catalogs`), no de esta
 * tabla: el comando es `startApp: false` (bootstrap del appliance, sin base) y
 * no puede leer la base. Por eso el republicador basado en esta tabla (con CAS
 * sobre `model_id`) se retiró en 4-8: no tenía llamador de producción (la
 * carrera que protegía no ocurre; republicar el modelo es un paso manual de
 * operador, escritor único). Ver el informe 4-8. La columna `model_id` queda
 * sin uso (cleanup futuro).
 */
import { systemClock } from './clock.js'
import { AuthorizationConfigError, DenyReachRefusedError, RelationConfigError } from './errors.js'
import { guardSql } from './shared/backend_guard.js'
import db from '@adonisjs/lucid/services/db'
import { invalidateAuthzCatalog, withAuthzCatalogWrite } from './catalog/catalog_cache.js'
import { defineRelationsConfig } from './relations/define_relations_config.js'
import type { RelationsConfig, RelationsConfigSpec } from './relations/define_relations_config.js'
import { DENY_REACH_KEY_PATTERN, deniedPublicRelation, denyReachBaselineOf, denyReachCheck, denyReachKey, denyReachLine, judgeDenyReach } from './relations/deny_reach.js'
import type { DenyReachFinding, LiveDenyGroup } from './relations/deny_reach.js'

const TABLE = 'authz_relations_config'
const ROW_ID = 1
const DEFAULT_TIMEOUT_MS = 5_000

export interface RelationsConfigStoreOptions {
  connection?: string
  timeoutMs?: number
}

/**
 * Opciones de `saveRelationsConfig`: las del store más las DOS salidas con nombre de la guarda del alcance de los denies
 * (8), separadas a propósito (A3 del auditor del panel: una salida que se usa como paso rutinario de adopción y no caduca es
 * un interruptor de apagado).
 */
export interface SaveRelationsConfigOptions extends RelationsConfigStoreOptions {
  /**
   * **La adopción de la línea base** (firma (8 · línea base)): levanta SOLO el motivo `no-baseline`, y SOLO cuando no hay
   * línea base utilizable (sin fila, o una fila que la lectura TODO O NADA no puede tipar); con una línea base utilizable es
   * INERTE (no sirve para estrechar después). Sigue juzgando los huérfanos. Solo `true` la levanta; un valor que no es
   * boolean es 500 `E_AUTHZ_CONFIG` (L5). Úsala UNA vez, con la spec que la flota sirve HOY, en una release que no cambie
   * `relations.config` (adoptar en una release que estrecha certifica el estrechamiento: A4).
   */
  establishBaseline?: boolean
  /**
   * **La salida forzada ACOTADA** (firma (8 · salida forzada)): la lista de `tipo#relación` cuyos hallazgos `shrunk`/`orphan`
   * se guardan aunque encojan el alcance de sus denies vivos. Exime SOLO esos: un hallazgo no nombrado se niega igual (un
   * encogimiento nuevo en otra relación no viaja en el mismo guardado forzado). No exime `no-baseline` (esa es
   * `establishBaseline`). No hay `true` global: cualquier forma que no sea un array de `tipo#relación` es 500
   * `E_AUTHZ_CONFIG` (L5). Y un nombre que en ESE guardado no exime ningún `shrunk`/`orphan` también es 500
   * `E_AUTHZ_CONFIG` sin escribir (cierre 1 del sublote (8)): la lista se retira tras el guardado que la necesita.
   */
  allowDenyReachShrink?: readonly string[]
}

/** La lista de la salida forzada acotada, validada (L5): `undefined` ⇒ ninguna; array de `tipo#relación` ⇒ esa; otra cosa ⇒ 500. */
function namedShrinkExemptions(value: unknown): ReadonlySet<string> {
  if (value === undefined) return new Set()
  const ok = Array.isArray(value) && value.every((key) => typeof key === 'string' && DENY_REACH_KEY_PATTERN.test(key))
  if (!ok) {
    throw new AuthorizationConfigError(
      `saveRelationsConfig: allowDenyReachShrink tiene que ser una lista de 'tipo#relación' (llegó ${JSON.stringify(value) ?? String(value)}). ` +
        `Desde el sublote (8) la salida forzada exime SOLO los hallazgos que nombras —p. ej. { allowDenyReachShrink: ['note#editor'] }—; ` +
        `no hay un true global.`
    )
  }
  return new Set(value as string[])
}

/** Los nombres de la lista que no eximen ningún hallazgo `shrunk`/`orphan` de este guardado (orden de la lista). */
function unusedShrinkExemptions(exempt: ReadonlySet<string>, judged: DenyReachFinding[]): string[] {
  const used = new Set(judged.filter((finding) => finding.reason !== 'no-baseline').map(denyReachKey))
  return [...exempt].filter((key) => !used.has(key))
}

function unusedShrinkExemptionsError(unused: string[]): AuthorizationConfigError {
  return new AuthorizationConfigError(
    `saveRelationsConfig: allowDenyReachShrink nombra ${JSON.stringify(unused)}, y en este guardado ningún deny vivo de ` +
      `esa(s) relación(es) encoge ni queda huérfano: no exime nada. Quita ese nombre de la lista (la salida forzada acotada ` +
      `se usa en el guardado que la necesita y se retira después; pegada, eximiría en silencio un encogimiento futuro). ` +
      `No se ha escrito nada (ni la fila ni la versión del catálogo).`
  )
}

/** `establishBaseline` validado (L5): solo `undefined`, `false` o `true`. */
function establishBaselineOf(value: unknown): boolean {
  if (value === undefined || value === false || value === true) return value === true
  throw new AuthorizationConfigError(
    `saveRelationsConfig: establishBaseline tiene que ser true o false (llegó ${JSON.stringify(value) ?? String(value)}): ` +
      `solo true adopta la línea base, y una opción mal escrita no puede levantar la guarda.`
  )
}

function connectionOf(options?: RelationsConfigStoreOptions): any {
  return options?.connection ? db.connection(options.connection) : db
}

/**
 * **Guarda (persiste) la config de relaciones** bajo el gate de versión: la
 * valida (⚪4/F-05 de config), la serializa a JSON y hace UPSERT de la fila
 * `id=1` dentro de `withAuthzCatalogWrite` —que sube la versión compartida como
 * última sentencia (invariante 14): un sync en otro proceso la ve en la
 * siguiente pregunta—. Devuelve la config congelada.
 */
export async function saveRelationsConfig(
  spec: RelationsConfigSpec,
  options: SaveRelationsConfigOptions = {}
): Promise<RelationsConfig> {
  // Valida ANTES de escribir: una config inválida no ensucia la tabla. Las dos salidas de la guarda (8), también antes
  // (L5: una forma rota es 500 sin tomar el cerrojo).
  const config = defineRelationsConfig(spec)
  const json = JSON.stringify(persistableRelationsSpec(spec))
  const { allowDenyReachShrink, establishBaseline, ...storeOptions } = options
  const exempt = namedShrinkExemptions(allowDenyReachShrink)
  const adopt = establishBaselineOf(establishBaseline)
  await withAuthzCatalogWrite(async (trx) => {
    const existing = await trx.from(TABLE).where('id', ROW_ID).first()
    // **La guarda (8) de `database`**, DENTRO de la transacción del catálogo (cerrojo de la fila de versión) y ANTES de la
    // primera escritura: la línea base es la fila que acabamos de leer (TODO O NADA) y los denies vivos se leen por la
    // MISMA trx. Cada hallazgo se niega salvo su salida con nombre: `no-baseline` ⇐ `establishBaseline: true` (solo existe
    // sin línea base utilizable: con ella es inerte); `shrunk`/`orphan` ⇐ su `tipo#relación` en `allowDenyReachShrink`.
    const judged = judgeDenyReach(baselineOf(existing), config, await liveDenyGroups(trx))
    const refused = judged.filter((finding) => (finding.reason === 'no-baseline' ? !adopt : !exempt.has(denyReachKey(finding))))
    if (refused.length > 0) throw denyReachRefused(refused)
    // **Un nombre de la salida acotada que no exime NADA en ESTE guardado ⇒ 500** (firma «(8 · cierre 1 · ronda)», 🟡 1 del
    // auditor del cierre 1): «casa» = exime un `shrunk`/`orphan` de este guardado (un `no-baseline` no cuenta), calculado
    // aquí, dentro de la trx. Así la salida se APAGA SOLA: una lista que se queda pegada en el pipeline no exime en silencio
    // el encogimiento FUTURO de esa relación. Un huérfano heredado sigue siendo hallazgo en cada guardado: su nombre casa.
    const unused = unusedShrinkExemptions(exempt, judged)
    if (unused.length > 0) throw unusedShrinkExemptionsError(unused)
    if (existing) {
      await trx.from(TABLE).where('id', ROW_ID).update({ spec: json, updated_at: systemClock() })
    } else {
      await trx.table(TABLE).insert({ id: ROW_ID, spec: json, model_id: null, updated_at: systemClock() })
    }
  }, storeOptions)
  invalidateAuthzCatalog()
  return config
}

/**
 * La LÍNEA BASE de la guarda (8) y del detector de un driver: la config persistida, leída TODO O NADA
 * (`denyReachBaselineOf`), o `null` = NO UTILIZABLE (sin fila, JSON roto, o una forma que la lectura no puede tipar). Una
 * fila que no valida en 2.5 pero cuyos campos de alcance se tipan (p. ej. una clave que 2.5 no conoce) SÍ es línea base:
 * re-guardarla con la spec corregida (la receta de B5) entra sin forzar.
 */
function baselineOf(row: any): ReturnType<typeof denyReachBaselineOf> {
  if (!row) return null
  let parsed: unknown
  try {
    parsed = JSON.parse(String(row.spec))
  } catch {
    return null
  }
  return denyReachBaselineOf(parsed)
}

/**
 * Los denies VIVOS de `authz_relations` agrupados por tipo y relación (las filas del driver `database`), por la conexión o
 * la trx que se le pase. Todas las filas `denied_*`: el deny no caduca (D3) y una fila con `expires_at` escrita a mano cuenta
 * igual (contar de más rechaza de más: lo conservador). El filtro del deny es UNO, aquí (`deniedPublicRelation`): una fila
 * que no es un deny no pide línea base (S-A0).
 */
async function liveDenyGroups(connection: any): Promise<LiveDenyGroup[]> {
  return denyGroupsOf(await liveDenyQuery(connection))
}

/** La consulta (un `GROUP BY` de `authz_relations`): aparte para que el detector de un driver le ponga su deadline. */
function liveDenyQuery(connection: any): any {
  return connection.from('authz_relations').select('object_type', 'relation').count('* as n').groupBy('object_type', 'relation')
}

function denyGroupsOf(rows: any[]): LiveDenyGroup[] {
  const groups: LiveDenyGroup[] = []
  for (const row of rows) {
    const relation = deniedPublicRelation(String(row.relation))
    if (relation !== null) groups.push({ objectType: String(row.object_type), relation, count: Number(row.n) })
  }
  return groups
}

function denyReachRefused(findings: DenyReachFinding[]): DenyReachRefusedError {
  const shrink = findings.filter((f) => f.reason !== 'no-baseline').map(denyReachKey)
  const exits = [
    ...(findings.some((f) => f.reason === 'no-baseline')
      ? ['sin línea base utilizable, la adopción es saveRelationsConfig(spec, { establishBaseline: true }) con la spec que la flota sirve HOY, sin cambios']
      : []),
    ...(shrink.length > 0
      ? [`si de verdad quieres que esos denies dejen de cortar, la salida forzada ACOTADA es saveRelationsConfig(spec, { allowDenyReachShrink: ${JSON.stringify(shrink)} })`]
      : []),
  ]
  const error = new DenyReachRefusedError(
    `saveRelationsConfig NEGADO (E_AUTHZ_DENY_REACH_REFUSED): ${findings.length} hallazgo(s) sobre denies vivos de authz_relations — ` +
      `una config que encoge su alcance haría conceder, de forma persistente, lo que negaban (decisión (8): para todo deny ` +
      `vivo, alcance nuevo ⊇ alcance viejo). ${findings.map(denyReachLine).join(' ')} No se ha escrito nada (ni la fila ni la ` +
      `versión del catálogo). ${exits.join('; ')}.`
  )
  error.findings = findings.map(({ objectType, relation, reason, count, lost, recipe }) => ({ objectType, relation, reason, count, lost, recipe }))
  return error
}

/** Lo que devuelve `checkRelationsConfigDenyReach`. */
export interface RelationsConfigDenyReachCheck {
  /** `'persisted'`: hay línea base utilizable; `'none'`: no la hay (sin fila, o una fila que no se puede tipar). */
  baseline: 'persisted' | 'none'
  /**
   * Persistida → servida: `shrunk`, `orphan` (también sin línea base) y, con `baseline: 'none'` y denies vivos,
   * `no-baseline` — lo mismo que juzgaría la guarda al guardar la config servida, sin salidas forzadas.
   */
  findings: DenyReachFinding[]
  /** Servida → persistida: `stale` — la línea base es más estrecha que lo servido en grupos con denies vivos (A1/S-B). */
  staleBaseline: DenyReachFinding[]
  /** `true` sii no hay ningún hallazgo en ninguna dirección (`no-baseline` cuenta como hallazgo). */
  ok: boolean
  /** Una línea por hallazgo, con el prefijo estable de su rama (`denyReachLine`). */
  lines: string[]
}

/**
 * **El detector de UN solo driver** (firma (8 · detector de un driver), R4 del analista del panel): en un despliegue
 * solo-`database` el detector de `authz:relations:reconcile --dry-run` no corre (necesita DOS drivers de relaciones:
 * origen = destino es 500). Esta función compara la config que SIRVE el proceso (`served`) con la línea base persistida
 * sobre los denies vivos de `authz_relations`, en las DOS direcciones:
 *  - persistida → servida: lo que la guarda negaría (`shrunk`, `orphan`, `no-baseline`);
 *  - servida → persistida: la línea base RANCIA (`stale`), que la guarda no puede ver.
 *
 * Solo LEE (la fila y un `GROUP BY` de `authz_relations`, por `options.connection` o la primaria), sin transacción y sin el
 * cerrojo del catálogo, con el MISMO punto de paso que la guarda (`baselineOf` + `liveDenyGroups` + `denyReachCheck`).
 * **Receta**: en CI, DESPUÉS del paso que guarda la config y ANTES de servir, y en un cron; falla el job si `ok` es `false`.
 * **Nunca** como fallo duro en `ready`: durante un despliegue un pod viejo que se reinicia sirve la config estrecha contra la
 * fila nueva y entraría en un bucle de reinicios.
 */
export async function checkRelationsConfigDenyReach(
  served: Pick<RelationsConfig, 'objectTypes'>,
  options: RelationsConfigStoreOptions = {}
): Promise<RelationsConfigDenyReachCheck> {
  if (!served || !Array.isArray(served.objectTypes)) {
    throw new AuthorizationConfigError(
      'checkRelationsConfigDenyReach: pasa la config de relaciones que SIRVE este proceso (relations.config de config/authorization.ts, la de defineRelationsConfig).'
    )
  }
  const connection = connectionOf(options)
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const row = await guardSql('relations-config', 'read', timeoutMs, () => connection.from(TABLE).where('id', ROW_ID).first())
  const groups = denyGroupsOf(await guardSql('relations-config', 'read', timeoutMs, () => liveDenyQuery(connection)))
  const check = denyReachCheck(baselineOf(row), served, groups)
  return {
    ...check,
    ok: check.findings.length === 0 && check.staleBaseline.length === 0,
    lines: [...check.findings, ...check.staleBaseline].map(denyReachLine),
  }
}

/**
 * **Lo que se persiste de la spec** (cierre-2 de R1 · P1, decisión del dueño 2026-10-20): `maxGroupDepth` y
 * `database.enforceGroupDepth` son claves de DESPLIEGUE, no de modelo. Se VALIDAN (`defineRelationsConfig`, arriba: un
 * valor malo es el mismo 500) pero NO se guardan. Nadie las lee de la base (el plan del reconcile toma el techo de
 * `to.groupDepthLimit()`, no de la config persistida), y guardarlas rompía un despliegue mezclado: un proceso alpha.2/
 * alpha.3 relee la fila con su lista blanca (B2, sin esas claves) y su `authz:relations:reconcile` sale con 1. No es el
 * «descartar en silencio» de B2: se conocen y se validan; solo no se escriben. El resto de la spec va TAL CUAL.
 */
function persistableRelationsSpec(spec: RelationsConfigSpec): RelationsConfigSpec {
  const { maxGroupDepth: _deployment, ...rest } = spec
  if (rest.database === undefined || rest.database === null || typeof rest.database !== 'object') return rest
  const { enforceGroupDepth: _enforce, ...database } = rest.database
  return { ...rest, database }
}

/** Lee el spec persistido (o `null` si no hay relaciones declaradas — opt-in). */
export async function readRelationsConfigSpec(
  options: RelationsConfigStoreOptions = {}
): Promise<RelationsConfigSpec | null> {
  const row: any = await guardSql('relations-config', 'read', options.timeoutMs ?? DEFAULT_TIMEOUT_MS, () =>
    connectionOf(options).from(TABLE).where('id', ROW_ID).first()
  )
  // Solo la AUSENCIA de fila es «ninguna persistida» (relaciones opt-in).
  if (!row) return null
  // Cierre 1 del lote B · 🟡 7: una fila que no es JSON es «la config persistida
  // NO valida» (422, misma familia que `defineRelationsConfig`), no «la lectura
  // falló» (503): la lectura SÍ terminó; el dato es el problema.
  let parsed: unknown
  try {
    parsed = JSON.parse(String(row.spec))
  } catch (error) {
    throw new RelationConfigError(
      `Config de relaciones inválida: la fila persistida en ${TABLE} (id=${ROW_ID}) no es JSON (${String((error as Error)?.message ?? error)}).`,
      { cause: error }
    )
  }
  // ⚪ N6 (cierre 2 del lote B): un JSON válido que NO es un objeto (`null`,
  // `0`, `false`, `""`, `[]`) también es «NO valida» — hasta el cierre se leía
  // como `null` («ninguna persistida») y APAGABA la vigilancia de la deriva del
  // modelo en silencio. Solo se llega con SQL a mano (`saveRelationsConfig`
  // valida antes), y justo por eso tiene que sonar.
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new RelationConfigError(
      `Config de relaciones inválida: la fila persistida en ${TABLE} (id=${ROW_ID}) no es un objeto ` +
        `(llegó ${JSON.stringify(parsed) ?? String(row.spec)}); se esperaba la spec { objectTypes, holderTypes?, database? }. ` +
        `Re-guárdala con saveRelationsConfig(<spec>).`
    )
  }
  return parsed as RelationsConfigSpec
}

/**
 * Lee la config persistida ya VALIDADA (o `null`). Es lo que hace 🟡3: un
 * proceso SIN `defineRelationsConfig` en memoria recupera aquí los tipos de
 * relación de la base, así que el modelo que republique los lleva.
 */
export async function readRelationsConfig(
  options: RelationsConfigStoreOptions = {}
): Promise<RelationsConfig | null> {
  const spec = await readRelationsConfigSpec(options)
  return spec ? defineRelationsConfig(spec) : null
}
