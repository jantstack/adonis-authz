/**
 * **La config de relaciones PERSISTIDA** (Fase 4, lote 4-5 · 🟡3) — vive en la
 * tabla `authz_relations_config`, bajo el gate de versión (invariante 14), como
 * el catálogo. Es lo que cierra el «modelo de uno, tuplas de otro» del auditor:
 * quien REPUBLICA el modelo fusionado —`syncAuthzCatalog`, `openfga:provision` o
 * un `defineRelationsConfig` que se guarda— lee los tipos de relación de la
 * BASE y NO los deja caer, aunque no tenga `defineRelationsConfig` en memoria.
 *
 * Este módulo vive en `src/` (NO en `src/relations/`, que la regla 2 de pureza
 * mantiene aislado del `db`): es la ruta que TOCA la base, como `catalog.ts`.
 * Importa el TIPO y el validador de `src/relations/` (la dirección permitida:
 * `relations/` no importa hacia afuera; los demás sí importan de él).
 *
 * **La carrera `defineRelationsConfig`↔`syncAuthzCatalog`** (los dos republican
 * el modelo del store compartido y compiten por el `modelId`): `republishFusedModel`
 * lo resuelve leyendo SIEMPRE las DOS mitades persistidas (permisos del catálogo
 * + tipos de relación de esta tabla), así que el modelo publicado nunca está
 * MUTILADO —el que gana la carrera publica el modelo COMPLETO—; y el `model_id`
 * se fija con un CAS con reintento acotado: una contención que no cede ⇒ **409
 * `E_AUTHZ_WRITE_CONFLICT`** (la lección de invariante 6, «relee y re-aplica;
 * gana el último; lo que no cede es 409, jamás un modelo a medias»).
 */
import db from '@adonisjs/lucid/services/db'
import { WriteConflictError } from './errors.js'
import { systemClock } from './clock.js'
import { guardSql } from './drivers/backend_guard.js'
import { invalidateAuthzCatalog, withAuthzCatalogWrite } from './catalog_cache.js'
import { defineRelationsConfig } from './relations/define_relations_config.js'
import type { RelationsConfig, RelationsConfigSpec } from './relations/define_relations_config.js'

const TABLE = 'authz_relations_config'
const ROW_ID = 1
const DEFAULT_TIMEOUT_MS = 5_000
/** Reintentos del CAS del `model_id` antes de rendirse con 409 (como el reintento del grant). */
const MAX_PIN_RETRIES = 5

/** Un driver que sabe republicar el modelo fusionado (lo implementa `openfga`). */
export interface FusedModelPublisher {
  /**
   * Republica el modelo fusionado (permisos del catálogo + la config de
   * relaciones que se le pasa) y devuelve el nuevo `modelId`. Leer los permisos
   * es cosa del driver (su memo del catálogo); los tipos de relación se los da
   * este módulo desde la BASE.
   */
  republishFusedModel(relationsConfig?: RelationsConfig): Promise<string>
}

export interface RelationsConfigStoreOptions {
  connection?: string
  timeoutMs?: number
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
  options: RelationsConfigStoreOptions = {}
): Promise<RelationsConfig> {
  // Valida ANTES de escribir: una config inválida no ensucia la tabla.
  const config = defineRelationsConfig(spec)
  const json = JSON.stringify(spec)
  await withAuthzCatalogWrite(async (trx) => {
    const existing = await trx.from(TABLE).where('id', ROW_ID).first()
    if (existing) {
      await trx.from(TABLE).where('id', ROW_ID).update({ spec: json, updated_at: systemClock() })
    } else {
      await trx.table(TABLE).insert({ id: ROW_ID, spec: json, model_id: null, updated_at: systemClock() })
    }
  }, options)
  invalidateAuthzCatalog()
  return config
}

/** Lee el spec persistido (o `null` si no hay relaciones declaradas — opt-in). */
export async function readRelationsConfigSpec(
  options: RelationsConfigStoreOptions = {}
): Promise<RelationsConfigSpec | null> {
  const row: any = await guardSql('relations-config', 'read', options.timeoutMs ?? DEFAULT_TIMEOUT_MS, () =>
    connectionOf(options).from(TABLE).where('id', ROW_ID).first()
  )
  if (!row?.spec) return null
  return JSON.parse(String(row.spec)) as RelationsConfigSpec
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

/** Lee el `model_id` fusionado pinado (o `null` si no hay fila / no se ha pinado). */
export async function readRelationsModelId(options: RelationsConfigStoreOptions = {}): Promise<string | null> {
  const row: any = await guardSql('relations-config', 'readModelId', options.timeoutMs ?? DEFAULT_TIMEOUT_MS, () =>
    connectionOf(options).from(TABLE).where('id', ROW_ID).select('model_id').first()
  )
  return row?.model_id ?? null
}

/**
 * CAS del `model_id`: fija `newModelId` SOLO si el pin actual sigue siendo
 * `expected` (el que se leyó antes de publicar). 0 filas afectadas ⇒ otro
 * proceso lo cambió entremedias (la carrera). La fila tiene que existir
 * (`saveRelationsConfig` la creó): un `model_id` es un pin DERIVADO, no crea
 * config.
 */
async function casModelId(
  newModelId: string,
  expected: string | null,
  options: RelationsConfigStoreOptions
): Promise<boolean> {
  const affected = await guardSql('relations-config', 'pinModelId', options.timeoutMs ?? DEFAULT_TIMEOUT_MS, () =>
    connectionOf(options)
      .from(TABLE)
      .where('id', ROW_ID)
      .where((b: any) => (expected === null ? b.whereNull('model_id') : b.where('model_id', expected)))
      .update({ model_id: newModelId, updated_at: systemClock() })
  )
  return Number(affected) > 0
}

/**
 * **Republica el modelo FUSIONADO desde las dos mitades PERSISTIDAS** y fija el
 * `model_id` con un CAS: la operación que corren, cada uno por su lado,
 * `syncAuthzCatalog` y un `saveRelationsConfig` (la carrera). Como los dos leen
 * la config de relaciones de la BASE (no de memoria), el modelo publicado
 * SIEMPRE es completo —permisos + tipos de relación—; jamás mutilado. El CAS
 * del `model_id` reintenta hasta `MAX_PIN_RETRIES`; una contención que no cede
 * ⇒ 409 `E_AUTHZ_WRITE_CONFLICT`, nunca un modelo a medias.
 *
 * `stub` (solo tests): fuerza el resultado del CAS para poder demostrar el 409
 * de la contención que no cede sin dos procesos reales.
 */
export async function republishFusedModel(
  publisher: FusedModelPublisher,
  options: RelationsConfigStoreOptions & { stubCas?: () => boolean } = {}
): Promise<{ modelId: string; relationTypes: string[] }> {
  for (let attempt = 0; ; attempt++) {
    const expected = await readRelationsModelId(options)
    const relationsConfig = await readRelationsConfig(options)
    // El driver lee SUS permisos (del catálogo) y emite el modelo fusionado con
    // los tipos de relación de la base: las DOS mitades, nunca una sola.
    const modelId = await publisher.republishFusedModel(relationsConfig ?? undefined)
    const won = options.stubCas ? options.stubCas() : await casModelId(modelId, expected, options)
    if (won) {
      return {
        modelId,
        relationTypes: relationsConfig ? relationsConfig.objectTypes.map((t) => t.type) : [],
      }
    }
    if (attempt >= MAX_PIN_RETRIES) {
      throw new WriteConflictError(
        `republishFusedModel: el pin del modelId no cedió tras ${MAX_PIN_RETRIES} reintentos ` +
          `(otra republicación —syncAuthzCatalog o defineRelationsConfig— lo cambia sin parar). ` +
          `Se rechaza con 409 en vez de dejar el pin en un modelo a medias.`
      )
    }
  }
}
