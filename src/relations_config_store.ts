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
 * no puede leer la base. Por eso el antiguo `republishFusedModel` —el
 * republicador basado en esta tabla, con CAS sobre `model_id`— se retiró en
 * 4-8: no tenía llamador de producción (la carrera que protegía no ocurre;
 * republicar el modelo es un paso manual de operador, escritor único). Ver el
 * informe 4-8. La columna `model_id` queda sin uso (cleanup futuro).
 */
import { systemClock } from './clock.js'
import { guardSql } from './drivers/backend_guard.js'
import db from '@adonisjs/lucid/services/db'
import { invalidateAuthzCatalog, withAuthzCatalogWrite } from './catalog_cache.js'
import { defineRelationsConfig } from './relations/define_relations_config.js'
import type { RelationsConfig, RelationsConfigSpec } from './relations/define_relations_config.js'

const TABLE = 'authz_relations_config'
const ROW_ID = 1
const DEFAULT_TIMEOUT_MS = 5_000

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
