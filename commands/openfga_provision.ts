import { BaseCommand, flags } from '@adonisjs/core/ace'
import { CommandOptions } from '@adonisjs/core/types/ace'

/**
 * Provisiona OpenFGA para el driver `openfga` del motor de autorización:
 * crea un store y escribe el authorization model **`facts` (c2r)** del
 * chasis. Imprime los ids para el .env (OPENFGA_STORE_ID / OPENFGA_MODEL_ID).
 *
 * **Publica el modelo `facts`** (3b-2k · K2): hasta 2.2 publicaba el del modo
 * `resolver`, que ya no existe. Ese modelo declara CUATRO relaciones por
 * permiso (`<P>`, `can_<P>`, `denied_<P>`, `permits_<P>`), así que necesita
 * la lista de permisos: sale de los `catalogs` del config, resueltos aquí
 * mismo (son funciones y no tocan la base). Sin `catalogs` no hay modelo que
 * publicar y el comando sale ≠ 0 en vez de dejar un store que no responde a
 * ninguna pregunta.
 *
 * Idempotencia: cada ejecución crea un store NUEVO (los stores son baratos y
 * aislados); re-ejecutar sobre un store existente no es necesario salvo que
 * cambie el modelo —añadir o quitar un permiso del catálogo lo cambia— y en
 * ese caso se usa --store-id para escribir un model nuevo versionado sobre el
 * mismo store.
 *
 * @example
 *   node ace openfga:provision                      # usa OPENFGA_URL del .env
 *   node ace openfga:provision --url http://openfga:8080
 *   node ace openfga:provision --store-id 01H...    # nuevo model en store existente
 */
export default class OpenFgaProvision extends BaseCommand {
  static commandName = 'openfga:provision'
  static description = 'Create an OpenFGA store + write the chassis authorization model'

  /**
   * **Bootstrap sin base: `startApp: false`, y el comando BOOTEA la app por su
   * cuenta hasta `boot()`** (2.4.0-alpha.4, opción B del panel; el único de
   * los nueve con `startApp: false`, a propósito).
   *
   * `this.app.config` NO existe hasta `app.boot()`: `Application.init()` no
   * llama a `ConfigManager.process()`, `boot()` sí (`@adonisjs/application`
   * 9.0.1; el docblock de `get config()` dice «after init» y es falso). Y el
   * ignitor de ace solo hace `boot()`+`start()` con `startApp: true`. Hasta
   * alpha.3 esto leía `this.app.config.get(...)` sobre `undefined`:
   * `TypeError` en la primera línea de `run()`, en cualquier consumidor.
   *
   * Por qué NO `startApp: true` (opción A, la que recomendaba COGNITIV):
   * `start()` ejecuta el `start()`/`ready()` de TODOS los providers del
   * consumidor y sus preloads (`start/routes.ts`, `start/kernel.ts`…) —
   * medido: un `ready()` que consulta la base mata este comando antes de
   * `run()` con la base ausente, que es exactamente el escenario en el que
   * corre; un preload que importe `services/relations` construye el driver
   * de relaciones, que pide el `OPENFGA_STORE_ID` que este comando existe
   * para producir (circular); y `app_provider.ready()` exige
   * `config/encryption.ts` válido. Lo que este comando necesita es SOLO el
   * config, y eso lo da `boot()` (≈80 ms: `config/*` + `register()`/`boot()`
   * de los providers). Ver `prepare()`.
   */
  static options: CommandOptions = {
    startApp: false,
  }

  @flags.string({ description: 'OpenFGA API URL (defaults to OPENFGA_URL)' })
  declare url: string | undefined

  @flags.string({ alias: 's', description: 'Write a new model into an EXISTING store' })
  declare storeId: string | undefined

  @flags.string({ description: 'Store name when creating one (default: APP_NAME del entorno)' })
  declare name: string | undefined

  /**
   * **La salida humana de la guarda contra la MUTILACIÓN del modelo** (plan 2.5 · lote D · D2; analista §4.6, juez
   * ronda 2 · R2-4 c). Sin ella, `--store-id` con un modelo nuevo que QUITA un `denied_<rel>` que el modelo actual del
   * store tiene es exit 1 sin escribir nada. Con ella, el comando BARRE el store y solo publica si no queda NI UN deny
   * vivo de esas relaciones: la bandera nunca autoriza apagar denies vivos.
   */
  @flags.boolean({ description: 'Allow a new model that drops denied_<rel> relations (only if the store has no live deny of them)' })
  declare allowDropDeny: boolean | undefined

  /**
   * Arranca la app hasta `boot()` — sin `start()` — para que `config/*`
   * exista. Va en `prepare()` y no en `run()` porque `BaseCommand.exec()`
   * encadena `prepare()` → `interact()` → `run()` dentro del mismo `try`:
   * el fallo se reporta igual y `run()` queda limpio de ciclo de vida.
   *
   * Las guardas de estado NO son decorativas: `Application.boot()` es un
   * no-op SILENCIOSO si el estado no es `initiated` (⚪ 9 del auditor), así
   * que desde `created` primero `init()`; desde `booted`/`ready` (comando
   * invocado dentro de una app ya arrancada) no se hace nada: idempotente.
   * Y si tras eso `app.config` sigue sin existir, se dice y se sale con 1
   * en vez de repetir el `TypeError` con otro disfraz.
   *
   * **Lo que sí exige, escrito**: «antes de que haya base» sigue siendo
   * verdad (cero conexiones, cero consultas, ningún `start`/`ready`, ningún
   * preload), pero todo `config/*` tiene que poder IMPORTARSE — un
   * `config/database.ts` que lance por un `.env` incompleto rompe esto igual
   * que a cualquier otro comando.
   */
  async prepare() {
    if (this.app.getState() === 'created') await this.app.init()
    if (this.app.getState() === 'initiated') await this.app.boot()
    if (!this.app.config) {
      this.logger.error(
        'config/* no está cargado: openfga:provision bootea la app hasta boot() para leer config/authorization.ts ' +
          `y tras hacerlo app.config sigue sin existir (estado de la app: ${this.app.getState()}). ` +
          'Comprueba que la app se puede inicializar y que todo config/* se puede importar.'
      )
      this.exitCode = 1
    }
  }

  async run() {
    if (this.exitCode === 1) return
    const config = this.app.config.get('authorization') as any
    const apiUrl = this.url ?? config?.openfga?.url
    if (!apiUrl) {
      this.logger.error('Falta la URL del servidor: --url o `openfga.url` en config/authorization.ts')
      this.exitCode = 1
      return
    }

    const { OpenFgaClient } = await import('@openfga/sdk')
    // El subpath `/openfga` es la única puerta al SDK (D9).
    const { openFgaFactsModel, provisionOpenFgaStore, assertFactsModelPublishable } = await import('../src/openfga.js')
    // Los holders del consumidor viven en SU config, no en el paquete.
    const holderTypes = config?.holderTypes ?? {}

    // Los PERMISOS del modelo (c2r) salen de los catálogos del config. Se
    // resuelven aquí porque son funciones del consumidor (pueden cargar otro
    // módulo) y no necesitan la base: el modelo se publica antes de que haya
    // una sola fila.
    const permissions = await this.resolvePermissions(config)
    if (!permissions) return

    // Los tipos de RELACIÓN (ReBAC) que el modelo lleva FUSIONADOS (Fase 4-8):
    // salen del CONFIG estático (`relations.config`), igual que los permisos
    // salen de `catalogs`. El comando es bootstrap sin base —`startApp: false`,
    // arranca hasta `boot()` para cargar `config/*`, que tiene que poder
    // importarse; no ejecuta `start`/`ready` ni preloads— y no puede leer
    // `authz_relations_config` de la BD; el config sí. Sin `relations.config` el modelo es
    // facts-only, como hasta ahora. Con él, un store recién aprovisionado ya
    // acepta tuplas de relación sin un `authz:catalog:sync` previo.
    const relations = relationsConfigOf(config)

    if (this.storeId) {
      // El mismo gate que la rama que CREA el store (L-F): la rama que
      // ACTUALIZA el modelo es justo donde se toca el techo de bytes, y sin
      // esto salía como error crudo del SDK con una request ya hecha (⚪ N1
      // del auditor de alpha.4). Cero requests si no es publicable.
      assertFactsModelPublishable(holderTypes, permissions, undefined, relations)
      const client = new OpenFgaClient({ apiUrl, storeId: this.storeId })
      const next = openFgaFactsModel(holderTypes, permissions, relations)
      // Lote D · D2: la guarda contra la MUTILACIÓN del modelo (R2-4 c / H3) — ANTES de escribir nada. Cierre 1 de D2:
      // juzga el ESTADO del store (🟡 3) y devuelve las relaciones que hay que RE-CONTAR justo antes de publicar (🟠 2).
      const guard = await this.guardDroppedDenies(client, next)
      if (guard === null) return
      // Cierre 1 de D2 · 🟠 2 (TOCTOU): el barrido es O(store) y la flota puede seguir escribiendo denies mientras dura.
      // Se vuelve a contar JUSTO antes de `writeAuthorizationModel`; un deny nuevo ⇒ exit 1 y CERO modelos. Estrecha la
      // ventana, no la cierra: la garantía es el paso 0 del procedimiento (la flota en deny: 'read' antes de contar).
      if (guard.recount.length > 0 && !(await this.recountBeforePublish(client, guard.recount))) return
      const model = await client.writeAuthorizationModel(next)
      this.logger.success('Nuevo authorization model escrito en el store existente.')
      if (relations) this.logger.info(`Tipos de relación fusionados: ${relations.objectTypes.map((t) => t.type).join(', ')}`)
      this.logger.log(`OPENFGA_STORE_ID=${this.storeId}`)
      this.logger.log(`OPENFGA_MODEL_ID=${model.authorization_model_id}`)
      return
    }

    // El paquete no lee env: el default APP_NAME se resuelve aquí (chasis).
    const { storeId, modelId } = await provisionOpenFgaStore(
      apiUrl,
      this.name ?? config?.openfga?.storeName ?? this.app.appName,
      holderTypes,
      permissions,
      relations
    )
    if (relations) this.logger.info(`Tipos de relación fusionados: ${relations.objectTypes.map((t) => t.type).join(', ')}`)
    this.logger.success('Store + authorization model provisionados.')
    this.logger.log('Añade al .env (junto a AUTHZ_DRIVER=openfga):')
    this.logger.log(`OPENFGA_URL=${apiUrl}`)
    this.logger.log(`OPENFGA_STORE_ID=${storeId}`)
    this.logger.log(`OPENFGA_MODEL_ID=${modelId}`)
  }

  /**
   * **La guarda contra la MUTILACIÓN del modelo** (plan 2.5 · lote D · D2; analista §4.6, juez ronda 2 · R2-4 c y H3;
   * cierre 1 de D2 · 🟡 3 y 🟠 2). `openfga:provision --store-id` publica desde la config del PROCESO: si ese proceso ya
   * no declara el opt-in de un tipo (un refactor, otra rama del config, un binario viejo), el modelo nuevo no trae
   * `denied_<rel>` y TODOS los denies de ese tipo dejan de bloquear en cuanto un pod lo resuelve — fail-open en silencio.
   *
   *  - **El ESTADO del store manda** (🟡 3): se leen TODOS los modelos del store (`readAuthorizationModels`, paginado y
   *    acotado por `PROVISION_MODEL_HISTORY_MAX`) y se barre por las `<tipo>#denied_<rel>` que ALGÚN modelo declaró y el
   *    nuevo no (una tupla `denied_*` solo puede existir si un modelo la declaró al escribirla). Un deny VIVO de esas
   *    relaciones ⇒ exit 1 con o sin la bandera. Hasta el cierre se comparaba solo con el ÚLTIMO modelo: un modelo
   *    intermedio sin `denied_*` (un ensayo de rollback con alpha.10) desactivaba la guarda.
   *  - **La INTENCIÓN la dice la bandera**: si el nuevo quita respecto del ÚLTIMO modelo, sin `--allow-drop-deny` es exit
   *    1 aunque no quede ningún deny (retirar un opt-in se pide en voz alta).
   *  - Devuelve las relaciones a RE-CONTAR antes de publicar (🟠 2), o `null` si negó. Todas las ramas fallidas empiezan
   *    por el prefijo ESTABLE «provision NEGADO:» (punto 7), también un barrido que falla a medias (⚪ 10 c).
   */
  private async guardDroppedDenies(client: any, next: any): Promise<{ recount: string[] } | null> {
    let models: any[]
    try {
      models = await readModelHistory(client)
    } catch (error: any) {
      this.logger.error(
        `provision NEGADO: no se pudo leer el modelo ACTUAL del store ${this.storeId} ni su historia de modelos ` +
          `(${String(error?.message ?? error)}). Sin ella no se puede comprobar si el modelo nuevo apaga denies vivos; no ` +
          'se publica a ciegas. No se ha escrito nada.'
      )
      this.exitCode = 1
      return null
    }
    const droppedLatest = droppedDenyRelations(models[0], next)
    const droppedEver = droppedDenyRelations({ type_definitions: models.flatMap((m) => m?.type_definitions ?? []) }, next)
    if (droppedLatest.length > 0 && this.allowDropDeny !== true) {
      this.logger.error(
        `provision NEGADO: el modelo nuevo QUITA ${droppedLatest.join(', ')}, que el modelo actual del store declara. Publicarlo apagaría ` +
          'todos los denies de esas relaciones en cuanto un pod lo resuelva (fail-open en silencio). Suele ser un proceso ' +
          "con la config sin el opt-in (deny: 'read'/'write') o con un paquete < 2.5.0-alpha.3: publica desde la versión y " +
          "la config actuales. Si de verdad quieres retirar el opt-in: pasa ANTES la flota entera a deny: 'read', retira esos " +
          'denies (removeDeny) y repite con --allow-drop-deny (solo publica si el store no tiene NI UN deny vivo de ellas). ' +
          'No se ha escrito nada.'
      )
      this.exitCode = 1
      return null
    }
    if (droppedEver.length === 0) return { recount: [] }
    const list = droppedEver.join(', ')
    const sweep = await this.sweep(client, droppedEver)
    if (sweep === null) return null
    if (sweep.count > 0) {
      this.logger.error(
        (droppedLatest.length > 0
          ? `provision NEGADO: --allow-drop-deny no apaga denies VIVOS: el store tiene ${sweep.count} deny(s) de ${list} `
          : `provision NEGADO: el store tiene ${sweep.count} deny(s) VIVOS de ${list} (declaradas por un modelo ` +
            `ANTERIOR del store) que el modelo nuevo no declara `) +
          `(p. ej. ${sweep.live.slice(0, 3).join(', ')}). Publicarlo los apagaría. Retíralos con removeDeny (o purga) y ` +
          'repite. No se ha escrito nada.'
      )
      this.exitCode = 1
      return null
    }
    this.logger.warning(
      `${droppedLatest.length > 0 ? '--allow-drop-deny: el modelo nuevo quita' : 'el modelo nuevo no declara (algún modelo anterior sí)'} ${list}; ` +
        `barrido del store: 0 denies vivos de esas relaciones (${sweep.read} tuplas leídas). Se publica.`
    )
    return { recount: droppedEver }
  }

  /**
   * El barrido; `null` (y exit 1 con el prefijo estable) si falla a medias (⚪ 10 c). Cierre 2 de D2 · 🟡 N4: en STREAMING
   * —página a página, sin cargar el store en memoria y SIN cota de tuplas—: hasta el cierre 2, un store de más de 1 M
   * tuplas dejaba `provision --store-id` en exit 1 PARA SIEMPRE tras retirar un opt-in (la historia de modelos no se
   * borra en FGA), sin bandera que lo salvara. Lo que sigue siendo ruidoso: un servidor que no avanza (token repetido).
   */
  private async sweep(client: any, dropped: string[]): Promise<{ live: string[]; count: number; read: number } | null> {
    try {
      return await countLiveDenies(client, dropped)
    } catch (error: any) {
      this.logger.error(
        `provision NEGADO: el barrido del store falló a medias (${String(error?.message ?? error)}): no se puede demostrar ` +
          `que no queda ningún deny vivo de ${dropped.join(', ')}. No se ha escrito nada.`
      )
      this.exitCode = 1
      return null
    }
  }

  /**
   * **El RECUENTO justo antes de publicar** (cierre 1 de D2 · 🟠 2, TOCTOU): otro barrido de las mismas relaciones; un
   * deny que llegó DURANTE o DESPUÉS del primero ⇒ exit 1 y CERO modelos. Es la señal de que la flota sigue en
   * `deny: 'write'` (el paso 0 del procedimiento no se hizo).
   */
  private async recountBeforePublish(client: any, dropped: string[]): Promise<boolean> {
    const sweep = await this.sweep(client, dropped)
    if (sweep === null) return false
    if (sweep.count === 0) return true
    this.logger.error(
      `provision NEGADO: el RECUENTO justo antes de publicar encontró ${sweep.count} deny(s) de ${dropped.join(', ')} ` +
        `que llegaron DURANTE el barrido (p. ej. ${sweep.live.slice(0, 3).join(', ')}): la flota sigue escribiendo denies. ` +
        "Pasa ANTES toda la flota a deny: 'read' (deny ⇒ 422 en todos los pods), retíralos y repite. No se ha escrito nada."
    )
    this.exitCode = 1
    return false
  }

  /**
   * Los permisos del modelo, o `null` (y exit 1) si no hay ninguno: un modelo
   * `facts` sin permisos no puede responder a nada, y descubrirlo aquí es
   * mucho mejor que descubrirlo en el primer `authorize`.
   */
  private async resolvePermissions(config: any): Promise<string[] | null> {
    const slugs = await permissionsOfCatalogs(config)
    if (slugs.length === 0) {
      this.logger.error(
        'El modelo `facts` declara cuatro relaciones por permiso: sin `catalogs` en ' +
          'config/authorization.ts no hay modelo que publicar. Declara tus catálogos y repite ' +
          '(el store que se creara sin ellos denegaría todo).'
      )
      this.exitCode = 1
      return null
    }
    return slugs
  }
}

/**
 * Los slugs de permiso de TODOS los catálogos del config, sin duplicados y en
 * orden estable (3b-2k · K2). Se exporta —y no es un método— para que se
 * pueda juzgar sin montar un comando de ace: es la pieza que decide qué
 * relaciones lleva el modelo `facts`, y una lista vacía es lo que hace que el
 * comando se niegue a provisionar.
 *
 * Los catálogos del config son FUNCIONES del consumidor (pueden cargar otro
 * módulo perezosamente) y no tocan la base: el modelo se publica antes de que
 * haya una sola fila.
 */
export async function permissionsOfCatalogs(config: any): Promise<string[]> {
  const sources: Array<() => Promise<any> | any> = config?.catalogs ?? []
  const slugs = new Set<string>()
  for (const source of sources) {
    const catalog = await source()
    for (const permission of catalog?.permissions ?? []) slugs.add(permission.slug)
  }
  return [...slugs].sort()
}

/**
 * Los tipos de relación (ReBAC) que van FUSIONADOS en el modelo `facts`
 * (Fase 4-8), leídos del CONFIG estático `relations.config` — o `undefined` si
 * el consumidor no declaró relaciones (modelo facts-only, como hasta 4-8). Se
 * exporta —y no es un método— para juzgar la decisión sin montar un ace: es la
 * pieza que decide si un store recién aprovisionado acepta tuplas de relación.
 *
 * La fuente es el config (`relations.config`), NO `authz_relations_config` de
 * la base: `openfga:provision` es bootstrap sin base (`startApp: false`;
 * arranca hasta `boot()` para cargar `config/*`, que tiene que poder
 * importarse; no ejecuta `start`/`ready` ni preloads) y el config es lo único
 * que tiene cargado — igual que los permisos salen de `catalogs` y no de
 * `authz_permissions`.
 */
export function relationsConfigOf(config: any): { objectTypes: readonly any[] } | undefined {
  const objectTypes = config?.relations?.config?.objectTypes
  if (!Array.isArray(objectTypes) || objectTypes.length === 0) return undefined
  return { objectTypes }
}

/**
 * Cierre 1 de D2 · 🟡 3: tope de la HISTORIA de modelos que `provision --store-id` lee para juzgar el estado del store
 * (cada modelo publicado es una versión): pasarse es exit 1 (`provision NEGADO:`), nunca juzgar con una historia cortada.
 */
export const PROVISION_MODEL_HISTORY_MAX = 10_000

/** Todos los modelos del store, del más RECIENTE al más antiguo (`readAuthorizationModels` paginado, acotado). */
async function readModelHistory(client: any): Promise<any[]> {
  const models: any[] = []
  let continuationToken: string | undefined
  do {
    const page: any = await client.readAuthorizationModels({ pageSize: 50, continuationToken })
    models.push(...(page?.authorization_models ?? []))
    if (models.length > PROVISION_MODEL_HISTORY_MAX) {
      throw new Error(`el store tiene más de ${PROVISION_MODEL_HISTORY_MAX} modelos (PROVISION_MODEL_HISTORY_MAX)`)
    }
    continuationToken = page?.continuation_token || undefined
  } while (continuationToken)
  return models
}

/** Los tipos que gobierna el modelo de ROLES (`facts`): sus `denied_<P>` son de permisos, no del deny de relaciones. */
const ROLE_MODEL_TYPES = new Set(['scope', 'role', 'role_binding', 'deny_binding'])

/**
 * **Las `<tipo>#denied_<rel>` de TIPOS DE RELACIÓN que el modelo actual declara y el nuevo no** (plan 2.5 · lote D ·
 * D2): la mutilación que la guarda de `openfga:provision` niega. Función PURA (dos modelos JSON en la forma de
 * `readLatestAuthorizationModel` / `openFgaFactsModel`). Los `denied_<P>` de `scope` (roles) quedan fuera: retirar un
 * permiso del catálogo no es retirar el opt-in de un tipo.
 */
export function droppedDenyRelations(current: any, next: any): string[] {
  const nextRelations = new Set<string>()
  for (const t of next?.type_definitions ?? []) {
    for (const relation of Object.keys(t?.relations ?? {})) nextRelations.add(`${t.type}#${relation}`)
  }
  const dropped: string[] = []
  for (const t of current?.type_definitions ?? []) {
    if (ROLE_MODEL_TYPES.has(t?.type)) continue
    for (const relation of Object.keys(t?.relations ?? {})) {
      if (relation.startsWith('denied_') && !nextRelations.has(`${t.type}#${relation}`)) dropped.push(`${t.type}#${relation}`)
    }
  }
  return dropped.sort()
}

/**
 * **El barrido de `--allow-drop-deny`, en STREAMING** (cierre 2 de D2 · 🟡 N4): cuenta las tuplas vivas cuyo
 * `<tipo>#<relación>` está en `dropped` leyendo el store ENTERO por páginas (`Read({})`: un `Read` por prefijo de objeto
 * es 200 con cero tuplas) sin acumularlo — guarda el recuento y TRES ejemplos para la letra, nada más — y SIN cota de
 * tuplas (hasta el cierre 2, 1 M ⇒ exit 1 para siempre). Exhaustivo o ruidoso: una página sin `tuples` o un
 * `continuation_token` que se repite (el servidor no avanza) LANZA (el comando lo dice como «el barrido falló a medias»).
 * Exportada para el caso que la juzga sin servidor.
 */
export async function countLiveDenies(client: any, dropped: string[]): Promise<{ live: string[]; count: number; read: number }> {
  const wanted = new Set(dropped)
  const live: string[] = []
  let count = 0
  let read = 0
  let continuationToken: string | undefined
  const seen = new Set<string>()
  do {
    const page: any = await client.read({}, { pageSize: 100, continuationToken })
    if (!Array.isArray(page?.tuples)) throw new Error("una página del Read no trae 'tuples': no se toma por vacía")
    for (const tuple of page.tuples) {
      read++
      const type = String(tuple?.key?.object ?? '').split(':')[0]
      if (!wanted.has(`${type}#${tuple?.key?.relation}`)) continue
      count++
      if (live.length < 3) live.push(`${tuple.key.object}#${tuple.key.relation}@${tuple.key.user}`)
    }
    const next = page?.continuation_token || undefined
    // Un token YA visto (no solo el inmediato: un ciclo a → b → a tampoco avanza) lanza; sin la cota de tuplas, esta
    // guarda es lo único que impide un barrido infinito. Coste: un token por página en memoria.
    if (next !== undefined && seen.has(next)) throw new Error(`el continuation_token se repite tras ${read} tuplas: el servidor no avanza`)
    if (next !== undefined) seen.add(next)
    continuationToken = next
  } while (continuationToken)
  return { live, count, read }
}
