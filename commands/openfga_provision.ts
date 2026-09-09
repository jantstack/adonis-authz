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
      const model = await client.writeAuthorizationModel(
        openFgaFactsModel(holderTypes, permissions, relations)
      )
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
