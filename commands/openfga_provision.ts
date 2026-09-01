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

  static options: CommandOptions = {
    startApp: false,
  }

  @flags.string({ description: 'OpenFGA API URL (defaults to OPENFGA_URL)' })
  declare url: string | undefined

  @flags.string({ alias: 's', description: 'Write a new model into an EXISTING store' })
  declare storeId: string | undefined

  @flags.string({ description: 'Store name when creating one (default: APP_NAME del entorno)' })
  declare name: string | undefined

  async run() {
    const config = this.app.config.get('authorization') as any
    const apiUrl = this.url ?? config?.openfga?.url
    if (!apiUrl) {
      this.logger.error('Falta la URL del servidor: --url o `openfga.url` en config/authorization.ts')
      this.exitCode = 1
      return
    }

    const { OpenFgaClient } = await import('@openfga/sdk')
    // El subpath `/openfga` es la única puerta al SDK (D9).
    const { openFgaFactsModel, provisionOpenFgaStore } = await import('../src/openfga.js')
    // Los holders del consumidor viven en SU config, no en el paquete.
    const holderTypes = config?.holderTypes ?? {}

    // Los PERMISOS del modelo (c2r) salen de los catálogos del config. Se
    // resuelven aquí porque son funciones del consumidor (pueden cargar otro
    // módulo) y no necesitan la base: el modelo se publica antes de que haya
    // una sola fila.
    const permissions = await this.resolvePermissions(config)
    if (!permissions) return

    if (this.storeId) {
      const client = new OpenFgaClient({ apiUrl, storeId: this.storeId })
      const model = await client.writeAuthorizationModel(openFgaFactsModel(holderTypes, permissions))
      this.logger.success('Nuevo authorization model escrito en el store existente.')
      this.logger.log(`OPENFGA_STORE_ID=${this.storeId}`)
      this.logger.log(`OPENFGA_MODEL_ID=${model.authorization_model_id}`)
      return
    }

    // El paquete no lee env: el default APP_NAME se resuelve aquí (chasis).
    const { storeId, modelId } = await provisionOpenFgaStore(
      apiUrl,
      this.name ?? config?.openfga?.storeName ?? this.app.appName,
      holderTypes,
      permissions
    )
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
