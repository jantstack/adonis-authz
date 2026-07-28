import { BaseCommand, flags } from '@adonisjs/core/ace'
import { CommandOptions } from '@adonisjs/core/types/ace'

/**
 * Provisiona OpenFGA para el driver `openfga` del motor de autorización:
 * crea un store y escribe el authorization model del chasis. Imprime los
 * ids para el .env (OPENFGA_STORE_ID / OPENFGA_MODEL_ID).
 *
 * Idempotencia: cada ejecución crea un store NUEVO (los stores son baratos y
 * aislados); re-ejecutar sobre un store existente no es necesario salvo que
 * cambie el modelo — en ese caso usar --store-id para escribir un model nuevo
 * versionado sobre el mismo store.
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
    const { openFgaAuthorizationModel, provisionOpenFgaStore } = await import(
      '../src/drivers/openfga_driver.js'
    )
    // Los holders del consumidor viven en SU config, no en el paquete.
    const holderTypes = config?.holderTypes ?? {}

    if (this.storeId) {
      const client = new OpenFgaClient({ apiUrl, storeId: this.storeId })
      const model = await client.writeAuthorizationModel(openFgaAuthorizationModel(holderTypes))
      this.logger.success('Nuevo authorization model escrito en el store existente.')
      this.logger.log(`OPENFGA_STORE_ID=${this.storeId}`)
      this.logger.log(`OPENFGA_MODEL_ID=${model.authorization_model_id}`)
      return
    }

    // El paquete no lee env: el default APP_NAME se resuelve aquí (chasis).
    const { storeId, modelId } = await provisionOpenFgaStore(
      apiUrl,
      this.name ?? config?.openfga?.storeName ?? this.app.appName,
      holderTypes
    )
    this.logger.success('Store + authorization model provisionados.')
    this.logger.log('Añade al .env (junto a AUTHZ_DRIVER=openfga):')
    this.logger.log(`OPENFGA_URL=${apiUrl}`)
    this.logger.log(`OPENFGA_STORE_ID=${storeId}`)
    this.logger.log(`OPENFGA_MODEL_ID=${modelId}`)
  }
}
