import { BaseCommand, flags } from '@adonisjs/core/ace'
import { CommandOptions } from '@adonisjs/core/types/ace'

/**
 * Migra los HECHOS del driver `database` a un store OpenFGA: copia las
 * asignaciones vigentes (authz_assignments) y los denies (authz_denies)
 * como tuples. El catálogo y la jerarquía no migran: son metadata local
 * para ambos drivers.
 *
 * Proceso completo database → openfga:
 *   1. Levantar el servidor (profile openfga del compose).
 *   2. node ace openfga:provision            → store + model (ids al .env)
 *   3. node ace openfga:import [--dry-run]   → copia los hechos
 *   4. AUTHZ_DRIVER=openfga + reiniciar api/worker.
 *
 * No destructivo (las tablas locales quedan intactas → rollback = volver a
 * AUTHZ_DRIVER=database). Sobre un store que YA tiene tuplas exige
 * `--reconcile`: compara tupla a tupla y reescribe las que difieren en
 * caducidad (S7) — nunca "ignora duplicados", porque en FGA la condición no
 * es parte de la clave.
 */
export default class OpenFgaImport extends BaseCommand {
  static commandName = 'openfga:import'
  static description = 'Copy authz facts (assignments/denies) from the database driver into OpenFGA'

  static options: CommandOptions = {
    startApp: true,
  }

  @flags.string({ description: 'OpenFGA API URL (defaults to OPENFGA_URL)' })
  declare url: string | undefined

  @flags.string({ alias: 's', description: 'Store id (defaults to OPENFGA_STORE_ID)' })
  declare storeId: string | undefined

  @flags.string({ description: 'Model id (defaults to OPENFGA_MODEL_ID)' })
  declare modelId: string | undefined

  @flags.boolean({ description: 'Count what would be written, without writing' })
  declare dryRun: boolean | undefined

  @flags.boolean({
    description: 'Import into a non-empty store: compare tuple by tuple and rewrite the ones that differ',
  })
  declare reconcile: boolean | undefined

  async run() {
    const config = this.app.config.get('authorization') as any
    const apiUrl = this.url ?? config?.openfga?.url
    const storeId = this.storeId ?? config?.openfga?.storeId
    if (!apiUrl || !storeId) {
      this.logger.error(
        'Faltan la URL o el store: --url/--store-id o OPENFGA_URL/OPENFGA_STORE_ID (ver openfga:provision)'
      )
      this.exitCode = 1
      return
    }

    const { importAuthzFactsToOpenFga } = await import('../src/drivers/openfga_driver.js')
    const holderTypes = config?.holderTypes ?? {}
    const result = await importAuthzFactsToOpenFga({
      apiUrl,
      storeId,
      modelId: this.modelId ?? config?.openfga?.modelId,
      dryRun: this.dryRun ?? false,
      reconcile: this.reconcile ?? false,
      holderTypes,
    })

    const verb = result.dryRun ? 'Se escribirían' : 'Escritas'
    this.logger.success(
      `${verb} ${result.written} tuplas nuevas, ${result.updated} reescritas (caducidad distinta), ` +
        `${result.unchanged} sin cambios; ${result.skippedExpired} asignaciones ya expiradas omitidas.`
    )
    if (!result.dryRun) {
      this.logger.log('Siguiente paso: AUTHZ_DRIVER=openfga y reiniciar api/worker.')
    }
  }
}
