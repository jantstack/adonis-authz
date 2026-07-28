/**
 * El juez, aplicado al driver que el paquete trae de serie.
 *
 * `runAuthorizationDriverContract` es la misma suite que se publica para que
 * un driver de terceros se pruebe a sí mismo — aquí la corre el paquete
 * contra `database`, sobre SQLite, sin app anfitriona.
 *
 * Si hay un OpenFGA a mano (`OPENFGA_TEST_URL`), el mismo juez se aplica
 * también a ese driver. En CI no hace falta: el contrato del driver por
 * defecto es lo que garantiza que la semántica no se rompe.
 */

import { runAuthorizationDriverContract } from '../src/testing/main.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import {
  OpenFgaAuthorizationDriver,
  provisionOpenFgaStore,
} from '../src/drivers/openfga_driver.js'
import { syncAuthzCatalog } from '../src/catalog.js'
import { cleanAuthzTables } from './helpers/schema.js'

runAuthorizationDriverContract({
  name: 'database',
  makeDriver: () => new DatabaseAuthorizationDriver(),
  seedCatalog: (catalog) => syncAuthzCatalog(catalog),
  cleanup: cleanAuthzTables,
})

/**
 * Los holders son del consumidor, no del motor: el harness declara los suyos
 * y con ellos se genera el modelo FGA.
 */
const TEST_HOLDER_TYPES = { users: 'user', admins: 'admin' }

const openFgaTestUrl = process.env.OPENFGA_TEST_URL
if (openFgaTestUrl) {
  let fgaDriver: OpenFgaAuthorizationDriver
  let storeCounter = 0

  runAuthorizationDriverContract({
    name: 'openfga',
    makeDriver: () => fgaDriver,
    seedCatalog: (catalog) => syncAuthzCatalog(catalog),
    // Store NUEVO por test: aislamiento total de los hechos. El catálogo
    // sigue siendo local (split: catálogo en SQL, hechos en FGA).
    cleanup: async () => {
      await cleanAuthzTables()
      storeCounter += 1
      const { storeId, modelId } = await provisionOpenFgaStore(
        openFgaTestUrl,
        `contract-${storeCounter}`,
        TEST_HOLDER_TYPES
      )
      fgaDriver = new OpenFgaAuthorizationDriver({
        apiUrl: openFgaTestUrl,
        storeId,
        modelId,
        holderTypes: TEST_HOLDER_TYPES,
      })
    },
  })
}
