/**
 * Borra UNA base de test del servidor, de forma autónoma y sin Lucid.
 *
 * Existe para el guard de salida de `bootApp` (3b-1): `process.exit()` no
 * espera a ninguna promesa, así que un script que sale así no puede llamar a
 * `teardown()` — y desde 2.5 eso dejaba una base `authz_test_<8 hex>`
 * huérfana por ejecución. El guard corre en `process.on('exit')`, que es
 * SÍNCRONO, y lo único que puede hacer allí es un `spawnSync`: este script.
 *
 *   node tests/helpers/drop_database.mjs '<json>'
 *   json = { engine: 'pg'|'mysql', host, port, user, password, database }
 *
 * Nunca borra una base sin sufijo: el nombre tiene que acabar en `_<8 hex>`,
 * que es lo único que el harness crea. Sale 0 aunque no exista (idempotente).
 */
const raw = process.argv[2]
if (!raw) {
  console.error('drop_database: falta el JSON de conexión')
  process.exit(2)
}
const { engine, host, port, user, password, database } = JSON.parse(raw)
if (!/_[0-9a-f]{8}$/.test(String(database))) {
  console.error(`drop_database: '${database}' no tiene la forma <base>_<8 hex> del harness; no se toca`)
  process.exit(2)
}

if (engine === 'pg') {
  const { default: pg } = await import('pg')
  const client = new pg.Client({ host, port, user, password, database: 'postgres' })
  await client.connect()
  try {
    await client.query(`DROP DATABASE IF EXISTS "${database}" WITH (FORCE)`)
  } finally {
    await client.end()
  }
} else if (engine === 'mysql') {
  const { default: mysql } = await import('mysql2/promise')
  const conn = await mysql.createConnection({ host, port, user, password })
  try {
    await conn.query(`DROP DATABASE IF EXISTS \`${database}\``)
  } finally {
    await conn.end()
  }
} else {
  console.error(`drop_database: motor '${engine}' no tiene base de servidor`)
  process.exit(2)
}
