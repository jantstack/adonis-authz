/**
 * Lo que `sqlite-file` (y PG/MySQL) prometen frente a `sqlite` en memoria
 * (2.5-B · K16, tester G4): un pool con MÁS de una conexión, y por tanto
 * concurrencia a nivel de conexión —no solo de `Promise.all` en JS—. El caso
 * de J4(a) (dos `grant` concurrentes) muere igual con pool 1: es una carrera
 * check-then-insert de JavaScript. Este caso NO puede pasar con una sola
 * conexión: una transacción abierta retiene la única conexión y la lectura
 * de al lado esperaría para siempre (aquí, hasta el deadline).
 *
 * En `sqlite` (`:memory:`, pool 1/1 a propósito: una base en memoria vive
 * dentro de UNA conexión) no se registra: allí la promesa es la contraria.
 */

import { test } from '@japa/runner'
import { v7 as uuidv7 } from 'uuid'
import db from '@adonisjs/lucid/services/db'
import { testEngine } from './helpers/app.js'
import { cleanAuthzTables } from './helpers/schema.js'

if (testEngine() !== 'sqlite') {
  test.group(`pool de conexiones en ${testEngine()} (2.5-B · K16)`, (group) => {
    group.each.setup(cleanAuthzTables)

    test('el pool admite al menos 2 conexiones', ({ assert }) => {
      const pool: any = (db.connection() as any).getWriteClient().client.pool
      assert.isAtLeast(Number(pool?.max), 2, `pool.max = ${pool?.max}`)
    })

    test('una lectura responde mientras OTRA conexión mantiene una transacción abierta con una escritura sin confirmar', async ({
      assert,
    }) => {
      const trx = await db.transaction()
      try {
        await trx.table('authz_permissions').insert({
          uuid: uuidv7(),
          slug: 'pending:write',
          description: null,
          created_at: new Date(),
          updated_at: new Date(),
        })
        // Con pool 1 esta lectura no obtiene conexión hasta que la
        // transacción termina: nunca, porque la transacción espera a la
        // lectura. Con ≥ 2 conexiones responde (WAL en SQLite; MVCC en PG;
        // lectura no bloqueada por una escritura de otra sesión en InnoDB).
        const outcome = await Promise.race([
          db.from('authz_permissions').where('slug', 'docs:read').select('slug').then((rows) => ({ rows })),
          new Promise<{ timeout: true }>((resolve) => setTimeout(() => resolve({ timeout: true }), 3_000)),
        ])
        assert.notProperty(outcome, 'timeout', 'la lectura se quedó esperando la conexión de la transacción')
        assert.isArray((outcome as any).rows)
      } finally {
        await trx.rollback()
      }
      assert.lengthOf(await db.from('authz_permissions').where('slug', 'pending:write'), 0, 'revertida')
    }).timeout(10_000)
  })
}
