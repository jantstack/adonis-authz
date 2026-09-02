/**
 * 3b-7 — el **freeze DURABLE** (decisión del dueño del 2026-08-31 (3b):
 * B + E-analista).
 *
 * Hasta este lote `freeze()` era un booleano de PROCESO: congelaba el manager
 * que lo llamaba y a sus vistas, y NADA más — el README prometía que una
 * escritura concurrente «no puede pasar» y era falso en el 100 % de los
 * despliegues con más de un worker. Desde este lote el freeze vive en la
 * fila `id = 2` de `authz_catalog_version` — la señal entre procesos que el
 * paquete ya usa (invariante 14) — con **token de dueño** (`fence` +
 * `holder`) y **lease renovado**:
 *
 *  - toda escritura del manager consulta la fila (consulta PROPIA, sin memo:
 *    +0,14 ms p50 medidos por el analista; `authorize` no paga nada);
 *  - `unfreeze(token)` solo levanta el freeze cuyo token coincide;
 *  - un lease vencido devuelve las escrituras SOLO (tras un SIGKILL nadie
 *    tiene que limpiar nada);
 *  - `freeze()` sobre un freeze vivo ajeno es 423 `E_AUTHZ_FREEZE_HELD`.
 *
 * Aquí van los casos de UN proceso (dos managers sobre el mismo backend, que
 * es lo que el freeze viejo no alcanzaba). El caso de DOS procesos —el único
 * que mata al mutante `modulo`, el «durable» como global de módulo— vive en
 * `freeze_multiprocess.spec.ts`, gateado a motores que otro proceso pueda
 * abrir.
 */

import { test } from '@japa/runner'
import db from '@adonisjs/lucid/services/db'
import { v7 as uuidv7 } from 'uuid'
import { AuthorizationManager } from '../src/manager.js'
import { DatabaseAuthorizationDriver } from '../src/drivers/database_driver.js'
import { syncAuthzCatalog } from '../src/catalog/catalog.js'
import { memoryScopeTree, resolveChainFrom } from '../src/testing/main.js'
import { APP_SCOPE } from '../src/types.js'
import { cleanAuthzTables } from './helpers/schema.js'

const HOLDERS = { users: 'user' }

/** Un driver de laboratorio que cuenta lo que le llega; nada sale a la red. */
function spyDriver(): any {
  const calls: string[] = []
  return {
    calls,
    withClock() {
      return this
    },
    async authorize() {
      calls.push('authorize')
      return true
    },
    async grant() {
      calls.push('grant')
      return { existed: false, expiresAt: null }
    },
    async revoke() {
      calls.push('revoke')
    },
    async deny() {
      calls.push('deny')
    },
    async removeDeny() {
      calls.push('removeDeny')
    },
    async listRoles() {
      calls.push('listRoles')
      return []
    },
    async hasRole() {
      calls.push('hasRole')
      return false
    },
    async onScopeAttached() {
      calls.push('onScopeAttached')
    },
    async onScopeMoved() {
      calls.push('onScopeMoved')
    },
    async onScopeDetached() {
      calls.push('onScopeDetached')
    },
    async purgeScope() {
      calls.push('purgeScope')
    },
  }
}

/** Dos managers INDEPENDIENTES sobre el mismo backend (dos workers de una flota). */
function worker(clock?: () => Date, extra: Record<string, unknown> = {}) {
  const tree = memoryScopeTree()
  const driver = spyDriver()
  const manager = new AuthorizationManager({
    default: 'spy',
    drivers: { spy: () => driver },
    holderTypes: HOLDERS,
    scopes: { resolveChain: resolveChainFrom(tree) },
    warnOnOptInSecurity: false,
    ...(clock ? { clock } : {}),
    ...extra,
  } as any)
  return { manager, driver, tree }
}

/**
 * Un manager sobre el driver `database` REAL (L-3): el que declara
 * `transactionalWrites: true` y, por tanto, el único al que la puerta 1 deja
 * pasar `{ transaction }` hasta la barrera. Con él se juzga el flip de L-2:
 * con `transaction` y freeze vivo ⇒ 503 `E_AUTHZ_FROZEN`, y CERO sentencias
 * por la transacción del llamante.
 */
function databaseWorker(extra: Record<string, unknown> = {}) {
  const tree = memoryScopeTree()
  const driver = new DatabaseAuthorizationDriver({ resolveChain: resolveChainFrom(tree) })
  const manager = new AuthorizationManager({
    default: 'database',
    drivers: { database: () => driver },
    holderTypes: HOLDERS,
    scopes: { resolveChain: resolveChainFrom(tree) },
    warnOnOptInSecurity: false,
    ...extra,
  } as any)
  return { manager, driver, tree }
}

const L3_CATALOG = {
  permissions: [{ slug: 'docs:read' }],
  roles: [{ slug: 'org-editor', scopeType: 'organization', permissions: ['docs:read'] }],
}

/** Espía sobre una transacción real: cuenta las sentencias que el paquete construye por ella. */
function spyTransaction<T extends object>(trx: T): { transaction: T; statements: () => number } {
  let statements = 0
  const counted = new Set(['from', 'table', 'query', 'insertQuery', 'rawQuery', 'raw', 'knexQuery', 'knexRawQuery', 'modelQuery'])
  const transaction = new Proxy(trx, {
    get(target, prop) {
      const value = Reflect.get(target, prop)
      if (typeof value !== 'function') return value
      if (typeof prop === 'string' && counted.has(prop)) {
        return (...args: unknown[]) => {
          statements += 1
          return value.apply(target, args)
        }
      }
      return value.bind(target)
    },
  })
  return { transaction, statements: () => statements }
}

async function factRows(subject: { type: string; uuid: string }): Promise<number> {
  const rows: any[] = await db.from('authz_assignments').where('holder_type', subject.type).where('holder_uuid', subject.uuid).count('* as n')
  const denies: any[] = await db.from('authz_denies').where('holder_type', subject.type).where('holder_uuid', subject.uuid).count('* as n')
  return Number(rows[0]?.n ?? 0) + Number(denies[0]?.n ?? 0)
}

async function rejects(assert: any, run: () => unknown, code: string, status: number) {
  try {
    await run()
    assert.fail(`se esperaba ${code} y no lanzó`)
  } catch (error: any) {
    assert.equal(error.code, code)
    assert.equal(error.status, status)
    return error
  }
}

/** Limpia la fila del freeze entre casos: un freeze que se escapa envenena a los siguientes (tester C1). */
async function resetFreezeRow(): Promise<void> {
  try {
    await db
      .from('authz_catalog_version')
      .where('id', 2)
      .update({ freeze_reason: null, freeze_holder: null, freeze_until_ms: null })
  } catch {
    // Antes de que exista el esquema nuevo (fase roja) no hay nada que limpiar.
  }
}

test.group('3b-7 · freeze durable — la fila, el token y el lease', (group) => {
  group.each.setup(async () => {
    await resetFreezeRow()
    return resetFreezeRow
  })

  test('el freeze de un manager congela a OTRO manager del mismo backend (la fila, no la memoria)', async ({
    assert,
  }) => {
    const a = worker()
    const b = worker()
    const subject = { type: 'users', uuid: uuidv7() }

    const token = await a.manager.freeze('cutover a openfga')
    assert.isObject(token, 'freeze() devuelve el token del dueño')
    assert.isNumber((token as any).fence)

    // B es OTRO manager (otro worker): antes de este lote su escritura ENTRABA.
    const error = await rejects(assert, () => b.manager.grant(subject, 'org-editor', APP_SCOPE), 'E_AUTHZ_FROZEN', 503)
    assert.isTrue(error.retryable, 'el 503 del freeze es reintentable')
    assert.include(error.message, 'cutover a openfga')
    assert.deepEqual(b.driver.calls, [], 'la escritura no puede haber llegado al driver de B')
    assert.isFalse(b.manager.frozen, 'B no SOSTIENE ningún freeze: lo ve por la fila')

    // La asimetría, entre managers: las lecturas de B siguen.
    assert.isTrue(await b.manager.authorize(subject, 'docs:read', APP_SCOPE))
    assert.deepEqual(b.driver.calls, ['authorize'])

    // unfreeze con el TOKEN devuelve las escrituras a toda la flota.
    assert.isTrue(await a.manager.unfreeze(token))
    await b.manager.grant(subject, 'org-editor', APP_SCOPE)
    assert.include(b.driver.calls, 'grant')
  })

  test('unfreeze AJENO no levanta la barrera de otro (el token manda)', async ({ assert }) => {
    const a = worker()
    const b = worker()
    const subject = { type: 'users', uuid: uuidv7() }

    const token = await a.manager.freeze('ventana de A')
    // Un token viejo/inventado no puede levantar el freeze de A.
    assert.isFalse(await b.manager.unfreeze({ fence: (token as any).fence - 1, holder: 'operator:0:deadbeef' }))
    await rejects(assert, () => b.manager.grant(subject, 'org-editor', APP_SCOPE), 'E_AUTHZ_FROZEN', 503)

    // Y un segundo freeze sobre el vivo de A es 423, no dos dueños.
    const held = await rejects(assert, () => b.manager.freeze('yo también'), 'E_AUTHZ_FREEZE_HELD', 423)
    assert.include(held.message, 'ventana de A')

    await a.manager.unfreeze(token)
  })

  test('el lease vencido devuelve las escrituras SOLO: tras un SIGKILL nadie limpia nada (reloj inyectado, sin sleep)', async ({
    assert,
  }) => {
    // El mismo reloj de pared, compartido y movible, en los dos workers.
    let wall = Date.parse('2030-06-15T12:00:00.000Z')
    const clock = () => new Date(wall)
    const a = worker(clock)
    const b = worker(clock)
    const subject = { type: 'users', uuid: uuidv7() }

    const token = await a.manager.freeze('migración que morirá con SIGKILL', { leaseMs: 3000 })
    await rejects(assert, () => b.manager.grant(subject, 'org-editor', APP_SCOPE), 'E_AUTHZ_FROZEN', 503)

    // El proceso de A «muere»: nadie renueva. Pasan 3001 ms de pared.
    wall += 3001
    await b.manager.grant(subject, 'org-editor', APP_SCOPE)
    assert.include(b.driver.calls, 'grant', 'con el lease vencido la flota vuelve a escribir sin intervención humana')
    // Higiene (tester C1): el dueño «muerto» limpia igualmente su lado (el
    // token vencido no molesta, pero su timer y su fila expirada sí).
    await a.manager.unfreeze(token)
  })

  test('freeze sin lease (leaseMs: null) NO caduca: es la ventana del operador', async ({ assert }) => {
    let wall = Date.parse('2030-06-15T12:00:00.000Z')
    const clock = () => new Date(wall)
    const a = worker(clock)
    const b = worker(clock)
    const subject = { type: 'users', uuid: uuidv7() }

    const token = await a.manager.freeze('cutover del operador', { leaseMs: null, kind: 'operator' })
    wall += 24 * 3600 * 1000 // un día después sigue congelado
    await rejects(assert, () => b.manager.grant(subject, 'org-editor', APP_SCOPE), 'E_AUTHZ_FROZEN', 503)

    const status = await b.manager.freezeStatus()
    assert.equal(status?.kind, 'operator')
    assert.equal(status?.reason, 'cutover del operador')
    assert.isNull(status?.untilMs)

    assert.isTrue(await a.manager.unfreeze(token))
    assert.isNull(await b.manager.freezeStatus())
  })

  test('la barrera cubre las siete escrituras y la delegación TAMBIÉN entre managers', async ({ assert }) => {
    const a = worker()
    const b = worker()
    const subject = { type: 'users', uuid: uuidv7() }
    const org = { type: 'organization', uuid: uuidv7() }
    await b.tree.attach(org, APP_SCOPE)

    const token = await a.manager.freeze('ventana')
    for (const write of [
      () => b.manager.grant(subject, 'org-editor', org),
      () => b.manager.revoke(subject, 'org-editor', org),
      () => b.manager.deny(subject, 'docs:read', org),
      () => b.manager.removeDeny(subject, 'docs:read', org),
      () => b.manager.scopes.attached({ type: 'organization', uuid: uuidv7() }, APP_SCOPE),
      () => b.manager.scopes.moved(org, APP_SCOPE),
      () => b.manager.scopes.detached(org),
      () => b.manager.defineScopedRole(subject, org, { slug: 'lead', scopeType: 'organization', rank: 1, permissions: [] }),
    ]) {
      await rejects(assert, write, 'E_AUTHZ_FROZEN', 503)
    }
    assert.deepEqual(b.driver.calls, [], 'ninguna escritura de B llegó a su driver')
    await a.manager.unfreeze(token)
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * F6 · Los comandos del cutover: la decisión de `authz:unfreeze`, pura.
 * ════════════════════════════════════════════════════════════════════════ */

test.group('3b-7 · authz:unfreeze — unfreezePlan', () => {
  const operador = { reason: 'cutover', holder: 'operator:1:aa', kind: 'operator' as const, untilMs: null, fence: 7 }
  const pasada = { reason: 'authz:reconcile --to=openfga', holder: 'reconcile:2:bb', kind: 'reconcile' as const, untilMs: 99, fence: 8 }

  test('sin freeze vivo: no-op en verde (idempotente)', async ({ assert }) => {
    const { unfreezePlan } = await import('../commands/authz_unfreeze.js')
    assert.equal(unfreezePlan(null, undefined).action, 'noop')
  })

  test('el freeze de OPERADOR se levanta; el de una PASADA viva no (sin --fence)', async ({ assert }) => {
    const { unfreezePlan } = await import('../commands/authz_unfreeze.js')
    assert.equal(unfreezePlan(operador, undefined).action, 'lift')
    const refuse = unfreezePlan(pasada, undefined)
    assert.equal(refuse.action, 'refuse', 'levantar la barrera de una pasada viva es el A1.3 que el token cierra')
    assert.include(refuse.message, 'reconcile:2:bb')
    assert.include(refuse.message, '--fence=8', 'y nombra la salida humana')
  })

  test('--fence es la decisión humana: levanta ESE freeze, y un fence viejo no levanta nada', async ({ assert }) => {
    const { unfreezePlan } = await import('../commands/authz_unfreeze.js')
    assert.equal(unfreezePlan(pasada, 8).action, 'lift')
    assert.equal(unfreezePlan(pasada, 7).action, 'refuse', 'un fence que ya no es el vivo no autoriza nada')
    assert.equal(unfreezePlan(operador, 3).action, 'refuse')
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * F1 · B entera: el README deja de prometer lo que el código no hace.
 * ════════════════════════════════════════════════════════════════════════ */

test.group('3b-7 · el README dice del freeze SOLO lo que es verdad', () => {
  /**
   * La frase de ~608 —«…would not appear in any counter, which is the one
   * thing the report promises cannot happen»— era falsa en el 100 % de los
   * despliegues con más de un worker (el freeze era de proceso), y «a
   * maintenance window of seconds» también lo era al tope declarado
   * (0,136 ms/hecho × 1 000 000 ≈ 136 s, analista §2.1). Este caso impide
   * que las dos vuelvan en una pasada de estilo (patrón de
   * `scope_outbox.spec.ts`).
   */
  test('la promesa falsa está FUERA y la honesta dentro: «otro proceso recibe 503», jamás «ninguna escritura entra»', async ({
    assert,
  }) => {
    const { readFile } = await import('node:fs/promises')
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')

    assert.notInclude(
      readme,
      'the one thing the report promises cannot happen',
      'esa promesa no era falsificable con destino OpenFGA y era falsa entre procesos'
    )
    assert.notInclude(
      readme,
      'a maintenance window of seconds',
      'al tope declarado la pasada dura minutos, no segundos (≈136 s medidos por extrapolación)'
    )
    // La promesa publicada, con las palabras del tester (A4):
    assert.include(readme, 'another process gets a retryable 503')
    assert.include(readme, 'never "no write enters the window"')
    // El alcance EXACTO (auditor 🟠 5): lo que el freeze NO congela, por su nombre.
    assert.include(readme, 'does NOT freeze')
    assert.include(readme, '`syncAuthzCatalog`')
    assert.include(readme, '`manager.driver()`')
    assert.include(readme, 'your own scope-tree tables')
    // La garantía es del MANAGER de este paquete (riesgo 4 del juez): la
    // suite publicada no la verifica para un driver de terceros.
    assert.include(readme, 'the published contract suite never checks it')
    // Y el cutover existe y tiene comandos.
    assert.include(readme, 'authz:freeze')
    assert.include(readme, 'authz:unfreeze')
    assert.include(readme, 'lapsed')
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * 3b-8 · B3 — la barrera del freeze se RE-AFIRMA a mitad de pasada.
 *
 * `relayScopeChanges` y `pruneOrphanRoles({force})` miraban el freeze UNA
 * vez al entrar y luego aplicaban hasta 10.000 escrituras (o N purgas
 * destructivas) sin volver a mirar: un freeze adquirido a mitad de drenaje
 * no paraba el resto de la pasada — escrituras que no aparecen en ningún
 * contador de la pasada certificada. El trade-off documentado en freeze.ts
 * cubre «una escritura que ya pasó su barrera», no una pasada de 10.000.
 * ════════════════════════════════════════════════════════════════════════ */

test.group('3b-8 · B3 — el freeze corta una pasada larga por lote', (group) => {
  group.each.setup(async () => {
    await resetFreezeRow()
    return resetFreezeRow
  })

  /** Una outbox en memoria con N cambios ya encolados, y sus filas a la vista. */
  function memoryOutbox(changes: any[]) {
    const rows = changes.map((change, i) => ({ id: i + 1, change, attempts: 0, applied: false }))
    const outbox = {
      async enqueue(change: any) {
        rows.push({ id: rows.length + 1, change, attempts: 0, applied: false })
      },
      async pending(limit: number, after?: any) {
        return rows
          .filter((r) => !r.applied && (after === undefined || r.id > after))
          .slice(0, limit)
          .map((r) => ({ id: r.id, change: r.change, attempts: r.attempts }))
      },
      async markApplied(id: any) {
        rows.find((r) => r.id === id)!.applied = true
      },
      async markFailed(id: any) {
        rows.find((r) => r.id === id)!.attempts += 1
      },
    }
    return { outbox, rows }
  }

  test('relay: un freeze adquirido a MITAD del drenaje corta la pasada en el siguiente lote (503 reintentable), y lo aplicado queda marcado', async ({
    assert,
  }) => {
    const b = worker() // el otro worker de la flota, el que congela
    const org1 = { type: 'organization', uuid: uuidv7() }
    const org2 = { type: 'organization', uuid: uuidv7() }
    const { outbox, rows } = memoryOutbox([
      { op: 'attached', child: org1, parent: APP_SCOPE },
      { op: 'attached', child: org2, parent: APP_SCOPE },
    ])

    const tree = memoryScopeTree()
    const driver = spyDriver()
    let token: any = null
    // La PRIMERA escritura del árbol dispara el freeze de otra pasada: es la
    // carrera real (reconcile congela mientras el relay drena).
    driver.onScopeAttached = async () => {
      driver.calls.push('onScopeAttached')
      if (!token) token = await b.manager.freeze('reconcile concurrente')
    }
    const a = new AuthorizationManager({
      default: 'spy',
      drivers: { spy: () => driver },
      holderTypes: HOLDERS,
      scopes: { resolveChain: resolveChainFrom(tree), outbox: outbox as any },
      warnOnOptInSecurity: false,
    })

    // Hasta 3b-8 la pasada entera se drenaba con el freeze ya vivo: las
    // escrituras posteriores al freeze no salían en ningún contador de la
    // pasada certificada.
    await rejects(assert, () => a.relayScopeChanges({ batchSize: 1 }), 'E_AUTHZ_FROZEN', 503)
    assert.lengthOf(
      driver.calls.filter((c: string) => c === 'onScopeAttached'),
      1,
      'la escritura posterior al freeze NO puede colarse (3b-8 · B3)'
    )
    assert.isTrue(rows[0].applied, 'lo aplicado antes del freeze queda marcado: la pasada es reanudable')
    assert.isFalse(rows[1].applied, 'lo demás sigue pendiente para después de la ventana')

    // Tras la ventana, la siguiente pasada drena lo que quedó.
    assert.isTrue(await b.manager.unfreeze(token))
    const despues = await a.relayScopeChanges({ batchSize: 1 })
    assert.lengthOf(despues.applied, 1)
    assert.isTrue(rows[1].applied)
  })

  test('prune-orphans --force: un freeze adquirido a MITAD corta ANTES de la siguiente purga, con la lista de lo ya purgado', async ({
    assert,
  }) => {
    const { withAuthzCatalogWrite, invalidateAuthzCatalog } = await import('../src/catalog/catalog_cache.js')
    const b = worker()
    // Dos roles locales cuyos owners YA no resuelven (huérfanos), a mano y
    // con la versión subida, como los casos '2.2' del juez.
    const uuids = [uuidv7(), uuidv7()].sort()
    const now = new Date()
    await withAuthzCatalogWrite(async (trx: any) => {
      for (const uuid of uuids) {
        await trx.table('authz_roles').insert({
          uuid,
          slug: `huerfano-${uuid.slice(0, 8)}`,
          name: 'huerfano',
          scope_type: 'unit',
          rank: 10,
          owner_scope_key: `organization|${uuidv7()}`,
          created_at: now,
          updated_at: now,
        })
      }
    })
    invalidateAuthzCatalog()

    const tree = memoryScopeTree()
    const driver = spyDriver()
    let token: any = null
    driver.purgeRole = async (uuid: string) => {
      driver.calls.push(`purgeRole:${uuid}`)
      if (!token) token = await b.manager.freeze('reconcile concurrente')
    }
    const a = new AuthorizationManager({
      default: 'spy',
      drivers: { spy: () => driver },
      holderTypes: HOLDERS,
      scopes: { resolveChain: resolveChainFrom(tree) },
      warnOnOptInSecurity: false,
    })

    try {
      let caught: any = null
      try {
        await a.pruneOrphanRoles({ force: true, allowMassPurge: true })
      } catch (error) {
        caught = error
      }
      assert.isNotNull(caught, 'la segunda purga tras el freeze tenía que cortarse (3b-8 · B3)')
      assert.equal(caught.code, 'E_AUTHZ_PRUNE_INTERRUPTED')
      assert.equal((caught.cause as any)?.code, 'E_AUTHZ_FROZEN', 'la causa es la barrera, y viaja')
      assert.lengthOf(caught.purged, 1, 'la lista de lo YA borrado viaja en el error')
      assert.lengthOf(
        driver.calls.filter((c: string) => c.startsWith('purgeRole:')),
        1,
        'la purga posterior al freeze NO puede ejecutarse'
      )
      assert.isTrue(await b.manager.unfreeze(token))
    } finally {
      await db.from('authz_roles').whereIn('uuid', uuids).delete()
      invalidateAuthzCatalog()
    }
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * L-1 · 🟠 8 (panel `{trx}`, auditor C1 + dictamen del juez) — **¿quién
 * decide la barrera?**
 *
 * Hasta L-1 `#assertNotFrozen` leía la fila del freeze POR EL CLIENTE que el
 * llamante pasaba en `transaction` (3b-7, «para no interbloquear un pool de
 * 1»). Eso convertía la barrera en una decisión del llamante: un cliente que
 * responde «no congelado» —o, en producción, el snapshot REPEATABLE READ de
 * InnoDB de una transacción abierta ANTES del freeze— dejaba entrar la
 * escritura. Y `#writeOptions` leía `transaction` con un cast aunque
 * `GrantOptions` no lo declarara, así que también valía para `grant`.
 *
 * La regla del juez: **la ESCRITURA va por la transacción del llamante; la
 * AUTORIDAD (leer si hay freeze) NUNCA.** La barrera se lee siempre por la
 * conexión del motor. El precio, decidido por el dueño: `{ transaction }`
 * exige pool ≥ 2; con pool 1 la escritura es un 503 clasificado con su
 * deadline, jamás un cuelgue ni un bypass.
 * ════════════════════════════════════════════════════════════════════════ */

/**
 * Un «cliente» que jura que el motor no está congelado. Es lo que un
 * llamante puede inyectar hoy en `transaction` (el auditor lo midió, C1), y
 * lo que en producción es el snapshot de una transacción vieja.
 */
function liarClient() {
  let reads = 0
  const row = { freeze_reason: null, freeze_holder: null, freeze_until_ms: null, freeze_fence: 1 }
  const builder: any = {
    where: () => builder,
    select: async () => {
      reads++
      return [row]
    },
    first: async () => {
      reads++
      return row
    },
  }
  return {
    from: () => {
      reads++
      return builder
    },
    table: () => builder,
    reads: () => reads,
  }
}

test.group('L-1 · 🟠 8 — la barrera del freeze la decide el MOTOR, nunca el cliente del llamante', (group) => {
  group.each.setup(async () => {
    await resetFreezeRow()
    return resetFreezeRow
  })

  test('un cliente inyectado que reporta «no congelado» NO deja pasar la escritura (ni se le pregunta): 503 E_AUTHZ_FROZEN en scopes.* y en grant; con el driver `database` (transactionalWrites: true, L-3) las cuatro de hechos CON transaction son 503 E_AUTHZ_FROZEN y al cliente no se le lee', async ({
    assert,
  }) => {
    const a = worker()
    const b = worker()
    const subject = { type: 'users', uuid: uuidv7() }
    const org = { type: 'organization', uuid: uuidv7() }
    await b.tree.attach(org, APP_SCOPE)
    const liar = liarClient()
    // El driver REAL, capaz (L-3): la puerta 1 se abre y manda la barrera.
    await cleanAuthzTables()
    await syncAuthzCatalog(L3_CATALOG)
    const real = databaseWorker()
    await real.tree.attach(org, APP_SCOPE)

    const token = await a.manager.freeze('cutover a openfga')
    // Las tres del árbol, que SÍ declaran `transaction` (para encolar).
    for (const write of [
      () => b.manager.scopes.attached({ type: 'organization', uuid: uuidv7() }, APP_SCOPE, { transaction: liar }),
      () => b.manager.scopes.moved(org, APP_SCOPE, { transaction: liar }),
      () => b.manager.scopes.detached(org, { transaction: liar }),
    ]) {
      const error = await rejects(assert, write, 'E_AUTHZ_FROZEN', 503)
      assert.isTrue(error.retryable)
    }
    // Y las de hechos. Hasta L-1 `#writeOptions` leía `transaction` con un
    // cast aunque el tipo no la declarara; desde L-2 SÍ está declarada
    // (`WriteOptions.transaction`: ESCRIBIR, no encolar) y pasa por la puerta
    // de la capacidad ANTES de la barrera: el driver de este worker no declara
    // `transactionalWrites` (= false), así que la respuesta es el 500
    // `E_AUTHZ_UNSUPPORTED` de la puerta 1 y no un 503 «reintenta luego» para
    // una llamada que no puede entrar NUNCA. Lo que este caso protege no
    // cambia: al driver no llega nada y al cliente del llamante no se le
    // pregunta. (Con un driver que declare `true` —el `database` de L-3— la
    // puerta se abre y entonces manda la barrera: 503 `E_AUTHZ_FROZEN`.)
    const smuggled = { actor: subject, transaction: liar }
    for (const write of [
      () => b.manager.grant(subject, 'org-editor', org, smuggled),
      () => b.manager.revoke(subject, 'org-editor', org, smuggled),
      () => b.manager.deny(subject, 'docs:read', org, smuggled),
      () => b.manager.removeDeny(subject, 'docs:read', org, smuggled),
    ]) {
      const error = await rejects(assert, write, 'E_AUTHZ_UNSUPPORTED', 500)
      assert.include(error.message, 'transactionalWrites')
    }
    // Sin `transaction`, las mismas cuatro son la barrera: 503 reintentable.
    for (const write of [
      () => b.manager.grant(subject, 'org-editor', org, { actor: subject }),
      () => b.manager.revoke(subject, 'org-editor', org, { actor: subject }),
      () => b.manager.deny(subject, 'docs:read', org, { actor: subject }),
      () => b.manager.removeDeny(subject, 'docs:read', org, { actor: subject }),
    ]) {
      const error = await rejects(assert, write, 'E_AUTHZ_FROZEN', 503)
      assert.isTrue(error.retryable)
    }
    assert.deepEqual(b.driver.calls, [], 'ROJO si algo llegó al driver: el cliente del llamante decidió la barrera')
    assert.equal(liar.reads(), 0, 'la barrera NUNCA se lee por el cliente del llamante: es autoridad, no escritura')

    // El FLIP de L-2 (L-3): con un driver que declara `transactionalWrites:
    // true` la puerta 1 deja pasar `{ transaction }` y vuelve a mandar la
    // barrera: 503 `E_AUTHZ_FROZEN` reintentable en las cuatro de hechos, y
    // al cliente del llamante sigue sin preguntársele nada (la barrera se
    // lee por la conexión del motor y corta ANTES de la primera sentencia).
    for (const write of [
      () => real.manager.grant(subject, 'org-editor', org, smuggled),
      () => real.manager.revoke(subject, 'org-editor', org, smuggled),
      () => real.manager.deny(subject, 'docs:read', org, smuggled),
      () => real.manager.removeDeny(subject, 'docs:read', org, smuggled),
    ]) {
      const error = await rejects(assert, write, 'E_AUTHZ_FROZEN', 503)
      assert.isTrue(error.retryable)
    }
    assert.equal(liar.reads(), 0, 'ROJO: con el driver capaz la barrera se leyó por el cliente del llamante')
    assert.equal(await factRows(subject), 0)
    await a.manager.unfreeze(token)
    // Sin freeze el mismo cliente llega al driver, que lo juzga: no es una
    // transacción ABIERTA de Lucid ⇒ 500 `E_AUTHZ_CONFIG`, y tampoco se le
    // lee (juzgar no es escribir).
    const notATransaction = await rejects(assert, () => real.manager.grant(subject, 'org-editor', org, smuggled), 'E_AUTHZ_CONFIG', 500)
    assert.include(notATransaction.message, 'isTransaction')
    assert.equal(liar.reads(), 0)
    assert.equal(await factRows(subject), 0)
    await cleanAuthzTables()
  })

  test('pool 1 (`:memory:`) + la transacción del llamante abierta ⇒ 503 E_AUTHZ_BACKEND_TIMEOUT con SU deadline, jamás un cuelgue; con pool ≥ 2 la barrera se lee en fresco y la escritura entra', async ({
    assert,
  }) => {
    const { testEngine } = await import('./helpers/app.js')
    const engine = testEngine()
    // Deadline propio y corto: el caso mide que el 503 llega POR el deadline
    // de la barrera y no por el `acquireConnectionTimeout` de knex (60 s).
    const b = worker(undefined, { freezeTimeoutMs: 400 })
    const org = { type: 'organization', uuid: uuidv7() }
    let caught: any = null
    const started = Date.now()
    await db.transaction(async (trx) => {
      // El llamante sostiene su transacción (la ÚNICA conexión en `:memory:`).
      await trx.from('authz_catalog_version').where('id', 1).first()
      try {
        await b.manager.scopes.attached(org, APP_SCOPE, { transaction: trx })
      } catch (error) {
        caught = error
      }
    })
    const elapsed = Date.now() - started
    if (engine === 'sqlite') {
      assert.isNotNull(caught, 'ROJO: con pool 1 la barrera se leyó por la transacción del llamante (la escritura entró)')
      assert.equal(caught.status, 503)
      assert.equal(caught.code, 'E_AUTHZ_BACKEND_TIMEOUT')
      assert.isBelow(elapsed, 5_000, `el 503 tiene que llegar por el deadline de la barrera (400 ms), no por el del pool (llegó a los ${elapsed} ms)`)
      assert.deepEqual(b.driver.calls, [], 'fail-closed: nada llegó al driver')
    } else {
      assert.isNull(caught, `con pool ≥ 2 (${engine}) la barrera se lee por otra conexión y la escritura entra: ${caught?.message}`)
      assert.deepEqual(b.driver.calls, ['onScopeAttached'])
    }
  }).timeout(20_000)

  test('el snapshot del llamante (REPEATABLE READ de InnoDB; PG con el nivel explícito; SQLite WAL) NO ve un freeze posterior, y AUN ASÍ la escritura es 503: la barrera no se lee por él; con el driver `database` (L-3) grant/deny CON esa transacción son 503 E_AUTHZ_FROZEN con CERO sentencias por ella, y tras el unfreeze entran POR ella', async ({
    assert,
  }) => {
    const { testEngine } = await import('./helpers/app.js')
    const engine = testEngine()
    if (engine === 'sqlite') {
      // `:memory:` tiene UNA conexión: no puede haber una transacción abierta
      // del llamante Y un freeze de otro proceso a la vez. El caso de pool 1
      // es el anterior; este es el de los motores con snapshot real.
      const b = worker()
      const org = { type: 'organization', uuid: uuidv7() }
      await b.manager.scopes.attached(org, APP_SCOPE, { transaction: db })
      assert.deepEqual(b.driver.calls, ['onScopeAttached'], 'sin freeze, `transaction` no cambia nada (no hay outbox)')
      return
    }
    const a = worker()
    const b = worker()
    const subject = { type: 'users', uuid: uuidv7() }
    const org = { type: 'organization', uuid: uuidv7() }
    await b.tree.attach(org, APP_SCOPE)
    await cleanAuthzTables()
    await syncAuthzCatalog(L3_CATALOG)
    const real = databaseWorker()
    await real.tree.attach(org, APP_SCOPE)

    // La transacción del llamante, abierta ANTES del freeze y con su foto ya
    // fijada por una primera lectura (en InnoDB el snapshot nace en la
    // primera lectura consistente; en PG hace falta pedir el nivel — la
    // misma forma que `withSourceSnapshot`, 3b-6).
    const options = engine === 'pg' || engine === 'mysql' ? { isolationLevel: 'repeatable read' as const } : undefined
    let token: any = null
    try {
      await db.transaction(async (trx) => {
        await trx.from('authz_catalog_version').where('id', 2).first()
        token = await a.manager.freeze('cutover del operador', { leaseMs: null, kind: 'operator' })

        const seen: any = await trx.from('authz_catalog_version').where('id', 2).first()
        assert.isNull(
          seen.freeze_reason,
          `${engine}: la foto de la transacción del llamante NO ve el freeze puesto después (es el mecanismo del bypass)`
        )

        // Las escrituras de hechos SIN `transaction` y la del árbol CON ella
        // (encolar): las tres pasan la barrera, que se lee por la conexión
        // del motor y ve el freeze que la foto del llamante no ve.
        for (const write of [
          () => b.manager.grant(subject, 'org-editor', org, { actor: subject }),
          () => b.manager.deny(subject, 'docs:read', org, { actor: subject }),
          () => b.manager.scopes.moved(org, APP_SCOPE, { transaction: trx }),
        ]) {
          const error = await rejects(assert, write, 'E_AUTHZ_FROZEN', 503)
          assert.include(error.message, 'authz:unfreeze')
        }
        // Y las de hechos CON `transaction` (desde L-2 declarada: ESCRIBIR en
        // tu transacción) no llegan ni a la barrera: el driver de este worker
        // no declara `transactionalWrites`, y la puerta 1 responde 500
        // `E_AUTHZ_UNSUPPORTED` antes — una llamada que no puede entrar nunca
        // no recibe un «reintenta luego». Hasta L-1 el cast de `#writeOptions`
        // leía este objeto y la barrera se decidía por la foto del llamante.
        const smuggled = { actor: subject, transaction: trx }
        for (const write of [
          () => b.manager.grant(subject, 'org-editor', org, smuggled),
          () => b.manager.deny(subject, 'docs:read', org, smuggled),
        ]) {
          await rejects(assert, write, 'E_AUTHZ_UNSUPPORTED', 500)
        }
        assert.deepEqual(b.driver.calls, [], 'ROJO: el snapshot del llamante decidió la barrera y la escritura entró')

        // El FLIP de L-2 (L-3): el driver `database` declara `true`, la
        // puerta se abre y manda la barrera — que se lee por la conexión del
        // motor y ve el freeze que la foto del llamante no ve: 503
        // `E_AUTHZ_FROZEN` y CERO sentencias por la transacción del llamante.
        const spy = spyTransaction(trx)
        const inTrx = { actor: subject, transaction: spy.transaction }
        for (const write of [
          () => real.manager.grant(subject, 'org-editor', org, inTrx),
          () => real.manager.deny(subject, 'docs:read', org, inTrx),
          () => real.manager.revoke(subject, 'org-editor', org, inTrx),
          () => real.manager.removeDeny(subject, 'docs:read', org, inTrx),
        ]) {
          const error = await rejects(assert, write, 'E_AUTHZ_FROZEN', 503)
          assert.include(error.message, 'authz:unfreeze')
        }
        assert.equal(spy.statements(), 0, 'ROJO: E_AUTHZ_FROZEN con { transaction } dejó sentencias en la transacción del llamante')
        assert.equal(await factRows(subject), 0)

        // Y tras el unfreeze la MISMA llamada entra POR la transacción del
        // llamante: la fila existe dentro de ella y no fuera hasta el commit.
        // Salvo en SQLite (WAL), y es del MOTOR: la transacción del llamante
        // leyó ANTES de que el freeze y el unfreeze confirmaran, así que su
        // snapshot quedó atrás y SQLite no la deja subir a escritora
        // (`SQLITE_BUSY` / BUSY_SNAPSHOT) — 503 clasificado, cero filas. PG
        // (REPEATABLE READ) y MySQL escriben: la fila del freeze no es la suya.
        await a.manager.unfreeze(token)
        token = null
        if (engine === 'sqlite-file') {
          const busy = await rejects(assert, () => real.manager.grant(subject, 'org-editor', org, inTrx), 'E_AUTHZ_BACKEND_UNAVAILABLE', 503)
          assert.match(String(busy.cause?.code ?? busy.cause?.message ?? ''), /SQLITE_BUSY/, 'sqlite-file: el snapshot atrasado no puede escribir')
          assert.isAbove(spy.statements(), 0, 'la sentencia fue por la transacción del llamante (y el motor la rechazó)')
        } else {
          await real.manager.grant(subject, 'org-editor', org, inTrx)
          assert.isAbove(spy.statements(), 0, 'la escritura fue por la transacción del llamante')
          assert.equal(await factRows(subject), 0, 'sin confirmar, la conexión del motor no la ve')
          assert.isFalse(await real.manager.authorize(subject, 'docs:read', org))
        }
      }, options)
      if (engine === 'sqlite-file') {
        assert.equal(await factRows(subject), 0)
      } else {
        assert.equal(await factRows(subject), 1, 'confirmada con la transacción del llamante')
        assert.isTrue(await real.manager.authorize(subject, 'docs:read', org))
      }
    } finally {
      if (token) await a.manager.unfreeze(token)
      await cleanAuthzTables()
    }
  }).timeout(20_000)
})

/* ════════════════════════════════════════════════════════════════════════
 * L-1 · 🟠 J1 (juez del panel `{trx}`) — **las relaciones no estaban
 * congeladas por nada**: ni una referencia al freeze en `src/relations/` ni
 * en `authz:relations:reconcile`. Durante un cutover las escrituras de roles
 * recibían 503 y las de relaciones ENTRABAN, y la pasada de reconcile de
 * relaciones certificaba un estado que podía cambiar debajo.
 * ════════════════════════════════════════════════════════════════════════ */

const RELATIONS_CAPS = {
  singleCheckRelations: true,
  listObjectsInherited: false,
  usersetSubjects: true,
  membersOfNative: true,
  enumerateRelations: true,
  listObjectsTruncation: false,
  injectableClock: true,
  // Doble en memoria (L-2/L-4): no escribe en ninguna transacción, así que declara `false` y se le juzga esa cara; la `true` la juzga el driver `database` REAL en pool ≥ 2 (`relations_database.spec.ts`).
  transactionalWrites: false,
} as const

/** Un `RelationsManager` sobre el doble en memoria, con espía de escrituras. */
async function relationsWorker(options: Record<string, unknown> = {}) {
  const { RelationsManager } = await import('../src/relations/manager.js')
  const { makeRelationsDriver, contractRelationsConfig } = await import('../src/testing/relations_contract.js')
  const config = contractRelationsConfig()
  const base: any = makeRelationsDriver({ config, capabilities: RELATIONS_CAPS as any })
  const writes: string[] = []
  const spied: any = {
    ...base,
    relate: async (...args: any[]) => {
      writes.push('relate')
      return base.relate(...args)
    },
    unrelate: async (...args: any[]) => {
      writes.push('unrelate')
      return base.unrelate(...args)
    },
    purgeObject: async (...args: any[]) => {
      writes.push('purgeObject')
      return base.purgeObject(...args)
    },
    purgeSubject: async (...args: any[]) => {
      writes.push('purgeSubject')
      return base.purgeSubject(...args)
    },
  }
  return { manager: new RelationsManager(spied, config, options as any), driver: base, writes }
}

test.group('L-1 · 🟠 J1 — las escrituras de relations pasan la MISMA barrera del freeze que las de roles', (group) => {
  group.each.setup(async () => {
    await resetFreezeRow()
    return resetFreezeRow
  })

  test('relate/unrelate/purgeObject/purgeSubject ⇒ 503 E_AUTHZ_FROZEN reintentable bajo un freeze de roles; check sigue; unfreeze los devuelve', async ({
    assert,
  }) => {
    const roles = worker()
    const rel = await relationsWorker()
    const user = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: `doc-${uuidv7()}` }

    const token = await roles.manager.freeze('cutover a openfga')
    for (const write of [
      () => rel.manager.relate(user, 'viewer', doc, APP_SCOPE),
      () => rel.manager.unrelate(user, 'viewer', doc, APP_SCOPE),
      () => rel.manager.purgeObject(doc, APP_SCOPE),
      () => rel.manager.purgeSubject(user, APP_SCOPE),
    ]) {
      const error = await rejects(assert, write, 'E_AUTHZ_FROZEN', 503)
      assert.isTrue(error.retryable, 'el 503 del freeze es reintentable también en relations')
      assert.include(error.message, 'cutover a openfga')
    }
    assert.deepEqual(rel.writes, [], 'ROJO: una escritura de relations entró con el motor congelado')
    // Las lecturas siguen (la misma asimetría que en roles).
    assert.isFalse(await rel.manager.check(user, 'viewer', doc, APP_SCOPE))

    assert.isTrue(await roles.manager.unfreeze(token))
    await rel.manager.relate(user, 'viewer', doc, APP_SCOPE)
    assert.deepEqual(rel.writes, ['relate'])
    assert.isTrue(await rel.manager.check(user, 'viewer', doc, APP_SCOPE))
  })

  test('la ventana del OPERADOR (authz:freeze) también congela relations, y el 503 dice cómo se levanta', async ({
    assert,
  }) => {
    const roles = worker()
    const rel = await relationsWorker()
    const user = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: `doc-${uuidv7()}` }
    const token = await roles.manager.freeze('cutover', { leaseMs: null, kind: 'operator' })
    const error = await rejects(assert, () => rel.manager.relate(user, 'viewer', doc, APP_SCOPE), 'E_AUTHZ_FROZEN', 503)
    assert.include(error.message, 'authz:unfreeze')
    assert.deepEqual(rel.writes, [])
    await roles.manager.unfreeze(token)
  })
})

/* ════════════════════════════════════════════════════════════════════════
 * L-1 · J1 (segunda mitad): `authz:relations:reconcile` corre bajo la
 * ventana DURABLE. `reconcileRelations` no ve al manager de roles (regla 2),
 * así que la ventana la abre el comando (`runRelationsReconcile`), con la
 * misma forma que `authz:reconcile` de roles: `--dry-run` no congela, la
 * pasada que escribe sí, la ventana del operador es contexto propio y el
 * reporte publica `frozen.lapsed`.
 * ════════════════════════════════════════════════════════════════════════ */

test.group('L-1 · J1 — authz:relations:reconcile corre bajo la ventana durable', (group) => {
  group.each.setup(async () => {
    await resetFreezeRow()
    return resetFreezeRow
  })

  /** Origen y destino en memoria; el origen SONDEA la barrera mientras se le enumera. */
  async function reconcileWorld() {
    const { makeRelationsDriver, contractRelationsConfig } = await import('../src/testing/relations_contract.js')
    const config = contractRelationsConfig()
    const from: any = makeRelationsDriver({ config, capabilities: RELATIONS_CAPS as any })
    const to: any = makeRelationsDriver({ config, capabilities: RELATIONS_CAPS as any })
    const user = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: `doc-${uuidv7()}` }
    await from.relate(user, 'viewer', doc, APP_SCOPE)
    // Otro worker de la flota intenta escribir relaciones A MITAD de la pasada.
    const other = await relationsWorker()
    const probes: Array<string | null> = []
    const probed: any = {
      ...from,
      enumerateRelations: async (...args: any[]) => {
        try {
          await other.manager.relate({ type: 'user', uuid: uuidv7() }, 'viewer', doc, APP_SCOPE)
          probes.push(null)
        } catch (error: any) {
          probes.push(error.code ?? String(error))
        }
        return from.enumerateRelations(...args)
      },
    }
    return { from: probed, to, user, doc, probes, other }
  }

  test('la pasada que ESCRIBE congela la flota (relate de otro worker ⇒ 503 a mitad), publica frozen{fence, lapsed:false} y suelta la ventana al terminar', async ({
    assert,
  }) => {
    const { runRelationsReconcile } = await import('../commands/authz_relations_reconcile.js')
    const roles = worker()
    const world = await reconcileWorld()

    const report = await runRelationsReconcile(roles.manager, { from: world.from, to: world.to, partition: APP_SCOPE, toKey: 'memoria' })
    assert.equal(report.written, 1)
    assert.isTrue(probes(world).length > 0, 'el origen se enumeró al menos una vez')
    assert.isTrue(
      probes(world).every((code) => code === 'E_AUTHZ_FROZEN'),
      `ROJO: una escritura de relations entró durante la pasada de reconcile (sondas: ${JSON.stringify(probes(world))})`
    )
    assert.deepEqual(report.frozen, { durable: true, lapsed: false, leaseMs: 15_000, fence: report.frozen!.fence })
    assert.isNull(await roles.manager.freezeStatus(), 'la ventana se soltó al terminar')
    await world.other.manager.relate(world.user, 'owner', world.doc, APP_SCOPE)
  })

  test('--dry-run NO congela (el verificador es read-only y corre en cron) y no publica frozen', async ({ assert }) => {
    const { runRelationsReconcile } = await import('../commands/authz_relations_reconcile.js')
    const roles = worker()
    const world = await reconcileWorld()
    const report = await runRelationsReconcile(roles.manager, { from: world.from, to: world.to, partition: APP_SCOPE, dryRun: true })
    assert.equal(report.written, 1)
    assert.isUndefined(report.frozen)
    assert.isTrue(probes(world).every((code) => code === null), `dry-run: las escrituras de la flota siguen (${JSON.stringify(probes(world))})`)
  })

  test('la ventana del OPERADOR (authz:freeze) es contexto propio: la pasada corre DENTRO, no la levanta, y frozen.fence es el suyo; el freeze de OTRA pasada es 423', async ({
    assert,
  }) => {
    const { runRelationsReconcile } = await import('../commands/authz_relations_reconcile.js')
    const operator = worker()
    const roles = worker()
    const world = await reconcileWorld()
    const token = await operator.manager.freeze('cutover', { leaseMs: null, kind: 'operator' })
    try {
      const report = await runRelationsReconcile(roles.manager, { from: world.from, to: world.to, partition: APP_SCOPE })
      assert.equal(report.frozen?.fence, (token as any).fence, 'la pasada corrió dentro de la ventana del operador')
      assert.isNull(report.frozen?.leaseMs)
      assert.isFalse(report.frozen?.lapsed)
      const status = await roles.manager.freezeStatus()
      assert.equal(status?.kind, 'operator', 'la ventana del operador sigue en pie: la pasada no la levantó')
      assert.isTrue(probes(world).every((code) => code === 'E_AUTHZ_FROZEN'))
    } finally {
      await operator.manager.unfreeze(token)
    }
    // Un freeze vivo de otra PASADA no es contexto: 423.
    const held = await worker().manager.freeze('otra pasada', { kind: 'reconcile' })
    try {
      await rejects(
        assert,
        () => runRelationsReconcile(roles.manager, { from: world.from, to: world.to, partition: APP_SCOPE }),
        'E_AUTHZ_FREEZE_HELD',
        423
      )
    } finally {
      await roles.manager.unfreeze(held).catch(() => {})
      await resetFreezeRow()
    }
  })

  function probes(world: { probes: Array<string | null> }): Array<string | null> {
    return world.probes
  }
})
