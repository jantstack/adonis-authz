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
import { memoryScopeTree, resolveChainFrom } from '../src/testing/main.js'
import { APP_SCOPE } from '../src/types.js'

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
function worker(clock?: () => Date) {
  const tree = memoryScopeTree()
  const driver = spyDriver()
  const manager = new AuthorizationManager({
    default: 'spy',
    drivers: { spy: () => driver },
    holderTypes: HOLDERS,
    scopes: { resolveChain: resolveChainFrom(tree) },
    warnOnOptInSecurity: false,
    ...(clock ? { clock } : {}),
  })
  return { manager, driver, tree }
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
    const { withAuthzCatalogWrite, invalidateAuthzCatalog } = await import('../src/catalog_cache.js')
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
