/**
 * **2.4.0-alpha.3 · bloque F — docs con dientes del evento de relaciones.**
 * Patrón de `trx_docs.spec.ts` (grep con `assert.include` sobre `README.md` +
 * el error real byte a byte). Fichero propio para no engordar el de `{trx}` y
 * porque estas frases sobreviven a `{trx}`. Cada frase nueva del README tiene
 * aquí su caso de letra: si alguien la suaviza o la quita, rojo.
 *
 *  - F2 · el invariante 13 nombrando el puerto de relaciones, y que en
 *    `openfga` el evento no lleva `transactional`.
 *  - F3 · la tabla de `operation`s de la purga (sin `subject`/`relation`;
 *    sin `object`/`relation`), SIN conteo y la receta (`enumerateRelations`).
 *  - F4 · `assertWrite` síncrono, puro y sin `actor`; después de F-05 y antes
 *    del driver; devolver una promesa es 500 `E_AUTHZ_CONFIG` — y lo que LANZA
 *    el manager es esa letra byte a byte.
 *  - F5 · el cableado (`relations.assertWrite` / `onRelationWrite` /
 *    `requireActor`, que anula el raíz por puerto), el hook que lanza se
 *    registra y no tumba, y `requireActor` alcanza a las purgas (breaking).
 *  - F6 · no-regresión: `manager.driver()` sigue saltándose los tres.
 */
import { test } from '@japa/runner'
import { readFile } from 'node:fs/promises'
import { v7 as uuidv7 } from 'uuid'
import { RelationsManager } from '../src/relations/manager.js'
import { AuthorizationConfigError } from '../src/errors.js'
import { makeRelationsDriver, contractRelationsConfig } from '../src/testing/relations_contract.js'
import type { RelationsDriverCapabilities } from '../src/types.js'

async function readme(): Promise<string> {
  return readFile(new URL('../README.md', import.meta.url), 'utf8')
}

/** El texto de una sección del README: desde su cabecera hasta la siguiente cabecera (`##`…`####`). */
function section(text: string, heading: string): string {
  const start = text.indexOf(heading)
  if (start < 0) return ''
  const rest = text.slice(start + heading.length)
  const next = rest.search(/\n#{2,4} /)
  return heading + (next < 0 ? rest : rest.slice(0, next))
}

const HEADING = '### The relation write event (2.4.0-alpha.3)'

const CAPS: RelationsDriverCapabilities = {
  singleCheckRelations: true,
  listObjectsInherited: false,
  usersetSubjects: true,
  membersOfNative: true,
  enumerateRelations: true,
  listObjectsTruncation: false,
  injectableClock: true,
  transactionalWrites: false,
}

test.group('alpha.3 · F · el README dice lo del evento de relaciones con estas palabras', () => {
  test('la sección existe con cuerpo', async ({ assert }) => {
    const text = await readme()
    const body = section(text, HEADING)
    assert.isAbove(body.length, HEADING.length + 800, `ROJO: el README no tiene la sección «${HEADING}» (o está vacía)`)
  })

  test('F2 · el invariante 13 nombra el puerto de relaciones (deadline ⇒ indeterminate: true ANTES del 503), cita sus casos, y en openfga el evento no lleva transactional', async ({
    assert,
  }) => {
    const body = section(await readme(), HEADING)
    assert.include(body, 'a relation write that elapses its deadline notifies `onRelationWrite` with `indeterminate: true` before propagating the 503')
    assert.include(body, 'on `openfga` the event never carries `transactional`')
    // Los casos, nombrados como hace el README en el resto (`:243`).
    assert.include(body, 'C1 · relate/unrelate que vencen el deadline')
    assert.include(body, 'servidor MUDO')
    assert.include(body, 'C3 · deadline vencido DENTRO de la trx externa')
  })

  test('F3 · la tabla de operations: relate, unrelate, purgeObject (sin subject/relation), purgeSubject (sin object/relation); UN evento por llamada, SIN conteo, y la receta (enumerateRelations antes de purgar)', async ({
    assert,
  }) => {
    const body = section(await readme(), HEADING)
    assert.match(body, /^\| `relate` \|/m)
    assert.match(body, /^\| `unrelate` \|/m)
    assert.match(body, /^\| `purgeObject` \|.*no `subject`, no `relation`/m)
    assert.match(body, /^\| `purgeSubject` \|.*no `object`, no `relation`/m)
    assert.include(body, 'one event per call')
    assert.include(body, 'does not count')
    assert.include(body, 'call `enumerateRelations` (or `listSubjects`) before purging')
    assert.include(body, 'even when the driver sweeps both spellings of the partition uuid')
    assert.include(body, 'a purge that deletes nothing notifies all the same')
  })

  test('F4 · assertWrite es síncrono, puro y sin actor a propósito (R-13), corre después de F-05 y antes del driver, y devolver una promesa es 500 E_AUTHZ_CONFIG — y lo que LANZA el manager es esa letra, byte a byte', async ({
    assert,
  }) => {
    const body = section(await readme(), HEADING)
    assert.include(body, '`assertWrite` is **synchronous, pure and has no `actor`** on purpose (R-13)')
    assert.include(body, 'runs after F-05 and before the driver')
    assert.include(body, 'returning a promise is 500 `E_AUTHZ_CONFIG`')
    assert.include(body, 'the write went in')
    // La letra del 500, byte a byte (patrón `trx_docs.spec.ts:145`).
    const config = contractRelationsConfig()
    const manager = new RelationsManager(makeRelationsDriver({ config, capabilities: CAPS }), config, {
      assertWrite: (async () => {}) as any,
    })
    let caught: any
    try {
      await manager.relate({ type: 'user', uuid: uuidv7() }, 'viewer', { type: 'document', id: uuidv7() }, { type: 'unit', uuid: uuidv7() })
    } catch (error) {
      caught = error
    }
    assert.instanceOf(caught, AuthorizationConfigError)
    assert.equal(caught.message, AuthorizationConfigError.asyncAssertWrite('relations.relate').message)
    for (const phrase of ['relations.relate:', 'devolvió una promesa', 'SÍNCRONO y puro (R-13)', 'fail-open', 'No se ha tocado el driver', 'servicio del consumidor', 'ANTES de llamar a relate/unrelate']) {
      assert.include(caught.message, phrase, `la letra lleva «${phrase}»`)
    }
  })

  test('F5 · el cableado: relations.assertWrite / relations.onRelationWrite / relations.requireActor (anula el raíz por puerto, como relations.requireTransactionalWrites); un hook que lanza se registra y no tumba; requireActor alcanza a las purgas (breaking)', async ({
    assert,
  }) => {
    const body = section(await readme(), HEADING)
    assert.include(body, '`relations.assertWrite`')
    assert.include(body, '`relations.onRelationWrite`')
    assert.include(body, '`relations.requireActor`')
    assert.include(body, 'overrides the root per port')
    assert.include(body, '`relations.requireTransactionalWrites`')
    assert.include(body, 'not in `hooks`')
    assert.include(body, 'hook that throws — sync or async — is logged and swallowed')
    assert.include(body, '`requireActor` now reaches `purgeObject`/`purgeSubject`')
    assert.include(body, 'a malformed `actor` is 422 `E_AUTHZ_INVALID_IDENTITY` before the driver')
  })

  test('F6 · no-regresión: el README conserva que manager.driver() se salta actor, assertWrite y onRelationWrite (F-05 ya no)', async ({ assert }) => {
    const text = await readme()
    // La frase de `README.md:565-566` (escrita en L-0) va partida en dos líneas: se acepta cualquier blanco.
    assert.match(
      text,
      /`manager\.driver\(\)` still skips the manager's \*other\* barriers \(`actor`,\s+`assertWrite`, `onRelationWrite`\)/,
      'ROJO: la frase «manager.driver() still skips the manager\'s other barriers (actor, assertWrite, onRelationWrite)» tiene que CONSERVARSE'
    )
    assert.include(section(text, HEADING), '`manager.driver()` still skips')
  })

  test('la tabla de errores nombra el assertWrite async bajo E_AUTHZ_CONFIG y las purgas bajo E_AUTHZ_ACTOR_REQUIRED', async ({ assert }) => {
    const text = await readme()
    const configRow = text.split('\n').find((line) => line.startsWith('| `E_AUTHZ_CONFIG` |')) ?? ''
    assert.include(configRow, 'a `relations.assertWrite` that returns a promise')
    assert.include(configRow, 'or any value at all', 'cierre 🟠 3: la fila del 500 dice que TODO retorno es el error')
    const actorRow = text.split('\n').find((line) => line.startsWith('| `E_AUTHZ_ACTOR_REQUIRED` |')) ?? ''
    assert.include(actorRow, '`purgeObject`/`purgeSubject`')
  })
})

/**
 * **Cierre de alpha.3 (auditor NO APTA, decisiones 2026-09-02 (2c)) — las
 * frases nuevas, con dientes.** F7 · el sink está en el camino crítico (🟡 5,
 * decisión: sin deadline, paridad con roles); F8 · «did not happen» reescrito
 * para `openfga` (🟡 6: una purga parcial es `indeterminate: true`); F9 ·
 * `assertWrite` no devuelve veredictos (🟠 3 / 🟡 4); F10 · F-05 en las siete
 * operaciones (🔴 1 / 🟠 2); F11 · `relations.requireActor: false` sobre un
 * raíz `true` ANULA el raíz sin aviso (⚪ 12); F12 · `actor: null` es 422
 * (⚪ 10, BREAKING en el CHANGELOG).
 */
test.group('cierre alpha.3 · F7–F12 · el README y el CHANGELOG dicen lo del cierre con estas palabras', () => {
  test('F7 · 🟡 5 · el sink se await-ea, está en el camino crítico de la escritura y, con { transaction }, dentro de tu transacción; un sink que no resuelve la mantiene abierta; difiere lo lento a trx.after(commit) o a una cola', async ({
    assert,
  }) => {
    const body = section(await readme(), HEADING)
    assert.include(body, 'the sink is **awaited**', 'ROJO: el README no dice que el sink se espera')
    assert.include(body, 'on the critical path of the write')
    assert.include(body, 'with `{ transaction }`, inside your transaction')
    assert.include(body, 'a sink that never resolves keeps it open')
    assert.include(body, 'defer anything slow to `trx.after(\'commit\')` or to a queue')
    assert.include(body, 'no deadline', 'la decisión (paridad con roles) está escrita, no escondida')
  })

  test('F8 · 🟡 6 · «that write did not happen» queda acotado: cierto en database (one DELETE) y en openfga solo si nada se borró; una purga multi-request que falla tras borrar es indeterminate: true', async ({
    assert,
  }) => {
    const body = section(await readme(), HEADING)
    // La frase ABSOLUTA de alpha.3 («A 503 that is not a timeout, a 422 … that write did not happen») era falsa en las purgas de openfga.
    assert.notInclude(body, 'A 503 that is not a timeout, a 422', 'ROJO: la frase absoluta sigue publicada')
    assert.include(body, 'an `assertWrite` that throws and the freeze emit **nothing** and call nothing: that write did not happen', 'lo que SÍ es verdad se conserva (422, assertWrite, freeze)')
    assert.include(body, 'a purge on `openfga` is **not one request**')
    assert.include(body, 'fails **after** it has already deleted')
    assert.include(body, 'notifies `indeterminate: true` as well')
    assert.include(body, 'on `database` a purge is one `DELETE`')
    assert.include(body, 'on `openfga` only when nothing had been deleted yet')
    assert.include(body, '`markPartialWrite`')
  })

  test('F9 · 🟠 3 / 🟡 4 · assertWrite does not return verdicts: any returned value — false, true, a thenable function — is 500 E_AUTHZ_CONFIG before the driver', async ({ assert }) => {
    const body = section(await readme(), HEADING)
    assert.include(body, '`assertWrite` **does not return verdicts**')
    assert.include(body, 'returning `false` did not refuse anything')
    assert.include(body, '**any value at all** — `false`, `true`, a thenable *function*')
    assert.include(body, 'is 500 `E_AUTHZ_CONFIG` before the driver')
  })

  test('F10 · 🔴 1 / 🟠 2 · F-05 covers the eight operations: purges and reads too (membersOf included, cierre-2), in the manager and in both drivers, with the exploit pinned against the shared store; and the relation is mandatory (two functions, not an optional)', async ({ assert }) => {
    const text = await readme()
    assert.include(text, 'F-05 covers **all eight operations of the port**')
    assert.notInclude(text, 'all seven operations of the port', 'cierre-2: membersOf era la octava')
    assert.include(text, '`membersOf`')
    assert.include(text, 'two functions, not an optional')
    assert.include(text, '`assertObjectTypeDeclared`')
    assert.include(text, 'a missing `relation` (`undefined`) is 422 `E_AUTHZ_RELATION_UNKNOWN`')
    assert.include(text, '`purgeObject({ type: \'role_binding\', id: R }, S)`')
    assert.include(text, 'deleted the real binding')
    assert.include(text, '`listSubjects(\'assignee\', role_binding)`')
    assert.include(text, 'in the manager **and** in both drivers')
    const body = section(text, HEADING)
    assert.include(body, 'F-05 runs first on the purges too')
  })

  test('F11 · ⚪ 12 · relations.requireActor: false under a root requireActor: true overrides the root for relations silently (warnOnOptInSecurity does not cover it)', async ({ assert }) => {
    const body = section(await readme(), HEADING)
    assert.include(body, '`relations.requireActor: false` under a root `requireActor: true` **overrides the root for relations, silently**')
    assert.include(body, '`warnOnOptInSecurity` does not cover it')
  })

  test('F12 · ⚪ 10 · el CHANGELOG anuncia actor: null ⇒ 422 como BREAKING, el hallazgo del auditor como «problema → decisión», el assertWrite que devuelve y el indeterminate parcial', async ({ assert }) => {
    const changelog = await readFile(new URL('../CHANGELOG.md', import.meta.url), 'utf8')
    const unreleased = changelog.slice(0, changelog.indexOf('## [2.4.0-alpha.2]'))
    assert.include(unreleased, '`actor: null`', 'ROJO: el CHANGELOG no anuncia actor: null')
    assert.match(unreleased, /\*\*BREAKING\*\*[^\n]*`actor: null`|`actor: null`[^\n]*\*\*BREAKING\*\*|BREAKING[\s\S]{0,400}`actor: null`/)
    assert.include(unreleased, 'F-05 did not cover `purgeObject`')
    assert.include(unreleased, 'pre-existing in alpha.2')
    assert.include(unreleased, 'does not return verdicts')
    assert.include(unreleased, 'markPartialWrite')
  })

  test('F13 · cierre-2 · el CHANGELOG anuncia como BREAKING que las lecturas (check/listSubjects/listObjects/membersOf) lanzan 422 con tipo o relación no declarados en vez de responder, y registra la regresión de la relación opcional como problema → decisión', async ({ assert }) => {
    const changelog = await readFile(new URL('../CHANGELOG.md', import.meta.url), 'utf8')
    const unreleased = changelog.slice(0, changelog.indexOf('## [2.4.0-alpha.2]'))
    assert.match(unreleased, /\*\*BREAKING\*\*[^\n]*the reads/, 'ROJO: las lecturas que lanzan no están en la lista de BREAKING')
    assert.include(unreleased, '`check`/`listSubjects`/`listObjects`/`membersOf`')
    assert.include(unreleased, 'instead of answering')
    assert.match(unreleased, /making `relation`\s+optional/, 'la regresión de la relación opcional está contada como problema → decisión')
    assert.include(unreleased, '`assertObjectTypeDeclared`')
  })
})
