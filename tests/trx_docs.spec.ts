/**
 * L-6 (panel `{trx}`, §7 · L-6): lo PUBLICADO sobre `{ transaction }` se
 * cumple o se reescribe. Tres dientes, sin servidor ni base:
 *
 * 1. **El grep**: el README no dice «atómico»/«atomic» de `openfga` en
 *    relación con la transacción del consumidor, en ninguna forma (patrón
 *    del grep de L-5 sobre el código, aplicado ahora a lo publicado). Y la
 *    sección de la receta por dirección no contiene la palabra en absoluto:
 *    la receta es un ORDEN de escritura que hace caer el fallo del lado
 *    cerrado, no atomicidad, y se dice con esas palabras.
 * 2. **La LETRA del 500** de la puerta 1 (patrón de `freeze.spec.ts` 3b-7):
 *    el mensaje nombra el driver, la operación, el porqué y LAS DOS salidas
 *    (`database` o `requireTransactionalWrites`); el del DRIVER `openfga`
 *    dice además que `manager.driver()` no es una salida y cuál es la
 *    alternativa que existe (la outbox del ÁRBOL); y el README documenta esa
 *    misma letra. Si alguien la suaviza, rojo.
 * 3. **La letra de L-6**: la receta por dirección con su límite («no
 *    compone») y «el paquete no lo automatiza», la frase del freeze ampliada
 *    (§6.3), el límite de `resolveChain` (§6.2) con su receta, pool ≥ 2 y la
 *    limitación para drivers de terceros — con las palabras exactas.
 */
import { test } from '@japa/runner'
import { readFile } from 'node:fs/promises'
import { v7 as uuidv7 } from 'uuid'
import { AuthorizationManager } from '../src/manager.js'
import { RelationsManager } from '../src/relations/manager.js'
import { UnsupportedOperationError } from '../src/errors.js'
import { APP_SCOPE } from '../src/types.js'
import { makeRelationsDriver, contractRelationsConfig } from '../src/testing/relations_contract.js'

async function readme(): Promise<string> {
  return readFile(new URL('../README.md', import.meta.url), 'utf8')
}

/** Lo que un `TransactionClientContract` de Lucid le enseña al paquete (la forma, no un motor). */
const fakeTrx = () => ({ from() {}, table() {}, isTransaction: true as const, connectionName: 'sqlite' })

const RECIPE_HEADING = '#### `openfga`: the recipe by direction'

/** El texto de una sección del README: desde su cabecera hasta la siguiente cabecera (`###`/`####`). */
function section(text: string, heading: string): string {
  const start = text.indexOf(heading)
  if (start < 0) return ''
  const rest = text.slice(start + heading.length)
  const next = rest.search(/\n#{2,4} /)
  return heading + (next < 0 ? rest : rest.slice(0, next))
}

test.group('L-6 · el README no dice «atómico» de openfga con la transacción del consumidor (grep con dientes)', () => {
  const ATOMIC = /at[oó]mic/i
  /** Una línea que habla de `openfga` o de su store. */
  const OPENFGA_ISH = /openfga|\bFGA\b|tuple|\bstore\b/i
  /** …y a la vez de la transacción del consumidor. */
  const CONSUMER_TRANSACTION =
    /\{ ?transaction ?\}|your (?:own |open |SQL )?transaction|caller'?s transaction|consumer'?s transaction|transactionalWrites: true|both or neither/i

  test('ninguna línea del README dice «atómico» de openfga/FGA/tuple/store hablando a la vez de la transacción del consumidor (y el grep mira algo)', async ({
    assert,
  }) => {
    const lines = (await readme()).split('\n')
    const offenders: string[] = []
    let atomicLines = 0
    lines.forEach((line, index) => {
      if (!ATOMIC.test(line)) return
      atomicLines += 1
      if (OPENFGA_ISH.test(line) && CONSUMER_TRANSACTION.test(line)) offenders.push(`README.md:${index + 1}: ${line.slice(0, 160)}`)
    })
    assert.isAbove(atomicLines, 0, 'el grep tiene que estar mirando algo: «atomic» aparece en el README (el Write de FGA, purgeRole…)')
    assert.deepEqual(offenders, [], 'el README promete atomicidad de openfga con la transacción del consumidor en:\n' + offenders.join('\n'))
  })

  test('la sección de la receta por dirección existe y NO contiene «atómico»/«atomic» en ninguna forma: es un orden de escritura, no atomicidad', async ({
    assert,
  }) => {
    const text = await readme()
    const recipe = section(text, RECIPE_HEADING)
    assert.isAbove(recipe.length, RECIPE_HEADING.length + 200, `el README tiene la sección «${RECIPE_HEADING}» con cuerpo`)
    assert.notMatch(recipe, ATOMIC, 'la receta por dirección no puede decir «atómico» de ninguna forma:\n' + recipe)
    // Lo que sí dice, con estas palabras (§1.1/§1.3 del juez):
    assert.include(recipe, 'This is not "both or neither"', 'la receta no es la promesa de la capacidad')
    assert.include(recipe, 'fail-closed', 'los dos modos de fallo caen del lado cerrado')
    assert.include(recipe, 'it does not compose', 'el límite, escrito')
    assert.include(recipe, 'The package does not automate it', 'lo fija un caso contra el servidor real')
  })
})

test.group('L-6 · la LETRA del 500 de la puerta: nombra driver, operación, porqué y las dos salidas — y el README dice lo mismo', () => {
  test('UnsupportedOperationError.transactional (puerta 1, los dos puertos): driver, operación, «transacción SQL», salida database y salida requireTransactionalWrites (la de relaciones nombra relations.requireTransactionalWrites)', ({
    assert,
  }) => {
    const roles = UnsupportedOperationError.transactional('grant', 'openfga', 'roles')
    assert.equal(roles.status, 500)
    assert.equal(roles.code, 'E_AUTHZ_UNSUPPORTED')
    for (const phrase of [
      'grant:',
      `'openfga'`,
      'transactionalWrites: false',
      'una tupla no entra en una transacción SQL',
      'No se ha tocado el driver',
      `usa el driver 'database' para los hechos`,
      'requireTransactionalWrites: true en config/authorization.ts',
      'falle al ARRANCAR',
      'Sin { transaction } la misma llamada entra',
    ]) {
      assert.include(roles.message, phrase, `roles · la letra lleva «${phrase}»`)
    }
    assert.notInclude(roles.message, 'relations.requireTransactionalWrites', 'roles: no nombra la bandera del otro puerto')

    const relations = UnsupportedOperationError.transactional('relations.relate', 'openfga', 'relations')
    for (const phrase of [
      'relations.relate:',
      `'openfga'`,
      `usa el driver 'database' para las relaciones`,
      'relations.requireTransactionalWrites',
      'falle al ARRANCAR',
      'Sin { transaction } la misma llamada entra',
    ]) {
      assert.include(relations.message, phrase, `relations · la letra lleva «${phrase}»`)
    }
  })

  test('UnsupportedOperationError.transactionalDriver (el DRIVER openfga, L-5): la MISMA letra más «manager.driver() no es una salida», la outbox del ÁRBOL como alternativa que existe y «no hay outbox» para hechos y relaciones', ({
    assert,
  }) => {
    const gate = UnsupportedOperationError.transactional('grant', 'openfga', 'roles')
    const driver = UnsupportedOperationError.transactionalDriver('grant', 'openfga', 'roles')
    assert.equal(driver.code, gate.code)
    assert.equal(driver.status, gate.status)
    assert.isTrue(driver.message.startsWith(gate.message), 'misma letra que la puerta 1, y después lo del driver')
    for (const phrase of [
      `Rechazado por el DRIVER 'openfga'`,
      'manager.driver() no es una salida',
      'scopes.outbox',
      'authz:scopes:relay',
      'para hechos y relaciones no hay outbox',
    ]) {
      assert.include(driver.message, phrase, `driver · la letra lleva «${phrase}»`)
    }
    // Y la delegación dice por qué no admite { transaction }: el serializador del catálogo.
    const catalog = UnsupportedOperationError.transactionalCatalog('defineScopedRole')
    assert.include(catalog.message, 'withAuthzCatalogWrite')
    assert.include(catalog.message, 'invariante 14')
  })

  test('lo que LANZA el manager es esa letra, byte a byte (roles y relaciones), no una versión suavizada', async ({ assert }) => {
    const rolesDriver: any = {
      capabilities: Object.freeze({ transactionalWrites: false }),
      grant: async () => ({ existed: false, expiresAt: null }),
      authorize: async () => false,
    }
    const manager = new AuthorizationManager({
      default: 'fake',
      drivers: { fake: () => rolesDriver },
      warnOnOptInSecurity: false,
    } as any)
    let caught: any
    try {
      await manager.grant({ type: 'users', uuid: uuidv7() }, 'editor', APP_SCOPE, { transaction: fakeTrx() })
    } catch (error) {
      caught = error
    }
    assert.instanceOf(caught, UnsupportedOperationError)
    assert.equal(caught.message, UnsupportedOperationError.transactional('grant', 'fake', 'roles').message)

    const config = contractRelationsConfig()
    const relations = new RelationsManager(
      makeRelationsDriver({
        config,
        capabilities: {
          singleCheckRelations: true,
          listObjectsInherited: false,
          usersetSubjects: true,
          membersOfNative: true,
          enumerateRelations: true,
          listObjectsTruncation: false,
          injectableClock: true,
          transactionalWrites: false,
        },
      }),
      config,
      { driverName: 'openfga' }
    )
    let caughtRelation: any
    try {
      await relations.relate(
        { type: 'user', uuid: uuidv7() },
        'viewer',
        { type: 'document', id: uuidv7() },
        APP_SCOPE,
        { transaction: fakeTrx() }
      )
    } catch (error) {
      caughtRelation = error
    }
    assert.instanceOf(caughtRelation, UnsupportedOperationError)
    assert.equal(caughtRelation.message, UnsupportedOperationError.transactional('relations.relate', 'openfga', 'relations').message)
  })

  test('el README documenta esa letra: nombra driver y operación, cero llamadas, y las dos salidas', async ({ assert }) => {
    const text = await readme()
    assert.include(text, 'the message names the driver and the operation, nothing was called')
    assert.include(text, 'the way out is the `database` driver or `requireTransactionalWrites`')
    assert.include(text, 'entering through `manager.driver()` is not a way out')
  })
})

test.group('L-6 · el README dice lo de L-6 con estas palabras (la receta, el freeze ampliado, resolveChain, pool ≥ 2, terceros)', () => {
  test('la frase del freeze AMPLIADA (§6.3): la autoridad va por la conexión del motor, un snapshot del llamante no la salta, la ventana es tan larga como tu transacción, y lo que NO congela sigue escrito por su nombre', async ({
    assert,
  }) => {
    const text = await readme()
    // Lo de 3b-7 sigue (el caso de `freeze.spec.ts` lo fija; aquí solo la ampliación).
    assert.include(text, 'does NOT freeze')
    assert.include(text, 'never through your transaction')
    assert.include(text, 'a snapshot taken before the freeze does not skip it')
    assert.include(text, 'as long as your transaction')
    assert.include(text, 'requires a pool of at least 2')
  })

  test('el límite de resolveChain dentro de una transacción (§6.2) con su receta: el árbol se juzga contra el estado PRE-transacción; quien mueva el árbol Y escriba hechos en la misma transacción notifica scopes.* ANTES (y con outbox, encola)', async ({
    assert,
  }) => {
    const text = await readme()
    assert.include(text, 'the tree is judged against the state before your transaction')
    assert.include(text, 'notify `authorization.scopes.*` first')
    assert.include(text, 'a `ScopeChainResolver` that closes over your transaction')
    assert.include(text, 'E_AUTHZ_UNKNOWN_SCOPE')
  })

  /**
   * **alpha.3 · B5/F1 — la frase que L-6 ya publicó y ningún caso sujetaba
   * (hallazgo H4 del tester).** `README.md` (§«Writing inside your
   * transaction») dice que `onWrite`/`onRelationWrite` disparan con
   * `transactional: true`: era FALSO para `onRelationWrite` desde que se
   * escribió. Desde alpha.3 es verdad (B1/B2/E4) y la letra queda sujeta:
   * los DOS puertos en la misma frase, la marca y la receta del commit.
   */
  test('alpha.3 · B5/F1 · la frase «onWrite/onRelationWrite fire when the driver returns, with transactional: true» sigue en el README, con los DOS puertos, la marca y la receta trx.after(commit)', async ({
    assert,
  }) => {
    const text = await readme()
    const sentence = text.split('\n').find((line) => line.includes('`onWrite`/`onRelationWrite` fire when the driver returns'))
    assert.isString(sentence, 'ROJO: la frase de L-6 no está (o cambió sin su caso)')
    assert.include(sentence!, '`onWrite`/`onRelationWrite` fire when the driver returns')
    assert.include(sentence!, '`transactional: true`')
    assert.include(sentence!, "trx.after('commit')")
  })

  test('la limitación para drivers de terceros, en voz alta: «los dos o ninguno» es una garantía del driver database del paquete; el runner exige el censo pero no puede probar lo que hace un driver ajeno por dentro', async ({
    assert,
  }) => {
    const text = await readme()
    assert.include(text, 'a guarantee of this package\'s `database` driver')
    assert.include(text, 'the runner requires the census')
    assert.include(text, 'cannot prove that a third-party driver')
  })
})
