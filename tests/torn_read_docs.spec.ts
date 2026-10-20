/**
 * **La letra del lector rasgado y de F4** (lote «antes de RC» · sublote 3; decisiones del dueño (6a), (6b) y
 * (6b-estudio)). Una frase de docs sin caso es una promesa (patrón `trx_docs.spec.ts`): la fila «torn read» de Limits con
 * sus cifras, «atómico» solo PARA EL ESCRITOR, la garantía del orden sobre PREFIJOS (no sobre lectores), README:459 sin
 * «hereda el fail-open del lag» (era falso: el prefijo GANABA un acceso que el deny quitaba) y los invariantes 2 y 18 de
 * CLAUDE.md con los textos aprobados. Si alguien suaviza o borra la declaración, rojo.
 */
import { test } from '@japa/runner'
import { readFile } from 'node:fs/promises'

const read = (path: string) => readFile(new URL(`../${path}`, import.meta.url), 'utf8')

test.group('F4 · la letra del lector rasgado (fila «torn read», «atómico para el escritor», «ningún PREFIJO»)', () => {
  test('Limits lleva la fila «Torn read» con las cifras medidas, quién lo provoca, «nunca persistido» y `database` fuera', async ({ assert }) => {
    const readme = await read('README.md')
    const limits = readme.slice(readme.indexOf('### Limits'), readme.indexOf('### Operational notes for the SQL engines'))
    const row = limits.split('\n').find((line) => line.startsWith('| **Torn read**'))
    assert.isString(row, 'falta la fila «Torn read» en Limits')
    // Cierre de F4 (🟡-5b del tester): también las cifras de purga y reconcile y «no cachear»; y la cifra de F4 es la
    // medida con c2r por el auditor (🟡 3), con fuente y condiciones — no la de c3u sobre el arnés.
    for (const phrase of ['1.2–7.1 %', 'whoever moves scopes', 'never persisted', '`database` has none', '~10⁻⁵', 'F4', 'prefixes', 'atomic for the writer', '1.4–1.8 %', '0.02 %', 'do not cache `authorize`', '~1.8·10⁻³ on a DESCENDANT', 'published model (c2r)', 'F4 audit']) {
      assert.include(row!, phrase, `la fila «Torn read» no dice «${phrase}»`)
    }
    assert.notInclude(row!, 'which includes the two `Write`s of the F4 sweep (1 in 50,000', 'la cifra de c3u atribuida a F4')
  })

  test('Limits declara las CARRERAS ENTRE ESCRITORES de roles en `openfga` como límite PROVISIONAL, persistente hasta el reconcile (decisión (F4-carreras))', async ({ assert }) => {
    const readme = await read('README.md')
    const limits = readme.slice(readme.indexOf('### Limits'), readme.indexOf('### Operational notes for the SQL engines'))
    const row = limits.split('\n').find((line) => line.startsWith('| **Races between writers of the `openfga` role driver**'))
    assert.isString(row, 'falta la fila de las carreras entre escritores')
    for (const phrase of ['PROVISIONAL', 'before the release candidate', '`projectCatalogRole`', 'OLD chain', 'relay lag', 'INLINE', 'EVERY local role', 'PERSISTS', '`authz:reconcile', 'across tenants']) {
      assert.include(row!, phrase, `la fila de las carreras no dice «${phrase}»`)
    }
  })

  test('ninguna línea del README dice «atómico» de un `Write` de OpenFGA sin «para el escritor», ni promete `atomicRenewal: true` con el upsert', async ({ assert }) => {
    const readme = await read('README.md')
    const offenders = readme
      .split('\n')
      .map((line, index) => ({ line, index }))
      .filter(({ line }) => /one atomic `Write`|applies atomically|atomic `Write`/.test(line) && !/atomic(ally)? for the writer/.test(line))
      .map(({ line, index }) => `README.md:${index + 1}: ${line.slice(0, 160)}`)
    assert.deepEqual(offenders, [], 'promete atomicidad a un lector concurrente')
    assert.notInclude(readme, '`atomicRenewal` will become `true`', 'un upsert no se ha medido contra un lector concurrente')
  })

  test('README: el barrido de roles locales ya no «hereda el fail-open del lag» y dice que falla CERRADO desde F4', async ({ assert }) => {
    const readme = await read('README.md')
    assert.notInclude(readme, 'so it inherits the [temporary fail-open of the relay lag]')
    // Cierre de F4 (🟡-5b del tester, 🟠 1 / 🟡 4 del auditor): ni el titular absoluto «the sweep itself never grants» ni
    // «the lag keeps old access» / «the old tree keeps deciding» sin matiz (un `grant` durante el lag al ENTRAR concede).
    assert.notInclude(readme, 'the sweep itself never grants')
    assert.notInclude(readme, 'the lag keeps old access')
    assert.notInclude(readme, 'during which the old tree keeps deciding —')
    assert.notInclude(readme, 'and nothing crosses tenants')
    assert.include(readme, "**since 2.5.0-alpha.4 (F4) a `moved` cut between its own writes never leaves a state that grants**")
    assert.include(readme, 'What F4 removes is that intermediate STATE; a single check that spans two writes can still read one before and one after')
    assert.include(readme, 'deletes the `scope#binding` edges the NEW chain forbids before writing the tree edge')
    assert.include(readme, 'fails **closed** — the user loses the local role early, never gains it')
  })

  test('las fuentes dicen PREFIJO, no «ningún estado intermedio» ni «sin estado intermedio» (la fuerza bruta demuestra prefijos)', async ({ assert }) => {
    const order = await read('src/relations/tuple_order.ts')
    assert.notInclude(order, 'ningún estado intermedio concede')
    assert.include(order, 'ningún PREFIJO')
    const relations = await read('src/drivers/openfga_relations_driver.ts')
    assert.notInclude(relations, 'NO hay estado intermedio que cortar')
    assert.notInclude(relations, 'es UN `Write`, sin estado\n')
    const roles = await read('src/drivers/openfga_driver.ts')
    assert.notInclude(roles, 'que es atómico dentro de la request')
  })

  test('CLAUDE.md: invariante 2 con la excepción declarada de `openfga` (1,2–7,1 %, cambio de árbol de roles) e invariante 18 sin «hereda el fail-open del lag»', async ({ assert }) => {
    const claude = await read('CLAUDE.md')
    const inv2 = claude.slice(claude.indexOf('2. **Deny explícito gana.**'), claude.indexOf('3. **Expiración observable sin scheduler.**'))
    for (const phrase of ['Excepción declarada (`openfga`)', 'cambio de árbol de roles', '1,2–7,1 %', 'nunca persistido', '«torn read»', '`database` no la tiene']) {
      assert.include(inv2, phrase, `invariante 2 sin «${phrase}»`)
    }
    const inv18 = claude.slice(claude.indexOf('18. **Un rol local solo existe dentro de su owner**'), claude.indexOf('16. **`authorizedScopes` es coherente'))
    assert.notInclude(inv18, 'hereda el fail-open temporal del lag del relay')
    assert.include(inv18, 'el barrido falla CERRADO')
  })
})
