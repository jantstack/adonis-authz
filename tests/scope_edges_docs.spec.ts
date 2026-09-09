/**
 * **E-1 · el diente de LETRA de `sqlScopeEdges` multi-tabla** (2.4.0-alpha.4;
 * pregunta 2 de COGNITIV, panel alpha.4 — el hallazgo del analista). El
 * helper cubre UNA tabla (LEFT JOIN contra sí misma) y descarta en silencio
 * la fila cuyo padre vive en otra: concatenar varios `sqlScopeEdges` NO
 * emite las aristas entre tablas, y con `authz:reconcile --prune` el destino
 * las borra ⇒ el subárbol entero deniega (invariante 9, `rooted`).
 *
 * Una frase de docs sin caso es una promesa (patrón `trx_docs.spec.ts`): si
 * alguien suaviza o borra la advertencia, rojo. El diente EJECUTABLE (E-2,
 * dos tablas nuevas en el espejo, ×4 motores) va con el helper de
 * composición en 2.6 — y el README lo dice: «receta no verificada por la
 * suite».
 */
import { test } from '@japa/runner'
import { readFile } from 'node:fs/promises'

const HEADING = '### Migrating and verifying: `authz:reconcile` (2.3)'

function section(text: string, heading: string): string {
  const start = text.indexOf(heading)
  if (start < 0) return ''
  const rest = text.slice(start + heading.length)
  const next = rest.search(/\n#{2,3} /)
  return heading + (next < 0 ? rest : rest.slice(0, next))
}

test.group('alpha.4 · E-1 · el README dice que sqlScopeEdges cubre UNA tabla, que concatenarlos no vale, por qué, y cómo se escribe el propio', () => {
  test('la sección de authz:reconcile lleva la advertencia con estas palabras', async ({ assert }) => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8')
    const text = section(readme, HEADING)
    assert.isNotEmpty(text, `falta la sección «${HEADING}»`)
    // (a) una sola tabla
    assert.include(text, '`sqlScopeEdges` covers ONE table')
    // (b) la concatenación NO vale, y por qué: LEFT JOIN contra sí misma + silencio
    assert.include(text, 'concatenating several does not cover a tree that lives in more than one')
    assert.include(text, '`LEFT JOIN` of the table *against itself*')
    assert.include(text, 'skipped in silence')
    assert.include(text, '**does not emit the edges between tables**')
    // …y la consecuencia con --prune: el subárbol entero deniega
    assert.include(text, 'deletes them')
    assert.include(text, '**the whole subtree denies**')
    assert.include(text, 'invariant 9')
    // (c) el cómo: enumerateEdges propio, UNION ALL, cursor estable, parent IS NULL = app
    assert.include(text, 'Write your own `enumerateEdges`')
    assert.include(text, '`UNION ALL`')
    assert.include(text, '`parent IS NULL` meaning `app`')
    assert.include(text, 'total and stable')
    assert.include(text, '--dry-run')
    // (d) una arista cuyo padre no está en NINGUNA tabla no se emite
    assert.include(text, 'emitting an edge only when the parent exists in *any* of the tables')
    // Sin caso ejecutable, la frase lo confiesa; y el helper queda en 2.6.
    assert.include(text, '*Recipe not verified by the suite*')
    assert.include(text, '`composeScopeEdges`')
    assert.include(text, 'deferred to 2.6')
  })
})
