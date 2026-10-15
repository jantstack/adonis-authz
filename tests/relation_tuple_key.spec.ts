/**
 * **`relationTupleKey` — la clave PURA de una tupla de relación** (plan 2.5 ·
 * lote A, P3; `panel-tenencia-2-tester.md` A-5, A-7, A-8).
 *
 *  - A-5 (P3-1): determinista e inyectiva sobre sus cinco componentes:
 *    holder vs userset con el mismo uuid, dos tipos con el mismo id, `app` vs
 *    partición tipada, `kind` allow/deny, relación. Mutante: quitar cualquier
 *    componente de la clave ⇒ dos tuplas distintas colapsan ⇒ rojo.
 *  - **Literal de ORO**: la clave de un ALLOW está fijada byte a byte. El lote D
 *    trae el deny como `kind: 'deny'`; la clave de un allow que un consumidor
 *    ya tenga en un índice NO cambia entonces (el `kind` va desde hoy).
 *  - A-7 (P3-4): `src/relations/reconcile.ts` no define clave propia ni copia
 *    `scopeKey`: importa `relationTupleKey` y `scopeKey` (por fuente, patrón
 *    C5 de la guardia de superficie).
 *  - A-8 (P3-5): dos ortografías del uuid de partición son DOS claves (la clave
 *    no canoniza; D4 cierra la puerta de entrada, no la clave).
 *  - ⚪ A9 (auditor del lote A): `kind` es OBLIGATORIO (sin default `allow`: un
 *    deny enumerado sin kind casaría con el allow en reconcile) y objeto,
 *    relación y sujeto pasan por la gramática de identidad: las dos formas del
 *    auditor que daban la MISMA clave son 422, no una clave.
 */
import { test } from '@japa/runner'
import { readFileSync } from 'node:fs'
import { relationTupleKey, relationSubjectKey } from '../src/relations/tuple_key.js'
import { APP_SCOPE } from '../src/types.js'
import type { RelObject, RelSubject, ScopeRef } from '../src/types.js'

const U = '0192a000-0000-7000-8000-0000000000aa'
const D = '0192a000-0000-7000-8000-0000000000dd'
const P = '0192a000-0000-7000-8000-0000000000ff'
const unit: ScopeRef = { type: 'unit', uuid: P }
const doc: RelObject = { type: 'document', id: D }
const user: RelSubject = { type: 'user', uuid: U }

test.group('relationTupleKey (plan 2.5 · lote A, P3)', () => {
  test('literal de ORO: la clave de un ALLOW es exactamente esta, la de un deny sobre la misma terna es otra (kind delante), y kind OMITIDO es 422 (A9)', ({ assert }) => {
    const golden = `allow|unit|${P}|document:${D}#viewer@user:${U}`
    assert.equal(relationTupleKey({ partition: unit, object: doc, relation: 'viewer', subject: user, kind: 'allow' }), golden)
    assert.equal(relationTupleKey({ partition: unit, object: doc, relation: 'viewer', subject: user, kind: 'deny' }), `deny|unit|${P}|document:${D}#viewer@user:${U}`)
    assert.equal(relationTupleKey({ partition: APP_SCOPE, object: doc, relation: 'viewer', subject: user, kind: 'allow' }), `allow|app|document:${D}#viewer@user:${U}`)
    assert.equal(
      relationTupleKey({ partition: unit, object: doc, relation: 'viewer', subject: { object: { type: 'group', id: U }, relation: 'member' }, kind: 'allow' }),
      `allow|unit|${P}|document:${D}#viewer@group:${U}#member`
    )
    // ⚪ A9: `kind` OMITIDO no es `allow`, es 422 (sin default).
    const sinKind = (() => {
      try {
        relationTupleKey({ partition: unit, object: doc, relation: 'viewer', subject: user } as any)
        return null
      } catch (e) {
        return e as any
      }
    })()
    assert.equal(sinKind?.code, 'E_AUTHZ_INVALID_IDENTITY', 'ROJO (A9): kind omitido tiene que ser 422, no allow')
    assert.include(sinKind?.message, 'ausente')
  })

  test('P3-1 · determinista e inyectiva: cada componente distingue (holder vs userset mismo uuid, tipo del objeto, app vs tipada, kind, relación, partición, sujeto); la caducidad NO forma parte', ({ assert }) => {
    const base = { partition: unit, object: doc, relation: 'viewer', subject: user, kind: 'allow' as const }
    const variants: Array<[string, Parameters<typeof relationTupleKey>[0]]> = [
      ['base', base],
      ['holder → userset con el MISMO uuid', { ...base, subject: { object: { type: 'group', id: U }, relation: 'member' } }],
      ['otro tipo de objeto, mismo id', { ...base, object: { type: 'workspace', id: D } }],
      ['app en vez de la partición tipada', { ...base, partition: APP_SCOPE }],
      ['otra partición del mismo tipo', { ...base, partition: { type: 'unit', uuid: U } }],
      ['otro tipo de partición, mismo uuid', { ...base, partition: { type: 'org', uuid: P } }],
      ['kind deny', { ...base, kind: 'deny' as const }],
      ['otra relación', { ...base, relation: 'editor' }],
      ['otro sujeto', { ...base, subject: { type: 'admin', uuid: U } }],
      ['otro id de objeto', { ...base, object: { type: 'document', id: U } }],
      ['userset con otra relación', { ...base, subject: { object: { type: 'group', id: U }, relation: 'owner' } }],
    ]
    const keys = variants.map(([, t]) => relationTupleKey(t))
    assert.lengthOf(new Set(keys), variants.length, `claves que colapsan: ${variants.filter(([, t], i) => keys.indexOf(keys[i]) !== i).map(([l]) => l).join(', ')}`)
    for (const [label, t] of variants) assert.equal(relationTupleKey(t), relationTupleKey({ ...t }), `determinista: ${label}`)
    // La caducidad no es identidad (renovar no cambia la clave; en database cambia el uuid de fila y tampoco).
    assert.equal(relationTupleKey({ ...base, expiresAt: new Date('2030-01-01') } as any), relationTupleKey(base))
    assert.equal(relationSubjectKey(user), `user:${U}`)
    assert.equal(relationSubjectKey({ object: doc, relation: 'viewer' }), `document:${D}#viewer`)
  })

  test('un kind que no es allow|deny es 422, y una partición mal formada es 422 (la gramática de identidad)', ({ assert }) => {
    const bad = (fn: () => unknown) => {
      try {
        fn()
        return null
      } catch (e) {
        return e as any
      }
    }
    assert.equal(bad(() => relationTupleKey({ partition: unit, object: doc, relation: 'viewer', subject: user, kind: 'maybe' as any }))?.code, 'E_AUTHZ_INVALID_IDENTITY')
    assert.equal(bad(() => relationTupleKey({ partition: unit, object: doc, relation: 'viewer', subject: user, kind: null as any }))?.code, 'E_AUTHZ_INVALID_IDENTITY', 'A9: null tampoco es allow')
    assert.equal(bad(() => relationTupleKey({ partition: { type: 'unit', uuid: 'A#B' }, object: doc, relation: 'viewer', subject: user, kind: 'allow' }))?.code, 'E_AUTHZ_INVALID_IDENTITY')
  })

  /**
   * ⚪ A9: sin gramática en objeto/relación/sujeto, `{ relation: 'b@user:c#d', subject: user:e }`
   * y `{ relation: 'b', subject: {user:c}#'d@user:e' }` daban la MISMA clave. Ahora cada
   * componente pasa por `assertRelationId`/`assertSubject`: ambas son 422, y la clave es unívoca.
   */
  test('A9 · objeto, relación y sujeto pasan por la gramática de identidad: `|`, `#`, `:`, `@`, mayúsculas o vacío en cualquier componente ⇒ 422, y las dos formas que colapsaban del auditor son 422 (no una clave)', ({ assert }) => {
    const bad = (fn: () => unknown) => {
      try {
        fn()
        return null
      } catch (e) {
        return e as any
      }
    }
    const ok = { partition: unit, object: doc, relation: 'viewer', subject: user, kind: 'allow' as const }
    const attempts: Array<[string, Parameters<typeof relationTupleKey>[0]]> = [
      ['auditor 1: relación con @ y #', { ...ok, relation: 'b@user:c#d', subject: { type: 'user', uuid: 'e' } }],
      ['auditor 2: userset con @ en la relación', { ...ok, relation: 'b', subject: { object: { type: 'user', id: 'c' }, relation: 'd@user:e' } }],
      ['tipo de objeto con |', { ...ok, object: { type: 'doc|ument', id: D } }],
      ['id de objeto con #', { ...ok, object: { type: 'document', id: `${D}#x` } }],
      ['id de objeto vacío', { ...ok, object: { type: 'document', id: '' } }],
      ['relación con :', { ...ok, relation: 'vie:wer' }],
      ['relación en mayúsculas', { ...ok, relation: 'Viewer' }],
      ['holder con uuid con @', { ...ok, subject: { type: 'user', uuid: `${U}@x` } }],
      ['holder con tipo con #', { ...ok, subject: { type: 'us#er', uuid: U } }],
      ['userset con tipo con |', { ...ok, subject: { object: { type: 'gro|up', id: U }, relation: 'member' } }],
      ['userset con id con :', { ...ok, subject: { object: { type: 'group', id: `${U}:x` }, relation: 'member' } }],
      ['userset con relación vacía', { ...ok, subject: { object: { type: 'group', id: U }, relation: '' } }],
    ]
    for (const [label, tuple] of attempts) {
      const caught = bad(() => relationTupleKey(tuple))
      assert.isNotNull(caught, `ROJO (A9 · ${label}): salió una clave`)
      assert.equal(caught.code, 'E_AUTHZ_INVALID_IDENTITY', `${label}: ${caught.message}`)
      assert.equal(caught.status, 422, label)
    }
    // Y la clave válida sigue siendo la de oro (la validación no la altera).
    assert.equal(relationTupleKey(ok), `allow|unit|${P}|document:${D}#viewer@user:${U}`)
    assert.equal(relationSubjectKey({ object: { type: 'group', id: U }, relation: 'member' }), `group:${U}#member`)
  })

  test('P3-5 · dos ortografías del uuid de partición son DOS claves: la clave no canoniza (D4 cierra la puerta, no la clave)', ({ assert }) => {
    const dashed = relationTupleKey({ partition: unit, object: doc, relation: 'viewer', subject: user, kind: 'allow' })
    const dashless = relationTupleKey({ partition: { type: 'unit', uuid: P.replace(/-/g, '') }, object: doc, relation: 'viewer', subject: user, kind: 'allow' })
    assert.notEqual(dashed, dashless)
    assert.include(dashless, `|unit|${P.replace(/-/g, '')}|`)
  })

  test('P3-4 · reconcile.ts no define clave propia: importa relationTupleKey (de ./tuple_key.js) y scopeKey/assertPartition (de ../identity.js); sin `scopeKeyOf` ni `function tupleKey` locales', ({ assert }) => {
    const source = readFileSync(new URL('../src/relations/reconcile.ts', import.meta.url), 'utf8')
    assert.match(source, /import \{ relationTupleKey \} from '\.\/tuple_key\.js'/, 'importa la clave pura')
    assert.match(source, /import \{ assertPartition, scopeKey \} from '\.\.\/identity\.js'/, 'importa scopeKey y assertPartition de identity')
    assert.notMatch(source, /function\s+scopeKeyOf\s*\(/, 'sin copia de scopeKey')
    assert.notMatch(source, /function\s+tupleKey\s*\(/, 'sin clave propia')
    assert.notMatch(source, /function\s+subjectKey\s*\(/, 'sin clave de sujeto propia')
    assert.match(source, /const tupleKey = relationTupleKey/, 'el alias apunta a la función exportada (identidad de función)')
    assert.notInclude(source, '`${scope.type}|${scope.uuid}`', 'ninguna plantilla de clave de scope a mano')
  })
})
