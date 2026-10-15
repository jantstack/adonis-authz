/**
 * **`relationTupleKey` — la clave PURA y estable de una tupla de relación**
 * (plan 2.5 · lote A, P3 del 7.º informe de COGNITIV; `panel-tenencia-juez.md`
 * §P3: «sin `meta` en el paquete; clave pura sí»).
 *
 * Determinista e inyectiva sobre los cinco componentes que identifican una
 * tupla —`kind`, partición, objeto (tipo + id), relación y sujeto (holder o
 * userset)— y SOLO sobre ellos: la caducidad no entra (renovarla no cambia la
 * identidad; en `database` sí cambia el uuid de fila, que por eso tampoco
 * sirve de clave), y el `uuid` de fila o el id del store tampoco. Es la clave
 * que `reconcileRelations` usa para casar origen y destino, y la que un
 * consumidor puede usar para indexar sus propios metadatos sobre una tupla
 * sin que el paquete los guarde.
 *
 * **`kind` desde el primer día, con literal de oro**: el lote D trae el deny
 * como tuplas `kind: 'deny'`. Para que un deny y un allow sobre la misma
 * terna nunca colapsen en una clave —y para que la clave de un allow que ya
 * está en un índice del consumidor NO cambie cuando llegue el deny—, el
 * `kind` va en la clave desde ahora (OBLIGATORIO, sin default: ⚪ A9) y
 * `tests/relation_tuple_key.spec.ts` fija el literal exacto de un allow.
 *
 * Forma: `<kind>|<scopeKey(partition)>|<object.type>:<object.id>#<relation>@<subject>`,
 * con `<subject>` = `<type>:<uuid>` (holder) o `<type>:<id>#<relation>`
 * (userset). Ningún componente admite `|`, `#`, `:` ni `@` —la gramática de
 * identidad se APLICA aquí a cada componente (⚪ A9), no se presupone—, así
 * que el parseo es unívoco.
 *
 * Pureza (regla 2): solo el puerto y la gramática de identidad.
 */
import { InvalidIdentityError } from '../errors.js'
import { assertRelationId, assertSubject, scopeKey } from '../identity.js'
import { isRelUserset } from '../types.js'
import type { RelObject, RelSubject, ScopeRef } from '../types.js'

export type RelationTupleKind = 'allow' | 'deny'

/**
 * Lo que identifica una tupla: la forma de `RelationTuple` más el `kind`,
 * **obligatorio y sin default** (⚪ A9 del auditor del lote A): `allow` por
 * omisión era el modo de fallo peligroso —un deny enumerado por un driver que
 * no pusiera `kind` casaría con el allow en `reconcileRelations`—. Quien
 * casa tuplas dice de qué clase son.
 */
export interface RelationTupleIdentity {
  partition: ScopeRef
  object: RelObject
  relation: string
  subject: RelSubject
  kind: RelationTupleKind
}

/**
 * La clave de un SUJETO: holder `<type>:<uuid>`, userset `<type>:<id>#<relation>`.
 * Valida sus componentes con la gramática de identidad (⚪ A9): sin ella
 * `{ relation: 'b@user:c#d' }` y un userset legítimo daban la MISMA clave y
 * el «parseo unívoco» del docblock era falso.
 */
export function relationSubjectKey(subject: RelSubject): string {
  if (isRelUserset(subject)) {
    assertRelationId('el tipo del objeto del userset', subject.object?.type)
    assertRelationId(`el id del objeto '${subject.object?.type}' del userset`, subject.object?.id)
    assertRelationId('la relación del userset', subject.relation)
    return `${subject.object.type}:${subject.object.id}#${subject.relation}`
  }
  assertSubject(subject)
  return `${subject.type}:${subject.uuid}`
}

export function relationTupleKey(tuple: RelationTupleIdentity): string {
  const kind: unknown = tuple?.kind
  if (kind !== 'allow' && kind !== 'deny') {
    throw new InvalidIdentityError(
      `relationTupleKey: kind inválido ${kind === undefined ? 'ausente' : `'${String(kind)}'`} ` +
        `(se exige 'allow' o 'deny', sin default: un deny sin kind casaría con el allow)`
    )
  }
  assertRelationId('el tipo del objeto', tuple.object?.type)
  assertRelationId(`el id del objeto '${tuple.object?.type}'`, tuple.object?.id)
  assertRelationId('la relación', tuple.relation)
  return `${kind}|${scopeKey(tuple.partition)}|${tuple.object.type}:${tuple.object.id}#${tuple.relation}@${relationSubjectKey(
    tuple.subject
  )}`
}
