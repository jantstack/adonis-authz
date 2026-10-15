/**
 * **`checkMany` — lo que comparten el manager y los dos drivers** (plan 2.5 ·
 * lote A, P4 del 7.º informe de COGNITIV; `panel-tenencia-juez.md` §P4):
 * el tope del lote, la validación de su forma y el reparto de duplicados.
 *
 *  - **Tope 50** (`RELATIONS_CHECK_MANY_MAX`, = `FGA_MAX_BATCH_CHECK`): por
 *    encima es 422 con CERO llamadas al backend, nunca un troceo silencioso
 *    que esconda el coste; `[]` también es 422 (un lote vacío no es una
 *    pregunta, y `[]` ⇒ `[]` se confundía con «todo denegado»).
 *  - **Duplicados permitidos, respuesta por POSICIÓN**: `[a, a, b]` ⇒
 *    `[x, x, y]`. Los drivers preguntan una vez por objeto distinto y
 *    reparten (`distinctObjects`).
 *
 * Pureza (regla 2): sin backend, sin manager.
 */
import { CheckManyBatchError } from '../errors.js'
import type { RelObject } from '../types.js'

/** Objetos por lote de `checkMany`. Es el tope de `batchCheck` del servidor FGA (50), para que un lote sea UNA request. */
export const RELATIONS_CHECK_MANY_MAX = 50

/** `objects` es un array con 1..RELATIONS_CHECK_MANY_MAX elementos, o 422 (`E_AUTHZ_CHECK_MANY_BATCH`) sin tocar nada. */
export function assertCheckManyObjects(objects: unknown): asserts objects is RelObject[] {
  if (!Array.isArray(objects)) {
    throw new CheckManyBatchError(`checkMany: 'objects' tiene que ser un array de objetos (llegó ${typeof objects}).`)
  }
  if (objects.length === 0) {
    throw new CheckManyBatchError(
      'checkMany: el lote está VACÍO. Un lote sin objetos no es una pregunta (y `[]` ⇒ `[]` se leería como «todo denegado»): pasa al menos un objeto.'
    )
  }
  if (objects.length > RELATIONS_CHECK_MANY_MAX) {
    throw new CheckManyBatchError(
      `checkMany: el lote tiene ${objects.length} objetos y el tope es ${RELATIONS_CHECK_MANY_MAX} (RELATIONS_CHECK_MANY_MAX, ` +
        `= el tope de batchCheck del servidor): trocea en el llamante. No se ha preguntado nada.`
    )
  }
}

/**
 * Los objetos DISTINTOS del lote (por `type:id`, en orden de primera aparición)
 * y, por posición del lote, el índice del distinto que la responde. Con
 * `[a, a, b]` ⇒ `distinct = [a, b]`, `index = [0, 0, 1]`.
 */
export function distinctObjects(objects: RelObject[]): { distinct: RelObject[]; index: number[] } {
  const seen = new Map<string, number>()
  const distinct: RelObject[] = []
  const index: number[] = []
  for (const object of objects) {
    const key = `${object.type}:${object.id}`
    let at = seen.get(key)
    if (at === undefined) {
      at = distinct.length
      seen.set(key, at)
      distinct.push(object)
    }
    index.push(at)
  }
  return { distinct, index }
}

/** Reparte las respuestas de los objetos DISTINTOS a las posiciones del lote. */
export function expandByPosition(index: number[], answers: boolean[]): boolean[] {
  return index.map((at) => answers[at])
}
