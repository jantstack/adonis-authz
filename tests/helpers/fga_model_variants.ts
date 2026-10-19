/**
 * Variantes del modelo `facts` que NO genera el paquete, para juzgarlas con el intérprete (`fga_interpreter.ts`).
 * Herramienta de test: el estudio 6b (`loteRC-6b-estudio-analista.md` §2) las construyó partiendo del generador real
 * y reescribiendo SOLO el tipo `scope`; aquí se copia la de **c3u** tal cual (`loteRC-6b-analista-models.ts`) para que
 * el comprobador del lector rasgado tenga su control NEGATIVO (c3u no debe dar `true` imposibles con una sola arista)
 * y para el juez T-1 cuando c3 se estudie en 2.6.
 *
 * c3u — deny local en `clean_P`, deny heredado solo en `can_P`:
 *   denied_P : [holders]                                      (solo el hecho: las tuplas no cambian)
 *   xd_P     : denied_P or xd_P from parent                   (el deny heredado)
 *   clean_P  : (rooted or clean_P from parent) but not denied_P
 *   can_P    : (can_P from parent or (P from binding and clean_P)) but not xd_P
 *   rooted   : [holders:*]                                    (solo el marcador; ya no se hereda)
 *   scope#P  : desaparece
 */
import { factsRelationsOf, openFgaFactsModel } from '../../src/drivers/openfga_facts.js'
import type { FactsRelationsConfig } from '../../src/drivers/openfga_facts.js'

const ttu = (tupleset: string, relation: string) => ({
  tupleToUserset: { tupleset: { relation: tupleset }, computedUserset: { relation } },
})
const computed = (relation: string) => ({ computedUserset: { relation } })
const NO_DIRECT = { directly_related_user_types: [] as unknown[] }

/**
 * El modelo c3u para `holders`/`permissions` (prefijos `xd_` y `clean_`, los del estudio). Con `relationsConfig`, el
 * modelo FUSIONADO (las relaciones no cambian: solo se reescribe `scope`).
 */
export function c3uFactsModel(
  holders: Record<string, string>,
  permissions: string[],
  relationsConfig?: FactsRelationsConfig
): any {
  const model = openFgaFactsModel(holders, permissions, relationsConfig)
  const scope = model.type_definitions.find((d: any) => d.type === 'scope')
  const rel = scope.relations
  const meta = scope.metadata.relations
  rel.rooted = { this: {} }
  for (const permission of permissions) {
    const r = factsRelationsOf(permission)
    const clean = `clean_${r.base}`
    const xd = `xd_${r.base}`
    rel[clean] = {
      difference: {
        base: { union: { child: [computed('rooted'), ttu('parent', clean)] } },
        subtract: computed(r.denied),
      },
    }
    meta[clean] = NO_DIRECT
    rel[r.denied] = { this: {} }
    rel[xd] = { union: { child: [computed(r.denied), ttu('parent', xd)] } }
    meta[xd] = NO_DIRECT
    rel[r.can] = {
      difference: {
        base: {
          union: { child: [ttu('parent', r.can), { intersection: { child: [ttu('binding', r.base), computed(clean)] } }] },
        },
        subtract: computed(xd),
      },
    }
    delete rel[r.base]
    delete meta[r.base]
  }
  return model
}
