/**
 * **El ALCANCE de un deny vivo, y cuándo un cambio de config lo ENCOGE** (lote RC · sublote (8); decisión §2026-10-15 (8)
 * del dueño y firmas «(8 · panel)» 2026-10-22). Módulo PURO (sin `db`, sin drivers: regla 2 de pureza) y PUNTO DE PASO
 * ÚNICO de las tres piezas de (8) —los gemelos guarda ↔ detector de un driver ↔ `--dry-run`—:
 *
 *  - la **guarda de `database`** (`saveRelationsConfig`, `src/relations_config_store.ts`): `judgeDenyReach` sobre la línea
 *    base persistida (leída TODO O NADA por `denyReachBaselineOf`), la config nueva y los denies vivos de `authz_relations`;
 *    niega (500 `E_AUTHZ_DENY_REACH_REFUSED`, cero escrituras) salvo las dos salidas con nombre: `establishBaseline: true`
 *    (solo el motivo `no-baseline`) y `allowDenyReachShrink: ['tipo#relación', …]` (solo esos hallazgos);
 *  - el **detector de un solo driver** (`checkRelationsConfigDenyReach`, mismo módulo de la guarda): `denyReachCheck`, la
 *    misma línea base y los mismos denies, en las DOS direcciones (persistida → servida, y servida → persistida: la línea
 *    base RANCIA, A1/S-B del panel);
 *  - el **detector de `authz:relations:reconcile --dry-run`** (`reconcileRelations({ denyReach })`): `denyReachCheck` sobre
 *    los denies que la pasada YA enumeró, en origen y destino. En `openfga` es solo detección (regla (ritmo): cero
 *    arreglos hasta 2.6; la guarda de `openfga:provision` sigue siendo el límite declarado `openfga.provision.deny-reach`).
 *
 * **El alcance** de un deny sobre `T#X` es el conjunto de relaciones cuyos grants CORTA (D5, corte de camino:
 * `cutPathAllows` corta un grant de `g` sii algún deny vivo está en `up*(g)`, o sea sii `g ∈ down*(X)`):
 * `alcance(T#X) = down*(X)`. Con `editor: { includes: ['owner'] }` un deny en `editor` corta `{editor, owner}`; estrechado
 * a `includes: []` corta solo `{editor}` y el owner directo vuelve a conceder (el escenario firmado).
 *
 * **La propiedad firmada es «para todo deny vivo, alcance_nuevo ⊇ alcance_viejo»**, NO «la relación sigue existiendo».
 * Motivos de un hallazgo:
 *  - `shrunk`: `T#X` sigue declarada pero `down*_nuevo(X) ⊉ down*_viejo(X)` —un `includes` estrechado, directo o
 *    TRANSITIVO, o una relación de `down*_viejo(X)` retirada del tipo—;
 *  - `orphan`: `T#X` ya no está declarada (relación o tipo retirados): el deny no lo lee nadie (alcance ∅) y ningún
 *    `removeDeny` lo alcanza (F-05); si la relación se vuelve a declarar, el deny resucita. Se juzga SIEMPRE contra la
 *    config nueva, con o sin línea base, y aunque ya fuera huérfano en la línea base (firma (8 · salida forzada): P2 «juzgar
 *    por delta» NO entra — una AUSENCIA en una fila que puede estar rancia no prueba que el deny ya fuera huérfano en la flota);
 *  - `no-baseline`: no hay línea base UTILIZABLE (sin fila, o una fila que la lectura TODO O NADA no puede tipar) y el deny
 *    vive: no se puede juzgar si encoge (firma (8 · línea base));
 *  - `stale` (solo el detector): la línea base no sabe que el deny corta algo que la config SERVIDA sí corta — la fila es
 *    más estrecha que lo servido, y desde ella un estrechamiento de vuelta parecería «sin cambio» (firma (8 · rancia)).
 *
 * Decisiones que siguen (informe `loteRC-8-informe.md`, sin cambio del dueño): una relación de `down*_viejo(X)` RETIRADA del
 * tipo cuenta como encogimiento aunque sus grants ya no concedan (la propiedad, literal); retirar el opt-in `deny` de un tipo
 * NO cambia el alcance en `database` (las lecturas honran la fila igual) y no se juzga aquí — en `openfga` lo juzga la guarda
 * de `provision` (`--allow-drop-deny`).
 */
import { RELATION_DENY_PREFIX, relationsDown } from './define_relations_config.js'
import type { RelationsConfig } from './define_relations_config.js'

type ConfigLike = Pick<RelationsConfig, 'objectTypes'>

/** Un deny vivo, agregado por tipo y relación PÚBLICA (`editor`, no `denied_editor`). */
export interface LiveDenyGroup {
  objectType: string
  relation: string
  /**
   * Cuántos denies vivos hay sobre `objectType#relation`: filas de `authz_relations` en la guarda; en el detector de
   * reconcile, CLAVES DE TUPLA DISTINTAS (firma (8 · `count`): un deny espejado en origen y destino cuenta una vez).
   */
  count: number
}

/**
 * Por qué un grupo de denies vivos es un hallazgo: `shrunk`/`orphan` (la config nueva encoge su alcance), `no-baseline`
 * (sin línea base utilizable no se puede juzgar) o `stale` (la línea base es más estrecha que lo servido; solo el detector).
 */
export type DenyReachReason = 'shrunk' | 'orphan' | 'no-baseline' | 'stale'

/** Un grupo de denies vivos cuyo alcance encoge con la config nueva, con su receta. */
export interface DenyReachFinding {
  objectType: string
  relation: string
  reason: DenyReachReason
  count: number
  /**
   * El alcance con la config VIEJA (`down*` en la línea base); `null` = sin línea base o ya huérfano allí. Con `stale`, el
   * alcance que CREE la línea base (`null` si no declara la relación).
   */
  before: string[] | null
  /** El alcance con la config NUEVA; `[]` si quedó huérfano. Con `stale`, el de la config SERVIDA. */
  after: string[]
  /**
   * Lo que deja de cortar (`before \ after`); con `orphan` sin línea base, `[relation]`; con `no-baseline`, `[]` (no se
   * sabe); con `stale`, lo que el deny corta con lo servido y la línea base no sabe (`after \ before`).
   */
  lost: string[]
  /** La receta (español, como el resto de la letra del paquete). */
  recipe: string
}

/**
 * **El alcance de un deny sobre `objectType#relation`** con `config`: `down*(relation)` ordenado, o `null` si la config no
 * declara ese tipo o esa relación (huérfano).
 */
export function denyReachOf(config: ConfigLike, objectType: string, relation: string): string[] | null {
  const type = config.objectTypes.find((t) => t.type === objectType)
  if (!type || !type.relations.some((r) => r.name === relation)) return null
  return relationsDown(config, objectType, relation).sort()
}

/** La relación ALMACENADA `denied_<rel>` ⇒ `<rel>`; cualquier otra ⇒ `null` (no es un deny). */
export function deniedPublicRelation(stored: string): string | null {
  return typeof stored === 'string' && stored.startsWith(RELATION_DENY_PREFIX) && stored.length > RELATION_DENY_PREFIX.length
    ? stored.slice(RELATION_DENY_PREFIX.length)
    : null
}

/** La clave `tipo#relación` de un grupo o hallazgo: la que nombra la salida forzada acotada (`allowDenyReachShrink`). */
export function denyReachKey(group: { objectType: string; relation: string }): string {
  return `${group.objectType}#${group.relation}`
}

/** La forma de una clave `tipo#relación` que acepta la salida forzada acotada (dos nombres no vacíos, sin `#` ni blancos). */
export const DENY_REACH_KEY_PATTERN = /^[^#\s]+#[^#\s]+$/

/**
 * **La lectura de la LÍNEA BASE, TODO O NADA y tipada** (firma (8 · línea base); conflicto 6 del juez del panel): de la spec
 * persistida (el JSON ya parseado) lee SOLO lo que decide un alcance —`objectTypes[].{type, relations[].{name, includes}}`—,
 * sin pasar por `defineRelationsConfig` (una fila de 2.4/alpha.3 con una clave que 2.5 no conoce sigue siendo una línea
 * base: la receta de B5, re-guardar la misma spec corregida, entra sin forzar). Cualquier forma rota EN LO QUE LEE —un
 * objeto que no lo es, `objectTypes`/`relations` que no son arrays, un `type`/`name` que no es string, un `includes`
 * presente que no es un array de strings— deja la línea base como NO UTILIZABLE (`null`): **nunca se filtra** (filtrar
 * subestima el alcance viejo y deja pasar el estrechamiento: S-D3 del tester del panel). Un `includes` ausente es `[]`
 * (la spec lo permite).
 */
export function denyReachBaselineOf(parsed: unknown): ConfigLike | null {
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return null
  const objectTypes: unknown = (parsed as { objectTypes?: unknown }).objectTypes
  if (!Array.isArray(objectTypes)) return null
  const types: Array<{ type: string; relations: Array<{ name: string; includes: string[] }> }> = []
  for (const t of objectTypes) {
    if (t === null || typeof t !== 'object' || Array.isArray(t)) return null
    if (typeof t.type !== 'string' || !Array.isArray(t.relations)) return null
    const relations: Array<{ name: string; includes: string[] }> = []
    for (const r of t.relations) {
      if (r === null || typeof r !== 'object' || Array.isArray(r) || typeof r.name !== 'string') return null
      if (r.includes !== undefined && !(Array.isArray(r.includes) && r.includes.every((i: unknown) => typeof i === 'string'))) return null
      relations.push({ name: r.name, includes: Array.isArray(r.includes) ? r.includes.filter((i: unknown) => typeof i === 'string') : [] })
    }
    types.push({ type: t.type, relations })
  }
  return { objectTypes: types }
}

function mergeGroups(denies: Iterable<LiveDenyGroup>): LiveDenyGroup[] {
  const groups = new Map<string, LiveDenyGroup>()
  for (const deny of denies) {
    const key = denyReachKey(deny)
    const seen = groups.get(key)
    groups.set(key, seen ? { ...seen, count: seen.count + deny.count } : { ...deny })
  }
  return [...groups.values()]
}

const byKey = (a: { objectType: string; relation: string; reason?: string }, b: { objectType: string; relation: string; reason?: string }) =>
  denyReachKey(a).localeCompare(denyReachKey(b)) || String(a.reason ?? '').localeCompare(String(b.reason ?? ''))

/**
 * **La propiedad de (8)**: para cada grupo de denies vivos, ¿`alcance(after) ⊇ alcance(before)`? Devuelve los que la
 * violan (`shrunk` | `orphan`, orden estable por tipo y relación), vacío si ninguno. `before = null` = sin línea base: solo
 * `orphan` (el motivo `no-baseline` lo añade `judgeDenyReach`).
 */
export function denyReachFindings(
  before: ConfigLike | null,
  after: ConfigLike,
  denies: Iterable<LiveDenyGroup>
): DenyReachFinding[] {
  const findings: DenyReachFinding[] = []
  for (const group of mergeGroups(denies).sort(byKey)) {
    const old = before ? denyReachOf(before, group.objectType, group.relation) : null
    const now = denyReachOf(after, group.objectType, group.relation)
    if (now === null) {
      findings.push({
        ...group,
        reason: 'orphan',
        before: old,
        after: [],
        lost: old ?? [group.relation],
        recipe: orphanRecipe(group),
      })
      continue
    }
    if (old === null) continue
    const lost = old.filter((relation) => !now.includes(relation))
    if (lost.length === 0) continue
    findings.push({ ...group, reason: 'shrunk', before: old, after: now, lost, recipe: shrunkRecipe(group, lost) })
  }
  return findings
}

/**
 * **El juicio de la guarda (y la mitad «persistida → servida» de los detectores)**: `denyReachFindings` más, SIN línea base
 * utilizable (`baseline === null`), un hallazgo `no-baseline` por cada grupo de denies vivos que no sea ya `orphan` (de un
 * huérfano sí se sabe que encoge: su alcance es ∅). Sin denies vivos no hay hallazgo alguno: la primera fila se crea sin
 * forzar. Orden estable por tipo, relación y motivo.
 */
export function judgeDenyReach(baseline: ConfigLike | null, next: ConfigLike, denies: Iterable<LiveDenyGroup>): DenyReachFinding[] {
  const groups = mergeGroups(denies)
  const findings = denyReachFindings(baseline, next, groups)
  if (baseline !== null) return findings
  const judged = new Set(findings.map(denyReachKey))
  for (const group of groups) {
    if (judged.has(denyReachKey(group))) continue
    findings.push({ ...group, reason: 'no-baseline', before: null, after: denyReachOf(next, group.objectType, group.relation) ?? [], lost: [], recipe: noBaselineRecipe(group) })
  }
  return findings.sort(byKey)
}

/**
 * **La línea base RANCIA** (firma (8 · rancia); conflicto 3 del juez): la dirección inversa, `denyReachFindings(servida,
 * persistida)`. Un grupo de denies vivos cuyo alcance con lo SERVIDO no cabe en el de la línea base (la fila no declara la
 * relación que se sirve, o la declara más estrecha) es un hallazgo `stale`: la flota sirvió (o sirve) algo que la fila no
 * registra, y desde esa fila un estrechamiento de vuelta a ella parecería «sin cambio» (A1/S-B). Un grupo que lo servido
 * tampoco declara no es rancio (es `orphan` en la otra dirección).
 */
export function staleDenyReach(baseline: ConfigLike, served: ConfigLike, denies: Iterable<LiveDenyGroup>): DenyReachFinding[] {
  return denyReachFindings(served, baseline, denies)
    .filter((reverse) => reverse.before !== null)
    .map((reverse) => ({
      objectType: reverse.objectType,
      relation: reverse.relation,
      count: reverse.count,
      reason: 'stale' as const,
      before: reverse.reason === 'orphan' ? null : reverse.after,
      after: reverse.before!,
      lost: reverse.lost,
      recipe: staleRecipe(reverse),
    }))
}

/** Lo que devuelven los dos detectores (el de un driver y el de `--dry-run`) para un estado: las dos direcciones. */
export interface DenyReachCheck {
  /** `'persisted'`: hay línea base utilizable; `'none'`: no la hay (sin fila, o fila que la lectura TODO O NADA no tipa). */
  baseline: 'persisted' | 'none'
  /** Persistida → servida: `shrunk`, `orphan` y, sin línea base, `no-baseline` (el juicio de la guarda, sin salidas). */
  findings: DenyReachFinding[]
  /** Servida → persistida: `stale` (solo con línea base). */
  staleBaseline: DenyReachFinding[]
}

/** **Los dos sentidos sobre el mismo estado** (firma (8 · detector de un driver)): el punto de paso de los detectores. */
export function denyReachCheck(baseline: ConfigLike | null, served: ConfigLike, denies: Iterable<LiveDenyGroup>): DenyReachCheck {
  const groups = mergeGroups(denies)
  return {
    baseline: baseline === null ? 'none' : 'persisted',
    findings: judgeDenyReach(baseline, served, groups),
    staleBaseline: baseline === null ? [] : staleDenyReach(baseline, served, groups),
  }
}

function shrunkRecipe(group: LiveDenyGroup, lost: string[]): string {
  return (
    `antes de estrechar, vuelve a emitir cada uno de esos ${group.count} deny(s) sobre una relación de '${group.objectType}' que ` +
    `con la config nueva siga cortando ${lost.map((r) => `'${r}'`).join(', ')} (deny(<sujeto>, '<esa relación>', <objeto>); ` +
    `listDenies(<objeto>, '${group.relation}') los enumera), o deja el includes como estaba; si de verdad deben dejar de ` +
    `cortarlo, nombra este hallazgo en la salida forzada: allowDenyReachShrink: ['${denyReachKey(group)}']`
  )
}

function orphanRecipe(group: LiveDenyGroup): string {
  return (
    `antes de retirar '${denyReachKey(group)}', quita esos ${group.count} deny(s) con removeDeny (o re-emítelos sobre ` +
    `una relación que se quede) y retírala después; si ya la retiraste, vuelve a declararla, haz removeDeny y retírala — ` +
    `un deny huérfano no lo lee nadie, ningún removeDeny lo alcanza (F-05) y resucita si la relación se vuelve a declarar ` +
    `(y re-declararla tras forzar la retirada resucita también los grants que cortaba)`
  )
}

function noBaselineRecipe(group: LiveDenyGroup): string {
  return (
    `guarda UNA vez la spec que la flota sirve HOY, sin cambios, con saveRelationsConfig(spec, { establishBaseline: true }), ` +
    `en una release que NO cambie relations.config (adoptar en una release que estrecha certifica el estrechamiento); ` +
    `desde esa fila la guarda juzga cada cambio de '${denyReachKey(group)}'`
  )
}

function staleRecipe(reverse: DenyReachFinding): string {
  return (
    `la línea base (authz_relations_config) es más estrecha que la config que se sirve: guarda con saveRelationsConfig la ` +
    `config que sirve la flota —persistir la config es paso obligatorio de release si usas deny— y vuelve a correr la ` +
    `comprobación; mientras la fila no lo sepa, un estrechamiento de vuelta a ella no lo niega la guarda y los ` +
    `${reverse.count} deny(s) de '${denyReachKey(reverse)}' dejarían de cortar ${reverse.lost.map((r) => `'${r}'`).join(', ')}`
  )
}

/**
 * Una línea por hallazgo, con el prefijo ESTABLE de su rama (CLAUDE.md punto 7): la usan el error de la guarda, el detector
 * de un driver y el comando. Prefijos: «deny con alcance ENCOGIDO», «deny HUÉRFANO», «deny SIN línea base», «línea base
 * RANCIA».
 */
export function denyReachLine(finding: DenyReachFinding): string {
  const where = `${denyReachKey(finding)} (${finding.count} deny(s))`
  switch (finding.reason) {
    case 'orphan':
      return `deny HUÉRFANO ${where}: la config nueva no declara la relación (cortaba ${finding.lost.join(', ')}). Receta: ${finding.recipe}.`
    case 'no-baseline':
      return (
        `deny SIN línea base ${where}: no hay config persistida utilizable en authz_relations_config con la que comparar, así que ` +
        `no se puede saber si la config nueva encoge su alcance (hoy corta ${finding.after.join(', ')}). Receta: ${finding.recipe}.`
      )
    case 'stale':
      return (
        `línea base RANCIA ${where}: con la config servida el deny corta ${finding.after.join(', ')}, y la config persistida ` +
        `${finding.before === null ? 'no declara la relación' : `solo sabe de ${finding.before.join(', ')}`} (no sabe de ` +
        `${finding.lost.join(', ')}). Receta: ${finding.recipe}.`
      )
    default:
      return (
        `deny con alcance ENCOGIDO ${where}: cortaba ${finding.before!.join(', ')} y con la config nueva solo ${finding.after.join(', ')} ` +
        `(deja de cortar ${finding.lost.join(', ')}: lo que negaba vuelve a conceder). Receta: ${finding.recipe}.`
      )
  }
}
