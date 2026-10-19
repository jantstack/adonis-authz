/**
 * **Lote «antes de RC» · L11 — «el modelo fijado y el que genera la config son IGUALES»** (decisiones del dueño
 * 2026-10-17 (1) y (2); plan del juez §1, injertos 2–9 y 15; casos C1–C15 y H1-1…H1-6 del tester; F0 · M-a(2)/M-b).
 *
 * Dos mitades:
 *  - PURA (los cuatro modos, sin servidor): C5 (la rejilla de `fgaTupleExpiry` contra el oráculo de M-b), C6 (fuerza
 *    bruta de mutaciones del modelo + normalizaciones neutras), C7 (la razón ESTRUCTURAL del límite «tipo ajeno»), C11
 *    («módulo el catálogo»), C14 (pin obligatorio), C15 (regla de fuente), H1-2, H1-3, H1-4 (reescrito tras M-a(2)).
 *  - CONTRA OPENFGA (`OPENFGA_TEST_URL`): C1 (condición de ACEPTACIÓN: el modelo generado, publicado y fijado, y los dos
 *    drivers responden), C2 (C6-1 literal ⇒ 500), H1-1 (su inverso: 409 por la opción A, no 500), C3 (tupla ajena viva en
 *    la portadora ⇒ 409), C4 (C6-2 contra el servidor), C10 (roles: tres modelos derivados ⇒ 500 antes de evaluar), H1-4
 *    (el modelo R de M-a(2) ⇒ 500), H1-5 (F-05 antes que la puerta), H1-6 (modelo inexistente ⇒ 503, PROVISIONAL: R3 lo
 *    voltea a 500). C12 (la relectura de `provision` contra el servidor real) vive en `commands.spec` (B-1/B-2).
 */
import { test } from '@japa/runner'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { v7 as uuidv7 } from 'uuid'
import { fgaTupleExpiry, fgaTimestampNs } from '../src/expiry.js'
import { factsModelDifferences, openFgaFactsModel } from '../src/drivers/openfga_facts.js'
import type { FactsModelSlice } from '../src/drivers/openfga_facts.js'
import { OpenFgaRelationsDriver } from '../src/drivers/openfga_relations_driver.js'
import { OpenFgaAuthorizationDriver, provisionOpenFgaStore } from '../src/drivers/openfga_driver.js'
import { contractDenyRelationsConfig, contractRelationsConfig } from '../src/testing/relations_contract.js'
import type { ScopeRef } from '../src/types.js'
import { APP_SCOPE } from '../src/types.js'
import { spyFgaClient } from './helpers/fga_spy.js'

const HOLDERS = { user: 'user', admin: 'admin', integration: 'integration' } as const
const PERMISSIONS = ['docs:read', 'org.audit.browse']
const ROOT = new URL('../', import.meta.url).pathname

const relationsOf = (deny = true) => ({ objectTypes: (deny ? contractDenyRelationsConfig() : contractRelationsConfig()).objectTypes })
const fullModel = (): any => openFgaFactsModel(HOLDERS, PERMISSIONS, relationsOf())
const diff = (served: unknown, slice: FactsModelSlice) =>
  factsModelDifferences(served, { holderTypes: HOLDERS, relations: slice === 'roles' ? undefined : relationsOf(), slice })
const clone = (x: any) => JSON.parse(JSON.stringify(x))
const typeOf = (model: any, name: string) => model.type_definitions.find((t: any) => t.type === name)
const ne = (valid_until: unknown) => ({ name: 'not_expired', context: { valid_until } })

/** Las tres partes del modelo que gobierna cada puerta (los holders van en las dos). */
const ROLE_TYPES = new Set(['role', 'role_binding', 'scope', ...Object.values(HOLDERS)])
const RELATION_TYPES = new Set(['group', ...relationsOf().objectTypes.map((t) => t.type), ...Object.values(HOLDERS)])

/** El modelo con la forma con que lo DEVUELVE OpenFGA v1.19.0 (medido en `:8090`): ruido de proto3 y otro orden. */
function served(model: any): any {
  const walk = (node: any): any => {
    if (Array.isArray(node)) return [...node].reverse().map(walk)
    if (node === null || typeof node !== 'object') return node
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(node).reverse()) out[key] = walk(node[key])
    if (out.computedUserset) (out.computedUserset as any).object = ''
    if (out.tupleset) (out.tupleset as any).object = ''
    if (Array.isArray(out.directly_related_user_types)) {
      out.module = ''
      out.source_info = null
      for (const r of out.directly_related_user_types as any[]) if (r.condition === undefined) r.condition = ''
    }
    if (out.type_name) out.generic_types = []
    return out
  }
  const copy = walk(clone(model))
  copy.id = '01ARZ3NDEKTSV4RRFFQ69G5FAW'
  for (const definition of copy.type_definitions) {
    if (definition.metadata === undefined || definition.metadata === null) definition.metadata = null
    else Object.assign(definition.metadata, { module: '', source_info: null })
  }
  for (const condition of Object.values<any>(copy.conditions)) condition.metadata = null
  return copy
}

/* ══ PURA ═══════════════════════════════════════════════════════════════════════════════════════════════════════ */

test.group('L11 · C5 · fgaTupleExpiry contra el oráculo de F0 · M-b (ns(now) < trunc9(ns(s)), rejilla determinista)', () => {
  test('0–12 decimales × {0,1,9,5} × {., ,} × desfases (Z, ±00:00, +02:00, -05:30, ±24:00, +23:59, +24:01) × ±2 ms alrededor de la frontera: isActive ⇔ ns(now) < trunc9(ns(s)), con un oráculo INDEPENDIENTE (Date.UTC)', ({ assert }) => {
    const BASE = Date.UTC(2030, 5, 15, 10, 20, 30)
    const offsets: Array<[string, number]> = [
      ['Z', 0], ['+00:00', 0], ['-00:00', 0], ['+02:00', 7200], ['-05:30', -19800], ['+24:00', 86400], ['-24:00', -86400], ['+23:59', 86340], ['+24:01', 86460],
    ]
    let checked = 0
    const mismatches: string[] = []
    for (let decimals = 0; decimals <= 12; decimals++) {
      for (const digit of ['0', '1', '9', '5']) {
        for (const separator of decimals === 0 ? [''] : ['.', ',']) {
          for (const [offset, seconds] of offsets) {
            const fraction = digit.repeat(decimals)
            const raw = `2030-06-15T10:20:30${separator}${fraction}${offset}`
            const oracle = (BigInt(BASE) / 1000n - BigInt(seconds)) * 1_000_000_000n + BigInt(fraction.slice(0, 9).padEnd(9, '0') || '0')
            assert.equal(fgaTimestampNs(raw), oracle, `ns de ${raw}`)
            const expiry = fgaTupleExpiry(ne(raw))
            assert.equal(expiry.kind, 'expiry', raw)
            const floorMs = oracle / 1_000_000n
            for (let k = -2n; k <= 2n; k++) {
              const nowMs = floorMs + k
              const active = Number(nowMs) < (expiry as { at: Date }).at.getTime()
              if (active !== nowMs * 1_000_000n < oracle) mismatches.push(`${raw} con now=${nowMs}: paquete ${active}`)
              checked++
            }
          }
        }
      }
    }
    assert.deepEqual(mismatches, [], `ROJO (C6-2): el paquete no coincide con el servidor en ${mismatches.length} de ${checked}`)
    assert.isAbove(checked, 4000)
  })

  test('H1-3 · lo que el servidor rechaza o el parser no reproduce ⇒ unparseable, JAMÁS none (= permanente); y contexto vacío/ausente ⇒ unparseable; el contexto con MÁS que valid_until ⇒ foreign (H2)', ({ assert }) => {
    const bad = [
      '2030-06-15T23:59:60Z', '10000-01-01T00:00:00Z', '', '2030-06-15T10:20:30', '2030-06-15T10:20:30z', '2030-06-15t10:20:30Z',
      '2030-06-15 10:20:30Z', '2030-06-15T10:20:30+0000', '2030-06-15', '1907000000', '2030-06-15T10:20:30+99:00', '2030-06-15T10:20:30+25:00',
      '2030-06-15T24:00:00Z', '2030-02-30T10:20:30Z', '2030-06-15T10:60:30Z', '2030-06-15T10:20:30+02:00:00', '2030-06-15T10:20:30.Z',
      '30-06-15T10:20:30Z', ' 2030-06-15T10:20:30Z ', 'garbage', 12345, null,
    ]
    for (const raw of bad) assert.equal(fgaTupleExpiry(ne(raw)).kind, 'unparseable', `ROJO (H1-3): ${JSON.stringify(raw)}`)
    assert.equal(fgaTupleExpiry({ name: 'not_expired', context: {} }).kind, 'unparseable')
    assert.equal(fgaTupleExpiry({ name: 'not_expired' }).kind, 'unparseable')
    assert.equal(fgaTupleExpiry({ name: '' }).kind, 'unparseable')
    assert.equal(fgaTupleExpiry('not_expired').kind, 'unparseable')
    assert.equal(fgaTupleExpiry({ name: 'not_expired', context: { valid_until: '2001-01-01T00:00:00Z', current_time: '2000-01-01T00:00:00Z' } }).kind, 'foreign')
    assert.equal(fgaTupleExpiry({ name: 'inverted', context: { valid_until: '2001-01-01T00:00:00Z' } }).kind, 'foreign')
    // Lo que el servidor ACEPTA y el parser sí reproduce (F0 · M-b): año 0000/0001/9999, +23:59.
    for (const ok of ['0000-01-01T00:00:00Z', '0001-01-01T00:00:00Z', '9999-12-31T23:59:59.999999999Z', '2028-02-29T00:00:00+23:59']) {
      assert.equal(fgaTupleExpiry(ne(ok)).kind, 'expiry', ok)
    }
  })

  test('H1-4 (reescrito tras F0 · M-a(2): la premisa «el modelo exige la condición» es FALSA para el modelo GENERADO) · sin condición ⇒ none, que es PERMANENTE igual que el servidor con el modelo generado (Check T medido); el modelo R que la exigiría lo rechaza la puerta (caso contra el servidor)', ({ assert }) => {
    assert.deepEqual(fgaTupleExpiry(undefined), { kind: 'none' })
    assert.deepEqual(fgaTupleExpiry(null), { kind: 'none' })
    const assignee = typeOf(fullModel(), 'role_binding').metadata.relations.assignee.directly_related_user_types
    assert.isTrue(assignee.some((r: any) => r.type === 'user' && r.condition === undefined), 'el modelo generado ADMITE assignee sin condición')
  })
})

test.group('L11 · C6 · fuerza bruta de mutaciones del modelo (pura): toda mutación de un tipo de un slice ⇒ ≥ 1 diferencia con su ruta; toda normalización neutra ⇒ igual', () => {
  test('normalizaciones neutras (ruido de proto3 de v1.19.0, orden de claves y de hijos conmutativos) ⇒ igual en los tres slices', ({ assert }) => {
    for (const slice of ['roles', 'relations', 'all'] as const) {
      assert.deepEqual(diff(fullModel(), slice).differences, [], `${slice}: el generado`)
      assert.deepEqual(diff(served(fullModel()), slice).differences, [], `${slice}: con la forma del servidor`)
    }
  })

  test('cada mutación de un operador, en CADA tipo y relación del modelo ⇒ ≥ 1 diferencia en su slice que nombra el tipo (o las condiciones / schema_version)', ({ assert }) => {
    const base = fullModel()
    const mutations: Array<[string, string | null, (m: any) => void]> = []
    for (const definition of base.type_definitions) {
      const t = definition.type as string
      mutations.push([`${t}: quitar el tipo`, t, (m) => { m.type_definitions = m.type_definitions.filter((d: any) => d.type !== t) }])
      mutations.push([`${t}: relación de más`, t, (m) => { typeOf(m, t).relations.zz_extra = { this: {} } }])
      mutations.push([`${t}: metadata.module`, t, (m) => { typeOf(m, t).metadata = { ...(typeOf(m, t).metadata ?? {}), module: 'mod' } }])
      for (const r of Object.keys(definition.relations)) {
        const other = Object.keys(definition.relations).find((x) => x !== r) ?? 'zz'
        mutations.push([`${t}#${r}: quitar`, t, (m) => { delete typeOf(m, t).relations[r] }])
        mutations.push([`${t}#${r}: regla ⇒ this`, t, (m) => { typeOf(m, t).relations[r] = { this: {} } }])
        mutations.push([`${t}#${r}: regla ⇒ computedUserset`, t, (m) => { typeOf(m, t).relations[r] = { computedUserset: { relation: other } } }])
        mutations.push([`${t}#${r}: unión con un hijo de más`, t, (m) => { typeOf(m, t).relations[r] = { union: { child: [clone(typeOf(m, t).relations[r]), { computedUserset: { relation: other } }] } } }])
        mutations.push([`${t}#${r}: this ⇒ {}`, t, (m) => { if (JSON.stringify(typeOf(m, t).relations[r]) === '{"this":{}}') typeOf(m, t).relations[r] = {} }])
      }
      for (const [r, meta] of Object.entries<any>(definition.metadata?.relations ?? {})) {
        const restrictions: any[] = meta.directly_related_user_types ?? []
        if (restrictions.length > 0) {
          mutations.push([`${t}#${r}: quitar una restricción`, t, (m) => { typeOf(m, t).metadata.relations[r].directly_related_user_types.shift() }])
          mutations.push([`${t}#${r}: restricción duplicada`, t, (m) => { const x = typeOf(m, t).metadata.relations[r].directly_related_user_types; x.push(clone(x[0])) }])
          mutations.push([`${t}#${r}: condición en una restricción`, t, (m) => {
            const x = typeOf(m, t).metadata.relations[r].directly_related_user_types
            const target = x.find((y: any) => !y.condition) ?? x[0]
            target.condition = target.condition === 'not_expired' ? 'inverted' : 'not_expired'
          }])
          mutations.push([`${t}#${r}: wildcard`, t, (m) => {
            const target = typeOf(m, t).metadata.relations[r].directly_related_user_types[0]
            if (target.wildcard) delete target.wildcard
            else if (!target.relation) target.wildcard = {}
            else target.relation = `${target.relation}_x`
          }])
        }
        mutations.push([`${t}#${r}: restricción de más`, t, (m) => { typeOf(m, t).metadata.relations[r].directly_related_user_types = [...(typeOf(m, t).metadata.relations[r].directly_related_user_types ?? []), { type: 'zz_type' }] }])
      }
    }
    mutations.push(['condición: renombrar', null, (m) => { m.conditions.not_expired.name = 'renamed' }])
    mutations.push(['condición: expresión', null, (m) => { m.conditions.not_expired.expression = 'current_time <= valid_until' }])
    mutations.push(['condición: tipo de parámetro', null, (m) => { m.conditions.not_expired.parameters.valid_until.type_name = 'TYPE_NAME_STRING' }])
    mutations.push(['condición: quitar un parámetro', null, (m) => { delete m.conditions.not_expired.parameters.current_time }])
    mutations.push(['condición: de más', null, (m) => { m.conditions.inverted = { name: 'inverted', expression: 'true', parameters: {} } }])
    mutations.push(['condición: quitar la de la caducidad', null, (m) => { delete m.conditions.not_expired }])
    mutations.push(['schema_version', null, (m) => { m.schema_version = '1.2' }])
    let judged = 0
    const silent: string[] = []
    for (const [what, type, mutate] of mutations) {
      const mutated = clone(base)
      mutate(mutated)
      if (JSON.stringify(mutated) === JSON.stringify(base)) continue
      judged++
      const slices: FactsModelSlice[] = type === null ? ['roles', 'relations', 'all'] : ['all', ...(ROLE_TYPES.has(type) ? ['roles' as const] : []), ...(RELATION_TYPES.has(type) ? ['relations' as const] : [])]
      for (const slice of slices) {
        let paths: string[]
        try {
          paths = diff(mutated, slice).differences.map((d) => d.path)
        } catch (error) {
          // El generador que NO puede generar (un `permits_*` impublicable): 500, nunca «igual» (H11 d).
          paths = [`(500) ${(error as Error).message}`]
        }
        const named = type === null ? paths.length > 0 : paths.some((p) => p.startsWith(type) || p.startsWith('(500)') || (type === 'role' && p.startsWith('scope')))
        if (!named) silent.push(`${what} [${slice}] ⇒ ${JSON.stringify(paths)}`)
      }
    }
    assert.deepEqual(silent, [], `ROJO (C6): mutaciones que la comparación NO ve`)
    assert.isAbove(judged, 250, 'es una fuerza bruta de verdad')
  })

  test('H1-2 · la restricción con `with not_expired` en el servido y SIN condición en lo generado (y al revés) ⇒ diferencia', ({ assert }) => {
    const gained = fullModel()
    typeOf(gained, 'role_binding').metadata.relations.role.directly_related_user_types[0].condition = 'not_expired'
    assert.include(diff(gained, 'roles').differences.map((d) => d.path), 'role_binding#role (restricciones de tipo)')
    const lost = fullModel()
    const assignee = typeOf(lost, 'role_binding').metadata.relations.assignee
    assignee.directly_related_user_types = assignee.directly_related_user_types.filter((r: any) => !r.condition)
    assert.include(diff(lost, 'roles').differences.map((d) => d.path), 'role_binding#assignee (restricciones de tipo)')
  })

  test('C7 · la razón ESTRUCTURAL del límite «tipo ajeno»: toda referencia de toda regla y restricción generada (computedUserset, tupleToUserset, tipos, relaciones de userset, condiciones) está DENTRO de su slice', ({ assert }) => {
    const model = fullModel()
    const outside: string[] = []
    for (const [slice, types] of [['roles', ROLE_TYPES], ['relations', RELATION_TYPES]] as const) {
      for (const t of types) {
        const definition = typeOf(model, t)
        const own = new Set(Object.keys(definition.relations))
        const walk = (node: any, where: string) => {
          if (!node || typeof node !== 'object') return
          if (node.computedUserset && node.tupleset === undefined && !own.has(node.computedUserset.relation)) outside.push(`${slice}: ${where} → ${node.computedUserset.relation}`)
          if (node.tupleToUserset) {
            const tupleset = node.tupleToUserset.tupleset.relation
            if (!own.has(tupleset)) outside.push(`${slice}: ${where} tupleset ${tupleset}`)
            const targets = (definition.metadata.relations[tupleset]?.directly_related_user_types ?? []).map((r: any) => r.type)
            for (const target of targets) {
              if (!types.has(target)) outside.push(`${slice}: ${where} TTU a ${target}`)
              else if (!(node.tupleToUserset.computedUserset.relation in typeOf(model, target).relations)) outside.push(`${slice}: ${where} TTU ${target}#${node.tupleToUserset.computedUserset.relation}`)
            }
            return
          }
          for (const value of Object.values(node)) walk(value, where)
        }
        for (const [r, rule] of Object.entries(definition.relations)) walk(rule, `${t}#${r}`)
        for (const [r, meta] of Object.entries<any>(definition.metadata?.relations ?? {})) {
          for (const restriction of meta.directly_related_user_types ?? []) {
            if (!types.has(restriction.type)) outside.push(`${slice}: ${t}#${r} restringe a ${restriction.type}`)
            if (restriction.relation && !(restriction.relation in typeOf(model, restriction.type).relations)) outside.push(`${slice}: ${t}#${r} → ${restriction.type}#${restriction.relation}`)
            if (restriction.condition && !(restriction.condition in model.conditions)) outside.push(`${slice}: ${t}#${r} con ${restriction.condition}`)
          }
        }
      }
    }
    assert.deepEqual(outside, [], 'ROJO (C7): una regla generada referencia algo fuera de su slice: el límite «tipo ajeno» ya no es razonable')
  })

  test('C11 · roles «módulo el catálogo»: P_M sale del PROPIO modelo (un modelo con más o menos permisos que el catálogo es igual a sí mismo); un permits_<P> sin su can_<P>/denied_<P>/<P> es diferencia', ({ assert }) => {
    for (const permissions of [[], ['a'], ['a', 'b.c', 'docs:read']]) {
      assert.deepEqual(diff(openFgaFactsModel(HOLDERS, permissions), 'roles').differences, [], JSON.stringify(permissions))
    }
    const half = openFgaFactsModel(HOLDERS, ['a']) as any
    typeOf(half, 'role').relations.permits_b = { this: {} }
    typeOf(half, 'role').metadata.relations.permits_b = clone(typeOf(half, 'role').metadata.relations.permits_a)
    const paths = diff(half, 'roles').differences.map((d) => d.path)
    for (const expected of ['scope#can_b (falta)', 'scope#denied_b (falta)', 'scope#b (falta)', 'role_binding#b (falta)']) assert.include(paths, expected)
  })

  test('H11 d · un generador que NO puede generar con el P_M del servido (un permits_* que choca con una relación propia) ⇒ 500 E_AUTHZ_CONFIG, nunca «igual»', ({ assert }) => {
    const model = fullModel()
    typeOf(model, 'role').relations.permits_parent = { this: {} }
    assert.throws(() => diff(model, 'roles'), /no se puede generar/)
    try {
      diff(model, 'roles')
    } catch (error: any) {
      assert.equal(error.status, 500)
      assert.equal(error.code, 'E_AUTHZ_CONFIG')
    }
  })
})

test.group('L11 · C14 · modelId OBLIGATORIO en los DOS drivers openfga (D14 ampliado), y C15 · regla de fuente', () => {
  test('C14 · sin modelId (ausente, vacío, solo espacios) ⇒ 500 E_AUTHZ_CONFIG al CONSTRUIR, con la receta, en roles y en relaciones, con o sin deny', ({ assert }) => {
    for (const modelId of [undefined, '', '   ']) {
      const builds: Array<[string, () => unknown]> = [
        ['roles', () => new OpenFgaAuthorizationDriver({ apiUrl: 'http://127.0.0.1:9', storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV', modelId: modelId as any, holderTypes: HOLDERS, acceptScopeDriftRisk: true })],
        ['relaciones sin deny', () => new OpenFgaRelationsDriver(contractRelationsConfig(), { apiUrl: 'http://127.0.0.1:9', storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV', modelId: modelId as any, holderTypes: HOLDERS })],
        ['relaciones con deny', () => new OpenFgaRelationsDriver(contractDenyRelationsConfig(), { apiUrl: 'http://127.0.0.1:9', storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV', modelId: modelId as any, holderTypes: HOLDERS })],
      ]
      for (const [label, build] of builds) {
        let caught: any = null
        try {
          build()
        } catch (error) {
          caught = error
        }
        assert.equal(caught?.status, 500, `${label} · ${JSON.stringify(modelId)}`)
        assert.equal(caught?.code, 'E_AUTHZ_CONFIG')
        for (const fragment of ['modelId', 'OPENFGA_MODEL_ID', 'openfga:provision', 'L11']) assert.include(String(caught?.message), fragment, label)
      }
    }
  })

  test('C15 · ninguna LECTURA de valid_until fuera de src/expiry.ts (la escritura `valid_until:` sí), y `toExpiryDate` solo lo importa src/shared/sql_expiry.ts', ({ assert }) => {
    const files: string[] = []
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const path = join(dir, name)
        if (statSync(path).isDirectory()) walk(path)
        else if (path.endsWith('.ts')) files.push(path)
      }
    }
    walk(join(ROOT, 'src'))
    const reads: string[] = []
    const importers: string[] = []
    for (const file of files) {
      const relative = file.slice(ROOT.length)
      const text = readFileSync(file, 'utf8')
      if (relative !== 'src/expiry.ts' && /(\?\.|\.)valid_until\b|\[['"]valid_until['"]\]/.test(text)) reads.push(relative)
      if (/import\s*\{[^}]*\btoExpiryDate\b[^}]*\}\s*from/.test(text)) importers.push(relative)
    }
    assert.deepEqual(reads, [], 'ROJO (C15): una caducidad de tupla leída a mano, sin fgaTupleExpiry')
    assert.deepEqual(importers, ['src/shared/sql_expiry.ts'], 'ROJO (C15): toExpiryDate (la de SQL) fuera de su sitio')
  })
})

/* ══ CONTRA OPENFGA ════════════════════════════════════════════════════════════════════════════════════════════ */

/**
 * **Cierre de L11** (revisiones del auditor y del tester sobre el diff; sin servidor).
 */
test.group('L11 · cierre · casos sin servidor', () => {
  test('⚪ A3.2 · una relación o una condición DE MÁS llamada `__proto__` (el servidor v1.19 la acepta, medido por el auditor) es deriva, no «igual» (D-L11-3)', ({ assert }) => {
    const raw = JSON.stringify(fullModel())
      .replace('"relations":{"owner"', '"relations":{"__proto__":{"this":{}},"owner"')
      .replace('"conditions":{', '"conditions":{"__proto__":{"name":"__proto__","expression":"true"},')
    const paths = diff(JSON.parse(raw), 'all').differences.map((d) => d.path)
    assert.isTrue(paths.some((p: string) => /#__proto__ \(relación de más\)$/.test(p)), `relación __proto__ invisible: ${JSON.stringify(paths)}`)
    assert.include(paths, 'conditions.__proto__ (condición de más)')
  })

  test('🟡-8 · renovación sobre `valid_until = …30.999999999Z` (techo al ms = 31.000Z; invariante 3 con `sameInstant`): omitido y 31.000Z ⇒ CERO Write; 32.000Z ⇒ UNA renovación (delete + write), no un bucle', async ({ assert }) => {
    const config = contractDenyRelationsConfig()
    const partition = { type: 'unit', uuid: uuidv7() }
    const subject = { type: 'user', uuid: uuidv7() }
    const doc = { type: 'document', id: uuidv7() }
    const object = `document:unit|${partition.uuid}|${doc.id}`
    const run = async (expiresAt: Date | undefined) => {
      const base = new OpenFgaRelationsDriver(config, { apiUrl: 'http://127.0.0.1:9', storeId: '01ARZ3NDEKTSV4RRFFQ69G5FAV', modelId: '01ARZ3NDEKTSV4RRFFQ69G5FAW', holderTypes: HOLDERS, timeoutMs: 1000, listObjectsDeadlineMs: 1000, logger: { warn: () => {} } })
      const driver: any = base.withClock(() => new Date('2030-06-15T10:20:30.000Z'))
      const writes: string[] = []
      driver.client = new Proxy({}, {
        get: (_t, prop) => async (body: any) => {
          if (prop === 'readAuthorizationModel') return { authorization_model: openFgaFactsModel(HOLDERS, [], { objectTypes: config.objectTypes }) }
          if (prop === 'read') return { tuples: [{ key: { user: `user:${subject.uuid}`, relation: 'viewer', object, condition: ne('2030-06-15T10:20:30.999999999Z') } }], continuation_token: '' }
          writes.push(`${String(prop)}:${body?.deletes ? 'deletes' : ''}${body?.writes ? 'writes' : ''}`)
          return {}
        },
      })
      await driver.relate(subject, 'viewer', doc, partition, expiresAt === undefined ? {} : { expiresAt })
      return writes
    }
    assert.deepEqual(await run(undefined), [], 'omitido preserva: cero Write')
    assert.deepEqual(await run(new Date('2030-06-15T10:20:31.000Z')), [], '31.000Z es el MISMO instante que …30.999999999Z (techo al ms): cero Write')
    assert.deepEqual(await run(new Date('2030-06-15T10:20:32.000Z')), ['write:deletes', 'write:writes'], 'una renovación de verdad: delete + write, una vez')
  })
})

const apiUrlFromEnv = process.env.OPENFGA_TEST_URL
if (apiUrlFromEnv) {
  const apiUrl: string = apiUrlFromEnv
  const stores: string[] = []
  const sdk = await import('@openfga/sdk')

  async function store(model: unknown = fullModel()): Promise<{ storeId: string; modelId: string; raw: InstanceType<typeof sdk.OpenFgaClient> }> {
    const created = await new sdk.OpenFgaClient({ apiUrl }).createStore({ name: `l11-${Date.now()}-${Math.random().toString(36).slice(2, 8)}` })
    stores.push(created.id!)
    const written = await new sdk.OpenFgaClient({ apiUrl, storeId: created.id }).writeAuthorizationModel(model as any)
    const raw = new sdk.OpenFgaClient({ apiUrl, storeId: created.id, authorizationModelId: written.authorization_model_id })
    return { storeId: created.id!, modelId: written.authorization_model_id!, raw }
  }
  const relations = (storeId: string, modelId: string, deny = true) =>
    new OpenFgaRelationsDriver(deny ? contractDenyRelationsConfig() : contractRelationsConfig(), { apiUrl, storeId, modelId, holderTypes: HOLDERS, logger: { warn: () => {} } })
  const roles = (storeId: string, modelId: string) =>
    new OpenFgaAuthorizationDriver({
      apiUrl,
      storeId,
      modelId,
      holderTypes: HOLDERS,
      resolveChain: async (scope: ScopeRef) => (scope.type === 'app' ? [APP_SCOPE] : [scope, APP_SCOPE]),
      acceptScopeDriftRisk: true,
      logger: { warn: () => {} },
    })
  const part = (): ScopeRef => ({ type: 'unit', uuid: uuidv7() })
  const user = () => ({ type: 'user', uuid: uuidv7() })
  const doc = () => ({ type: 'document', id: uuidv7() })

  test.group('L11 · contra OpenFGA (OPENFGA_TEST_URL)', (group) => {
    group.teardown(async () => {
      while (stores.length) await new sdk.OpenFgaClient({ apiUrl, storeId: stores.pop()! }).deleteStore().catch(() => undefined)
    })

    test('C1 · CONDICIÓN DE ACEPTACIÓN: el modelo GENERADO (roles + relaciones con deny), publicado tal cual por provisionOpenFgaStore y FIJADO, es IGUAL al releerlo (slice all, roles y relations) y los DOS drivers responden con UNA lectura del modelo por proceso en una MUESTRA de sus operaciones (relaciones: 12 de 15 + la vista withClock; roles: 7 de 21) — que la puerta cubra TODAS lo juzga la guardia (columna model y openfga.roles.model.equal, cliente falso)', async ({ assert }) => {
      const { storeId, modelId } = await provisionOpenFgaStore(apiUrl, `l11-c1-${Date.now()}`, HOLDERS, PERMISSIONS, relationsOf())
      stores.push(storeId)
      const reread: any = await new sdk.OpenFgaClient({ apiUrl, storeId, authorizationModelId: modelId }).readAuthorizationModel()
      for (const slice of ['all', 'roles', 'relations'] as const) {
        assert.deepEqual(diff(reread.authorization_model, slice).differences, [], `ROJO (C1): el canonicalizador no está anclado al servidor real (${slice})`)
      }
      const r = relations(storeId, modelId)
      const spy = spyFgaClient(r)
      const p = part()
      const u = user()
      const d = doc()
      const g = { type: 'group', id: uuidv7() }
      await r.relate(u, 'viewer', d, p)
      await r.relate(u, 'member', g, p, { expiresAt: new Date(Date.now() + 3_600_000) })
      await r.deny(user(), 'viewer', d, p)
      assert.isTrue(await r.check(u, 'viewer', d, p))
      assert.deepEqual(await r.checkMany(u, 'viewer', [d, doc()], p), [true, false])
      assert.deepEqual(await r.decideMany(u, 'viewer', [d], p), ['allow'])
      assert.lengthOf((await r.listObjects(u, 'viewer', 'document', p)).objects, 1)
      assert.lengthOf((await r.listSubjects('viewer', d, p)).subjects, 1)
      assert.lengthOf((await r.listDenies('viewer', d, p)).subjects, 1)
      assert.isAtLeast((await r.enumerateRelations(p)).tuples.length, 3)
      await r.withClock(() => new Date()).check(u, 'viewer', d, p)
      await r.unrelate(u, 'viewer', d, p)
      await r.purgeSubject(u, p)
      await r.purgeObject(d, p)
      assert.equal(spy.calls.filter((c) => c === 'readAuthorizationModel').length, 1, 'UNA lectura del modelo por proceso (memo compartido con withClock)')
      const a = roles(storeId, modelId)
      const roleSpy = spyFgaClient(a)
      const unit = part()
      await a.onScopeAttached(unit, APP_SCOPE)
      assert.isFalse(await a.authorize({ type: 'user', uuid: uuidv7() }, 'docs:read', unit))
      assert.deepEqual(await a.authorizeMany({ type: 'user', uuid: uuidv7() }, 'docs:read', [unit]), [false])
      assert.deepEqual(await a.listRoles({ type: 'user', uuid: uuidv7() }, unit), [])
      assert.isFalse(await a.hasRole({ type: 'user', uuid: uuidv7() }, 'admin', unit))
      assert.isArray((await a.enumerateFacts({ limit: 10 })).facts)
      await a.purgeScope(unit)
      assert.equal(roleSpy.calls.filter((c) => c === 'readAuthorizationModel').length, 1, 'UNA lectura del modelo por proceso (roles)')
    }).timeout(60_000)

    test('C2 · C6-1 LITERAL (loteD2-auditor-cierre6.ts F1): el generado + denied_viewer que admite `group#member with inverted` + la condición inverted, FIJADO ⇒ la renovación de la membresía es 500 E_AUTHZ_CONFIG que nombra las DOS rutas, con CERO Write/Read de tuplas', async ({ assert }) => {
      const model = fullModel()
      typeOf(model, 'document').metadata.relations.denied_viewer.directly_related_user_types.push({ type: 'group', relation: 'member', condition: 'inverted' })
      model.conditions.inverted = { name: 'inverted', expression: 'current_time >= valid_until', parameters: { current_time: { type_name: 'TYPE_NAME_TIMESTAMP' }, valid_until: { type_name: 'TYPE_NAME_TIMESTAMP' } } }
      const { storeId, modelId, raw } = await store(model)
      const p = part()
      const u = user()
      const g = { type: 'group', id: uuidv7() }
      const groupObject = `group:unit|${p.uuid}|${g.id}`
      await raw.write({ writes: [{ user: `user:${u.uuid}`, relation: 'member', object: groupObject, condition: ne(new Date(Date.now() + 3_600_000).toISOString()) }] })
      await raw.write({ writes: [{ user: `${groupObject}#member`, relation: 'denied_viewer', object: `document:unit|${p.uuid}|${uuidv7()}`, condition: { name: 'inverted', context: { valid_until: '2001-01-01T00:00:00Z' } } }] })
      const driver = relations(storeId, modelId)
      const spy = spyFgaClient(driver)
      const caught = await driver.relate(u, 'member', g, p, { expiresAt: new Date(Date.now() + 7_200_000) }).then(() => null, (e) => e)
      assert.equal(caught?.status, 500, `ROJO (C2): ${caught?.code} ${caught?.message}`)
      assert.equal(caught?.code, 'E_AUTHZ_CONFIG')
      assert.include(String(caught?.message), 'document#denied_viewer (restricciones de tipo)')
      assert.include(String(caught?.message), 'conditions.inverted (condición de más)')
      assert.deepEqual(spy.calls, ['readAuthorizationModel'], 'CERO Write, Read de tuplas, Check')
    }).timeout(30_000)

    test('H1-1 · el INVERSO de C2: el MISMO escenario con el modelo generado (sin la condición ajena) y un deny VIVO del grupo ⇒ la renovación sigue siendo 409 E_AUTHZ_RENEWAL_UNSAFE por la opción A (§2026-10-16 (10)), no 500: la puerta no sustituye a la opción A', async ({ assert }) => {
      const { storeId, modelId } = await store()
      const driver = relations(storeId, modelId)
      const p = part()
      const u = user()
      const g = { type: 'group', id: uuidv7() }
      await driver.relate(u, 'member', g, p, { expiresAt: new Date(Date.now() + 3_600_000) })
      await driver.deny({ object: g, relation: 'member' }, 'viewer', doc(), p)
      const caught = await driver.relate(u, 'member', g, p, { expiresAt: new Date(Date.now() + 7_200_000) }).then(() => null, (e) => e)
      assert.equal(caught?.status, 409)
      assert.equal(caught?.code, 'E_AUTHZ_RENEWAL_UNSAFE')
    }).timeout(30_000)

    test('C3 · el modelo generado FIJADO y una tupla `inverted` en el store (escrita bajo un modelo ANTERIOR del mismo store) que transporta un deny ⇒ la renovación de la membresía es 409 E_AUTHZ_RENEWAL_UNSAFE (foreign cuenta VIVA en la portadora), CERO Write — y el servidor IGNORA esa tupla al evaluar (M-a(1), medido por el auditor: lo que hace del 409 la opción más ESTRICTA, fail-closed)', async ({ assert }) => {
      const old = fullModel()
      typeOf(old, 'document').metadata.relations.denied_viewer.directly_related_user_types.push({ type: 'group', relation: 'member', condition: 'inverted' })
      old.conditions.inverted = { name: 'inverted', expression: 'current_time >= valid_until', parameters: { current_time: { type_name: 'TYPE_NAME_TIMESTAMP' }, valid_until: { type_name: 'TYPE_NAME_TIMESTAMP' } } }
      const { storeId, raw } = await store(old)
      const p = part()
      const u = user()
      const g = { type: 'group', id: uuidv7() }
      const groupObject = `group:unit|${p.uuid}|${g.id}`
      const d = doc()
      const documentObject = `document:unit|${p.uuid}|${d.id}`
      await raw.write({ writes: [{ user: `user:${u.uuid}`, relation: 'member', object: groupObject, condition: ne(new Date(Date.now() + 3_600_000).toISOString()) }] })
      await raw.write({ writes: [{ user: `${groupObject}#member`, relation: 'denied_viewer', object: documentObject, condition: { name: 'inverted', context: { valid_until: '2001-01-01T00:00:00Z' } } }] })
      const generated = await new sdk.OpenFgaClient({ apiUrl, storeId }).writeAuthorizationModel(fullModel())
      const driver = relations(storeId, generated.authorization_model_id!)
      await driver.relate(u, 'viewer', d, p)
      assert.isTrue(await driver.check(u, 'viewer', d, p), 'M-a(1): con el modelo generado el servidor IGNORA la tupla ajena (el deny no corta)')
      const spy = spyFgaClient(driver)
      const caught = await driver.relate(u, 'member', g, p, { expiresAt: new Date(Date.now() + 7_200_000) }).then(() => null, (e) => e)
      assert.equal(caught?.code, 'E_AUTHZ_RENEWAL_UNSAFE', `ROJO (C3): ${caught?.code} ${caught?.message}`)
      assert.notInclude(spy.calls, 'write', 'CERO Write')
      const denies = await driver.listDenies('viewer', d, p)
      assert.deepEqual(denies.subjects, [], 'listDenies NO lista un deny con condición ajena (se avisa y se cuenta)')
      assert.isAtLeast(driver.diagnostics.unparseableTuples, 1)
    }).timeout(30_000)

    test('C4 · C6-2 contra el servidor: valid_until=…30.999999999Z ⇒ con now=.999 el paquete (check, listSubjects) y el servidor dicen VIVA; con now=31.000 los dos dicen VENCIDA (reloj inyectado con withClock, sin sleep)', async ({ assert }) => {
      const { storeId, modelId, raw } = await store()
      const p = part()
      const u = user()
      const d = doc()
      const object = `document:unit|${p.uuid}|${d.id}`
      await raw.write({ writes: [{ user: `user:${u.uuid}`, relation: 'viewer', object, condition: ne('2030-06-15T10:20:30.999999999Z') }] })
      const driver = relations(storeId, modelId)
      for (const [now, alive] of [['2030-06-15T10:20:30.999Z', true], ['2030-06-15T10:20:31.000Z', false]] as const) {
        const view = driver.withClock(() => new Date(now))
        const server = await raw.check({ user: `user:${u.uuid}`, relation: 'viewer', object, context: { current_time: now } })
        assert.equal(server.allowed, alive, `el servidor con now=${now}`)
        assert.equal(await view.check(u, 'viewer', d, p), alive, `check con now=${now}`)
        assert.lengthOf((await view.listSubjects('viewer', d, p)).subjects, alive ? 1 : 0, `ROJO (C6-2): listSubjects con now=${now} no coincide con el servidor`)
      }
    }).timeout(30_000)

    test('C10 + H1-4 · roles: tres modelos DERIVADOS publicados y fijados —scope#can_P sin `but not denied_P`, assignee sin `with not_expired` (el modelo R de F0 · M-a(2)) y rooted cambiado— ⇒ 500 E_AUTHZ_CONFIG al usarlos, con CERO Check (hasta L11 concedía o negaba sin error)', async ({ assert }) => {
      const variants: Array<[string, (m: any) => void, string]> = [
        ['can sin but not', (m) => { typeOf(m, 'scope').relations.can_docs_read = { intersection: { child: [{ computedUserset: { relation: 'docs_read' } }, { computedUserset: { relation: 'rooted' } }] } } }, 'scope#can_docs_read (regla)'],
        ['assignee solo with not_expired (modelo R)', (m) => {
          const a = typeOf(m, 'role_binding').metadata.relations.assignee
          a.directly_related_user_types = a.directly_related_user_types.filter((r: any) => r.condition)
        }, 'role_binding#assignee (restricciones de tipo)'],
        ['rooted sin la TTU', (m) => { typeOf(m, 'scope').relations.rooted = { this: {} } }, 'scope#rooted (regla)'],
      ]
      for (const [what, mutate, path] of variants) {
        const model = fullModel()
        mutate(model)
        const { storeId, modelId } = await store(model)
        const driver = roles(storeId, modelId)
        const spy = spyFgaClient(driver)
        const caught = await driver.authorize({ type: 'user', uuid: uuidv7() }, 'docs:read', part()).then(() => null, (e) => e)
        assert.equal(caught?.code, 'E_AUTHZ_CONFIG', `ROJO (C10 · ${what}): ${caught?.code}`)
        assert.include(String(caught?.message), path, what)
        assert.deepEqual(spy.calls, ['readAuthorizationModel'], `${what}: CERO Check`)
      }
    }).timeout(60_000)

    test('H1-5 · F-05 va ANTES que la puerta: un tipo no declarado con un modelo con deriva ⇒ 422 E_AUTHZ_RELATION_TYPE_UNKNOWN con CERO llamadas (ni la lectura del modelo)', async ({ assert }) => {
      const model = fullModel()
      typeOf(model, 'document').relations.zz_extra = { this: {} }
      typeOf(model, 'document').metadata.relations.zz_extra = { directly_related_user_types: [{ type: 'user' }] }
      const { storeId, modelId } = await store(model)
      const driver = relations(storeId, modelId)
      const spy = spyFgaClient(driver)
      const caught = await driver.relate(user(), 'assignee', { type: 'role_binding', id: uuidv7() }, part()).then(() => null, (e) => e)
      assert.equal(caught?.status, 422)
      assert.equal(caught?.code, 'E_AUTHZ_RELATION_TYPE_UNKNOWN')
      assert.deepEqual(spy.calls, [])
      const drift = await driver.check(user(), 'viewer', doc(), part()).then(() => null, (e) => e)
      assert.include(String(drift?.message), 'document#zz_extra (relación de más)', 'C8: la relación de más es deriva y se nombra')
    }).timeout(30_000)

    test('H1-6 · PROVISIONAL (R3 lo voltea a 500 E_AUTHZ_CONFIG «no es transitorio»): un modelId que NO existe en el store ⇒ la lectura del modelo es 503 E_AUTHZ_BACKEND_UNAVAILABLE, nunca «igual», y no se memoriza', async ({ assert }) => {
      const { storeId } = await store()
      const driver = relations(storeId, '01ARZ3NDEKTSV4RRFFQ69G5FAW')
      const spy = spyFgaClient(driver)
      for (let i = 0; i < 2; i++) {
        const caught = await driver.check(user(), 'viewer', doc(), part()).then(() => null, (e) => e)
        assert.equal(caught?.status, 503, `H1-6 (provisional): ${caught?.code}`)
        assert.equal(caught?.code, 'E_AUTHZ_BACKEND_UNAVAILABLE')
      }
      assert.deepEqual(spy.calls, ['readAuthorizationModel', 'readAuthorizationModel'], 'el fallo no se memoriza: relee')
    }).timeout(30_000)
  })
}
