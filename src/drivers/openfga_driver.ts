import { Exception } from '@adonisjs/core/exceptions'
import db from '@adonisjs/lucid/services/db'
import {
  OpenFgaClient,
  ClientWriteRequestOnDuplicateWrites,
  ClientWriteRequestOnMissingDeletes,
} from '@openfga/sdk'
import type {
  AuthorizationDriver,
  GrantOptions,
  ScopeAncestorsResolver,
  ScopeRef,
  ScopeType,
  SubjectRef,
} from '../types.js'
import { APP_SCOPE, APP_SCOPE_TYPE } from '../types.js'
import { APP_SCOPE_DB_UUID } from './database_driver.js'

/**
 * Driver `openfga` — los HECHOS (asignaciones y denies) viven en un servidor
 * OpenFGA; el CATÁLOGO (roles/permisos/vínculos) y la JERARQUÍA (orgs/units)
 * siguen siendo metadata local en las tablas del chasis (split de propiedad
 * de datos del análisis: cambiar de driver = migrar una tabla de hechos).
 *
 * Modelo FGA genérico (ver `openFgaAuthorizationModel()`):
 *  - `role_binding:<scopeKey>|<rol>`   #assignee  → asignación de rol
 *  - `deny_binding:<scopeKey>|<perm>`  #denied    → deny explícito
 *  - Expiración vía condition `not_expired` (valid_until en la tupla,
 *    current_time en cada check) — ni scheduler necesita.
 *
 * La herencia se resuelve igual que en el driver database: la cadena de
 * scopes se calcula localmente (el árbol lo declara el consumidor vía
 * `resolveAncestors`) y se consulta FGA por batchCheck sobre la cadena.
 *
 * NADA del dominio está cableado: los holders llegan como `holderTypes`
 * (morph name → tipo FGA) y los niveles de scope se derivan del propio
 * `ScopeRef`, así que un consumidor con otros guards u otra jerarquía solo
 * cambia config.
 */

/**
 * Mapa morph name → tipo del modelo FGA (`users` → `user`). Debe ser el
 * MISMO con el que se generó el authorization model del store.
 */
export type HolderTypeMap = Record<string, string>

/** `:` no es válido en ids de FGA — se encodea (`audit:read` → `audit~read`). */
function encodeSlug(slug: string): string {
  return slug.replaceAll(':', '~')
}
function decodeSlug(encoded: string): string {
  return encoded.replaceAll('~', ':')
}

/**
 * Caracteres admitidos en un tipo de scope y en un uuid al construir la clave
 * del binding. `|` es el separador y `~` el escape de los slugs: si alguno
 * apareciera dentro de un componente, dos scopes DISTINTOS podrían producir
 * la misma clave —p. ej. `{org, 'anization|X'}` y `{'org|anization', 'X'}`—
 * y un grant en uno autorizaría en el otro (confusión de privilegios).
 *
 * El driver `database` es inmune por construcción (guarda tipo y uuid en
 * columnas separadas, sin codificar); esta validación protege la única ruta
 * que serializa el scope a un string.
 */
const SCOPE_COMPONENT_FORMAT = /^[a-zA-Z0-9_.:-]+$/

function assertScopeComponent(kind: string, value: string): void {
  if (!SCOPE_COMPONENT_FORMAT.test(value)) {
    throw new Exception(
      `${kind} inválido para el driver openfga: '${value}'. ` +
        `Solo se admiten letras, dígitos y . _ - : (ni '|' ni '~').`,
      { status: 500 }
    )
  }
}

/**
 * Clave de scope dentro del id del binding: `app` para la raíz,
 * `<tipo>|<uuid>` para el resto. Genérico: sirve para cualquier nivel que
 * defina el consumidor sin tocar el driver.
 */
function scopeKey(scope: ScopeRef): string {
  assertScopeComponent('Tipo de scope', scope.type)
  if (scope.type === APP_SCOPE_TYPE) return APP_SCOPE_TYPE
  assertScopeComponent('UUID de scope', String(scope.uuid ?? ''))
  return `${scope.type}|${scope.uuid}`
}

function parseBindingId(id: string): { scope: ScopeRef; slug: string } | null {
  const parts = id.split('|')
  if (parts.length === 2 && parts[0] === APP_SCOPE_TYPE) {
    return { scope: { type: APP_SCOPE_TYPE, uuid: null }, slug: decodeSlug(parts[1]) }
  }
  if (parts.length === 3) {
    return { scope: { type: parts[0], uuid: parts[1] }, slug: decodeSlug(parts[2]) }
  }
  return null
}

/** `<tipoFga>:<uuid>` a partir del morph name del holder. */
function fgaSubjectWith(subject: SubjectRef, holderTypes: HolderTypeMap): string {
  const fgaType = holderTypes[subject.type]
  if (!fgaType) {
    throw new Exception(
      `Holder type '${subject.type}' no está en el modelo FGA ` +
        `(declarados: ${Object.keys(holderTypes).join(', ') || 'ninguno'}). ` +
        `Añádelo a holderTypes y regenera el authorization model.`,
      { status: 500 }
    )
  }
  return `${fgaType}:${subject.uuid}`
}

function checkContext(): object {
  return { current_time: new Date().toISOString() }
}

/**
 * El authorization model en formato JSON del API de FGA, generado a partir
 * de los holders del consumidor. El mismo mapa debe usarse al construir el
 * driver: si difieren, los checks no encuentran las tuplas.
 */
export function openFgaAuthorizationModel(holderTypeMap: HolderTypeMap): any {
  const holderTypes = [...new Set(Object.values(holderTypeMap))]
  const direct = holderTypes.map((type) => ({ type }))
  const directWithExpiry = [
    ...direct,
    ...holderTypes.map((type) => ({ type, condition: 'not_expired' })),
  ]
  return {
    schema_version: '1.1',
    type_definitions: [
      ...holderTypes.map((type) => ({ type, relations: {}, metadata: null })),
      {
        type: 'role_binding',
        relations: { assignee: { this: {} } },
        metadata: {
          relations: { assignee: { directly_related_user_types: directWithExpiry } },
        },
      },
      {
        type: 'deny_binding',
        relations: { denied: { this: {} } },
        metadata: {
          relations: { denied: { directly_related_user_types: direct } },
        },
      },
    ],
    conditions: {
      not_expired: {
        name: 'not_expired',
        expression: 'current_time < valid_until',
        parameters: {
          current_time: { type_name: 'TYPE_NAME_TIMESTAMP' },
          valid_until: { type_name: 'TYPE_NAME_TIMESTAMP' },
        },
      },
    },
  }
}

/**
 * Crea un store nuevo + escribe el authorization model derivado de los
 * holders del consumidor. Para bootstrap de un appliance o del harness de
 * tests. El `name` lo decide el caller (el comando openfga:provision
 * resuelve APP_NAME del entorno — el motor no lee env).
 */
export async function provisionOpenFgaStore(
  apiUrl: string,
  name: string,
  holderTypeMap: HolderTypeMap
): Promise<{ storeId: string; modelId: string }> {
  const client = new OpenFgaClient({ apiUrl })
  const store = await client.createStore({ name })
  const scoped = new OpenFgaClient({ apiUrl, storeId: store.id })
  const model = await scoped.writeAuthorizationModel(openFgaAuthorizationModel(holderTypeMap))
  return { storeId: store.id!, modelId: model.authorization_model_id! }
}

export interface OpenFgaDriverOptions {
  apiUrl: string
  storeId: string
  /** Pin del model; si se omite, FGA usa el último. */
  modelId?: string
  /** Jerarquía del consumidor (ver ScopeAncestorsResolver). */
  resolveAncestors?: ScopeAncestorsResolver
  /**
   * Holders del consumidor: morph name → tipo FGA. Debe coincidir con el
   * mapa usado al escribir el authorization model del store.
   */
  holderTypes: HolderTypeMap
}

export interface ImportFactsResult {
  assignments: number
  denies: number
  skippedExpired: number
  dryRun: boolean
}

/**
 * Migración de hechos database → openfga: copia las asignaciones vigentes y
 * los denies de las tablas `authz_*` como tuples del store FGA.
 *
 * - COPIA, no mueve: las tablas locales quedan intactas → el rollback es
 *   volver a AUTHZ_DRIVER=database (solo se pierde lo escrito mientras se
 *   operó con openfga). El catálogo y la jerarquía nunca migran: son
 *   metadata local para ambos drivers.
 * - Idempotente: re-ejecutar no duplica (onDuplicateWrites: Ignore).
 * - Las asignaciones ya expiradas se saltan (no tiene sentido copiarlas);
 *   las de expiración futura viajan con la condition `not_expired`.
 */
export async function importAuthzFactsToOpenFga(
  options: OpenFgaDriverOptions & { dryRun?: boolean }
): Promise<ImportFactsResult> {
  const client = new OpenFgaClient({
    apiUrl: options.apiUrl,
    storeId: options.storeId,
    authorizationModelId: options.modelId,
  })

  const now = new Date()
  const result: ImportFactsResult = {
    assignments: 0,
    denies: 0,
    skippedExpired: 0,
    dryRun: options.dryRun ?? false,
  }
  const tuples: any[] = []

  const assignments = await db
    .from('authz_assignments as a')
    .join('authz_roles as r', 'r.uuid', 'a.role_uuid')
    .select('a.holder_type', 'a.holder_uuid', 'a.scope_type', 'a.scope_uuid', 'a.expires_at')
    .select('r.slug as role_slug')

  const rowScope = (row: any): ScopeRef => ({
    type: row.scope_type,
    uuid: row.scope_uuid === APP_SCOPE_DB_UUID ? null : row.scope_uuid,
  })

  for (const row of assignments) {
    const expiresAt = row.expires_at ? new Date(row.expires_at) : null
    if (expiresAt && expiresAt <= now) {
      result.skippedExpired++
      continue
    }
    const scope = rowScope(row)
    const key = {
      user: fgaSubjectWith({ type: row.holder_type, uuid: row.holder_uuid }, options.holderTypes),
      relation: 'assignee',
      object: `role_binding:${scopeKey(scope)}|${encodeSlug(row.role_slug)}`,
    }
    tuples.push(
      expiresAt
        ? {
            ...key,
            condition: { name: 'not_expired', context: { valid_until: expiresAt.toISOString() } },
          }
        : key
    )
    result.assignments++
  }

  const denies = await db
    .from('authz_denies as d')
    .join('authz_permissions as p', 'p.uuid', 'd.permission_uuid')
    .select('d.holder_type', 'd.holder_uuid', 'd.scope_type', 'd.scope_uuid')
    .select('p.slug as permission_slug')

  for (const row of denies) {
    const scope = rowScope(row)
    tuples.push({
      user: fgaSubjectWith({ type: row.holder_type, uuid: row.holder_uuid }, options.holderTypes),
      relation: 'denied',
      object: `deny_binding:${scopeKey(scope)}|${encodeSlug(row.permission_slug)}`,
    })
    result.denies++
  }

  if (!result.dryRun && tuples.length > 0) {
    // Chunks: el write transaccional de FGA tiene límite de tuples por request.
    for (let i = 0; i < tuples.length; i += 50) {
      await client.writeTuples(tuples.slice(i, i + 50), {
        conflict: { onDuplicateWrites: ClientWriteRequestOnDuplicateWrites.Ignore },
      })
    }
  }

  return result
}

export class OpenFgaAuthorizationDriver implements AuthorizationDriver {
  private client: OpenFgaClient
  private resolveAncestors: ScopeAncestorsResolver
  private holderTypes: HolderTypeMap

  constructor(options: OpenFgaDriverOptions) {
    this.client = new OpenFgaClient({
      apiUrl: options.apiUrl,
      storeId: options.storeId,
      authorizationModelId: options.modelId,
    })
    this.resolveAncestors =
      options.resolveAncestors ??
      (async (scope) => (scope.type === APP_SCOPE_TYPE ? [] : [APP_SCOPE]))
    this.holderTypes = options.holderTypes
  }

  private async chain(scope: ScopeRef): Promise<ScopeRef[]> {
    return [scope, ...(await this.resolveAncestors(scope))]
  }

  private fgaSubject(subject: SubjectRef): string {
    return fgaSubjectWith(subject, this.holderTypes)
  }

  /**
   * batchCheck troceado al límite del servidor FGA (50 checks/request) y con
   * verificación de completitud: TODOS los checks deben volver respondidos.
   */
  private async batchCheckAll(checks: any[]): Promise<any[]> {
    const results: any[] = []
    for (let i = 0; i < checks.length; i += 50) {
      const slice = checks.slice(i, i + 50)
      const response = await this.client.batchCheck({ checks: slice })
      results.push(...response.result)
    }
    if (results.length !== checks.length) {
      throw new Exception('OpenFGA batchCheck devolvió menos resultados que checks', {
        status: 500,
      })
    }
    return results
  }

  // ── Catálogo local (compartido entre drivers) ─────────────────────────

  private async findPermission(slug: string): Promise<{ uuid: string } | null> {
    return db.from('authz_permissions').where('slug', slug).select('uuid').first()
  }

  private async findRoleOrFail(slug: string, scopeType: string): Promise<void> {
    const role = await db
      .from('authz_roles')
      .where('slug', slug)
      .where('scope_type', scopeType)
      .select('uuid')
      .first()
    if (!role) {
      throw new Exception(`Rol '${slug}' no existe en el catálogo para el nivel '${scopeType}'`, {
        status: 422,
      })
    }
  }

  /** Roles del catálogo que conceden el permiso, agrupados por scope_type. */
  private async rolesGranting(permissionUuid: string): Promise<Map<string, string[]>> {
    const rows = await db
      .from('authz_role_permissions as rp')
      .join('authz_roles as r', 'r.uuid', 'rp.role_uuid')
      .where('rp.permission_uuid', permissionUuid)
      .select('r.slug', 'r.scope_type')
    const byScopeType = new Map<string, string[]>()
    for (const row of rows) {
      const list = byScopeType.get(row.scope_type) ?? []
      list.push(row.slug)
      byScopeType.set(row.scope_type, list)
    }
    return byScopeType
  }

  // ── Contrato ──────────────────────────────────────────────────────────

  async authorize(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<boolean> {
    const perm = await this.findPermission(permission)
    if (!perm) return false

    const user = this.fgaSubject(subject)
    const chain = await this.chain(scope)

    // 1. Denies en la cadena. FAIL-CLOSED: un check de deny con error se
    //    trata como denegado (jamás se ignora un deny por un fallo puntual).
    const denyChecks = chain.map((s) => ({
      user,
      relation: 'denied',
      object: `deny_binding:${scopeKey(s)}|${encodeSlug(permission)}`,
    }))
    const denyResults = await this.batchCheckAll(denyChecks)
    if (denyResults.some((r) => r.allowed || r.error)) return false

    // 2. Alguna asignación vigente en la cadena cuyo rol concede el permiso.
    //    Aquí un error individual falla cerrado por sí solo (no concede).
    const granting = await this.rolesGranting(perm.uuid)
    const checks = chain.flatMap((s) =>
      (granting.get(s.type) ?? []).map((roleSlug) => ({
        user,
        relation: 'assignee',
        object: `role_binding:${scopeKey(s)}|${encodeSlug(roleSlug)}`,
        context: checkContext(),
      }))
    )
    if (checks.length === 0) return false

    const results = await this.batchCheckAll(checks)
    return results.some((r) => r.allowed && !r.error)
  }

  async grant(
    subject: SubjectRef,
    role: string,
    scope: ScopeRef,
    options: GrantOptions = {}
  ): Promise<void> {
    await this.findRoleOrFail(role, scope.type)

    const key = {
      user: this.fgaSubject(subject),
      relation: 'assignee',
      object: `role_binding:${scopeKey(scope)}|${encodeSlug(role)}`,
    }
    const write = options.expiresAt
      ? {
          ...key,
          condition: {
            name: 'not_expired',
            context: { valid_until: options.expiresAt.toISOString() },
          },
        }
      : key

    // Re-grant refresca la expiración. FGA no admite delete+write de la
    // misma tuple key en una transacción → dos llamadas tolerantes.
    await this.client.deleteTuples([key], {
      conflict: { onMissingDeletes: ClientWriteRequestOnMissingDeletes.Ignore },
    })
    await this.client.writeTuples([write], {
      conflict: { onDuplicateWrites: ClientWriteRequestOnDuplicateWrites.Ignore },
    })
  }

  async revoke(subject: SubjectRef, role: string, scope: ScopeRef): Promise<void> {
    await this.client.deleteTuples(
      [
        {
          user: this.fgaSubject(subject),
          relation: 'assignee',
          object: `role_binding:${scopeKey(scope)}|${encodeSlug(role)}`,
        },
      ],
      { conflict: { onMissingDeletes: ClientWriteRequestOnMissingDeletes.Ignore } }
    )
  }

  async hasRole(subject: SubjectRef, role: string, scope: ScopeRef): Promise<boolean> {
    const user = this.fgaSubject(subject)
    const chain = await this.chain(scope)
    const results = await this.batchCheckAll(
      chain.map((s) => ({
        user,
        relation: 'assignee',
        object: `role_binding:${scopeKey(s)}|${encodeSlug(role)}`,
        context: checkContext(),
      }))
    )
    return results.some((r) => r.allowed && !r.error)
  }

  async deny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void> {
    const perm = await this.findPermission(permission)
    if (!perm) {
      throw new Exception(`Permiso '${permission}' no existe en el catálogo`, { status: 422 })
    }
    await this.client.writeTuples(
      [
        {
          user: this.fgaSubject(subject),
          relation: 'denied',
          object: `deny_binding:${scopeKey(scope)}|${encodeSlug(permission)}`,
        },
      ],
      { conflict: { onDuplicateWrites: ClientWriteRequestOnDuplicateWrites.Ignore } }
    )
  }

  async removeDeny(subject: SubjectRef, permission: string, scope: ScopeRef): Promise<void> {
    await this.client.deleteTuples(
      [
        {
          user: this.fgaSubject(subject),
          relation: 'denied',
          object: `deny_binding:${scopeKey(scope)}|${encodeSlug(permission)}`,
        },
      ],
      { conflict: { onMissingDeletes: ClientWriteRequestOnMissingDeletes.Ignore } }
    )
  }

  async listSubjects(role: string, scope: ScopeRef): Promise<SubjectRef[]> {
    // ListUsers exige EXACTAMENTE un user_filter → una consulta por tipo.
    const results: SubjectRef[] = []
    const fgaToMorph = Object.fromEntries(
      Object.entries(this.holderTypes).map(([morph, fga]) => [fga, morph])
    )
    for (const fgaType of [...new Set(Object.values(this.holderTypes))]) {
      const response = await this.client.listUsers({
        object: { type: 'role_binding', id: `${scopeKey(scope)}|${encodeSlug(role)}` },
        relation: 'assignee',
        user_filters: [{ type: fgaType }],
        context: checkContext(),
      })
      for (const u of response.users ?? []) {
        if (u.object) {
          results.push({ type: fgaToMorph[u.object.type] ?? u.object.type, uuid: u.object.id })
        }
      }
    }
    return results
  }

  /** role_binding ids del subject (asignaciones directas vigentes). */
  private async listBindings(subject: SubjectRef): Promise<string[]> {
    const response = await this.client.listObjects({
      user: this.fgaSubject(subject),
      relation: 'assignee',
      type: 'role_binding',
      context: checkContext(),
    })
    return (response.objects ?? []).map((obj) => obj.replace(/^role_binding:/, ''))
  }

  async listRoles(subject: SubjectRef, scope: ScopeRef): Promise<string[]> {
    const prefix = scopeKey(scope)
    const roles = new Set<string>()
    for (const id of await this.listBindings(subject)) {
      const parsed = parseBindingId(id)
      if (parsed && scopeKey(parsed.scope) === prefix) roles.add(parsed.slug)
    }
    return [...roles]
  }

  async listRoleScopes(subject: SubjectRef, scopeType: ScopeType): Promise<ScopeRef[]> {
    const seen = new Map<string, ScopeRef>()
    for (const id of await this.listBindings(subject)) {
      const parsed = parseBindingId(id)
      if (parsed && parsed.scope.type === scopeType) {
        seen.set(scopeKey(parsed.scope), parsed.scope)
      }
    }
    return [...seen.values()]
  }

  async listScopes(subject: SubjectRef, permission: string): Promise<ScopeRef[]> {
    const perm = await this.findPermission(permission)
    if (!perm) return []

    const granting = await this.rolesGranting(perm.uuid)

    // Denies del subject para este permiso (una sola consulta).
    const denyResponse = await this.client.listObjects({
      user: this.fgaSubject(subject),
      relation: 'denied',
      type: 'deny_binding',
    })
    const deniedKeys = new Set(
      (denyResponse.objects ?? [])
        .map((obj) => obj.replace(/^deny_binding:/, ''))
        .map((id) => parseBindingId(id))
        .filter((p): p is NonNullable<typeof p> => Boolean(p && p.slug === permission))
        .map((p) => scopeKey(p.scope))
    )

    const result = new Map<string, ScopeRef>()
    for (const id of await this.listBindings(subject)) {
      const parsed = parseBindingId(id)
      if (!parsed) continue
      if (!(granting.get(parsed.scope.type) ?? []).includes(parsed.slug)) continue

      const chain = await this.chain(parsed.scope)
      const blocked = chain.some((s) => deniedKeys.has(scopeKey(s)))
      if (!blocked) result.set(scopeKey(parsed.scope), parsed.scope)
    }
    return [...result.values()]
  }
}
