import { BaseCommand, flags } from '@adonisjs/core/ace'
import { CommandOptions } from '@adonisjs/core/types/ace'

/** Un huérfano tal como lo reporta `manager.pruneOrphanRoles()`. */
interface OrphanRow {
  role: { uuid: string; slug: string; scopeType: string; rank: number }
  owner: { type: string; uuid?: string | null }
  permissions: string[]
  /** Hechos vigentes del rol, o `undefined` si el driver no sabe contarlos (3b-2j). */
  assignments: number | undefined
  /** `true` concede, `false` no concede SEGURO, `undefined` **no se sabe** (3b-2j). */
  stillGranting: boolean | undefined
}

/**
 * Las líneas del listado, en TRES cubos (3b-2j, decisión del dueño del
 * 2026-08-31 (3) · consecuencia 2). Es una función pura para que el reparto
 * —lo único del comando que decide algo— tenga su caso.
 *
 *  - `stillGranting === false`: el driver ha contado sus hechos y son cero.
 *    Es el único cubo del que se puede decir «no concede»: línea normal.
 *  - `true`: concede hoy. Aparte y con aviso, desde 3b-0b · AA1.
 *  - `undefined`: el driver no implementa `countRoleAssignments`, así que
 *    NADIE lo sabe. Va con los anteriores —aparte y con aviso—, porque «no
 *    lo sé» no puede leerse como «no concede» justo antes de un borrado.
 */
export function orphanLines(
  orphans: OrphanRow[],
  purged: Set<string>,
  skipped: Set<string>
): Array<{ level: 'log' | 'warning'; message: string }> {
  const estado = (o: OrphanRow) =>
    skipped.has(o.role.uuid) ? 'saltado (el owner volvió)' : purged.has(o.role.uuid) ? 'purgado' : 'huérfano'
  const linea = (o: OrphanRow) =>
    `${o.role.slug}@${o.role.scopeType} (uuid ${o.role.uuid}, rank ${o.role.rank}) — owner ` +
    `${o.owner.type}:${o.owner.uuid ?? ''} ya no existe en el árbol; permisos: ${o.permissions.join(', ') || '—'}` +
    (o.stillGranting === true ? `; asignaciones VIGENTES: ${o.assignments}` : '')
  const lines: Array<{ level: 'log' | 'warning'; message: string }> = []
  for (const o of orphans.filter((x) => x.stillGranting === false)) {
    lines.push({ level: 'log', message: `${estado(o)}: ${linea(o)}` })
  }
  const vivos = orphans.filter((x) => x.stillGranting === true)
  for (const o of vivos) lines.push({ level: 'warning', message: `${estado(o)} · TODAVÍA CONCEDE: ${linea(o)}` })
  const dudosos = orphans.filter((x) => x.stillGranting === undefined)
  for (const o of dudosos) {
    lines.push({ level: 'warning', message: `${estado(o)} · NO SE SABE SI CONCEDE: ${linea(o)}` })
  }
  if (vivos.length > 0) {
    lines.push({
      level: 'warning',
      message:
        `${vivos.length} rol(es) huérfano(s) siguen teniendo asignaciones vigentes: un rol dormido NO deja de conceder si ` +
        `algún scope vivo conserva al owner en su cadena (rutas materializadas, borrado en dos pasos). Purgarlos revoca ` +
        `permisos que hoy funcionan.`,
    })
  }
  if (dudosos.length > 0) {
    lines.push({
      level: 'warning',
      message:
        `${dudosos.length} rol(es) huérfano(s) SIN demostración de que no concedan: el driver configurado no implementa ` +
        `'countRoleAssignments' (el método del puerto que cuenta los hechos vigentes de un rol), así que nadie sabe si ` +
        `están concediendo. Se listan aparte a propósito: 'no lo sé' no es 'no concede', y --force los borra igual.`,
    })
  }
  return lines
}

/**
 * La letra de los disparadores del seguro de purga masiva (3b-0b · AA2 + rotación 2 · R2-02), en el orden en que
 * el manager los reporta. Pura, para que el caso la fije.
 */
export function massPurgeLetter(reasons: ReadonlyArray<string>): string {
  const words: Record<string, string> = {
    'all-owners': 'todos los owners salen huérfanos',
    'proportion': 'más del 50 % de los roles locales',
    'granting-across-owners': 'huérfanos de más de un owner y alguno TODAVÍA concede o no se sabe',
  }
  return reasons.map((reason) => words[reason] ?? reason).join('; ') || 'sin motivo reportado'
}

/**
 * Lista —y con `--force` borra— los roles LOCALES cuyo owner el árbol del
 * consumidor YA NO conoce (3b-0 · Z2).
 *
 * Un rol así está DORMIDO, y «dormido» significa exactamente esto
 * (3b-0b · AA1): no es visible desde ningún scope vivo cuya cadena NO pase
 * por su owner. NO significa que no conceda: un descendiente vivo cuya ruta
 * materializada siga pasando por el owner cumple la regla de visibilidad
 * (invariante 18), y desde ahí el rol concede, es membresía y se puede
 * asignar. Por eso este comando puede estar revocando permisos VIVOS, y por
 * eso los huérfanos que aún tienen asignaciones vigentes se listan aparte,
 * con aviso — y desde 3b-2j también los que el driver no sabe contar (un
 * driver sin `countRoleAssignments`): «no lo sé» no es «no concede».
 *
 * Lo que el rol dormido hace en todo caso es ocupar su
 * `(slug, nivel)` allí donde todavía se le vea, y `deleteScopedRole` no lo
 * alcanza (resuelve el owner en fresco: 422 `E_AUTHZ_UNKNOWN_SCOPE`). Esta
 * es su salida.
 *
 *   node ace authz:catalog:prune-orphans                      # --dry-run: solo lista
 *   node ace authz:catalog:prune-orphans --force              # purga de verdad
 *   node ace authz:catalog:prune-orphans --force --allow-mass-purge
 *   node ace authz:catalog:prune-orphans --max-local-roles=50000   # catálogo local de más de 10 000 roles
 *
 * Es una operación de PLATAFORMA, no una escritura que dispare un tenant: no
 * lleva actor ni mide rangos. Hasta 3G esta limpieza la arrastraba
 * `scopes.detached` —que SÍ dispara un tenant, sobre un scope que ya no
 * resuelve—, y de ahí salieron tres de las cuatro regresiones de la Fase 3.
 *
 * `--allow-mass-purge` (3b-0b · AA2) desbloquea la cota que rechaza una
 * pasada con la firma de un resolutor ciego (todos los owners huérfanos,
 * más del 50 % de los roles locales, o —rotación 2 · R2-02— huérfanos de más
 * de un owner con alguno que todavía concede): es una decisión humana, no un
 * default. `--max-local-roles` (R2-04) sube la cota de la lectura.
 */
export default class AuthzCatalogPruneOrphans extends BaseCommand {
  static commandName = 'authz:catalog:prune-orphans'
  static description = 'List (or, with --force, purge) local roles whose owner scope no longer exists'

  static options: CommandOptions = {
    startApp: true,
  }

  @flags.boolean({ description: 'Actually purge the orphan roles (default is a dry run)' })
  declare force: boolean | undefined

  @flags.boolean({
    description:
      'Allow a pass that would purge every owner, more than half the local roles, or orphans of several owners that still grant (or cannot be counted) — check your resolveChain first',
  })
  declare allowMassPurge: boolean | undefined

  /**
   * Rotación 2 · R2-04: la cota de la lectura del catálogo local (default 10 000). Hasta este cierre el mensaje
   * de `E_AUTHZ_TOO_MANY_LOCAL_ROLES` pedía «subir la cota» y no había mando: un tenant que pasara de 10 000 roles
   * locales dejaba este comando muerto para todos. Un valor que no es un entero ≥ 1 lo rechaza el manager (500
   * `E_AUTHZ_CONFIG`) antes de leer nada.
   */
  @flags.number({
    description: 'Cap on the local roles this pass reads (default 10000); above it, 500 E_AUTHZ_TOO_MANY_LOCAL_ROLES, never a partial list',
  })
  declare maxLocalRoles: number | undefined

  async run() {
    const { default: authorization } = await import('../services/main.js')
    const { orphans, purged, skipped, massPurge, massPurgeReasons, dryRun } = await authorization.pruneOrphanRoles({
      force: this.force === true,
      allowMassPurge: this.allowMassPurge === true,
      ...(this.maxLocalRoles !== undefined ? { maxLocalRoles: this.maxLocalRoles } : {}),
    })

    // Los que todavía conceden —y los que NADIE puede demostrar que no
    // concedan— van aparte, con aviso: purgarlos es revocar permisos vivos,
    // no recoger basura (3b-0b · AA1 + 3b-2j).
    for (const { level, message } of orphanLines(
      orphans,
      new Set(purged.map((role) => role.uuid)),
      new Set(skipped.map(({ role }) => role.uuid))
    )) {
      this.logger[level](message)
    }

    if (orphans.length === 0) {
      this.logger.success('No hay roles locales huérfanos: todos los owners resuelven.')
      return
    }
    if (dryRun) {
      if (massPurge) {
        this.logger.warning(
          `${orphans.length} de los roles locales quedarían huérfanos: eso es la firma de un 'scopes.resolveChain' ciego ` +
            `(${massPurgeLetter(massPurgeReasons ?? [])}). ` +
            `Con --force esto se rechaza (E_AUTHZ_MASS_PURGE_REFUSED); comprueba el resolutor antes de añadir --allow-mass-purge.`
        )
      }
      this.logger.warning(
        `${orphans.length} rol(es) local(es) con el owner fuera del árbol. No se ha borrado nada: repite con --force.`
      )
      return
    }
    if (skipped.length > 0) {
      this.logger.warning(`${skipped.length} rol(es) saltado(s): su owner volvió al árbol durante la pasada.`)
    }
    this.logger.success(`${purged.length} rol(es) local(es) huérfano(s) purgado(s).`)
  }
}
