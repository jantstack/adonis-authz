/**
 * **`@jantstack/adonis-authz/relations/reconcile` — la ÚNICA vía pública para
 * reconciliar relaciones desde código** (plan 2.5 · lote B · B7, ruptura del
 * roadmap 2.5). Hasta `2.5.0-alpha.1` `runRelationsReconcile` se importaba de
 * `@jantstack/adonis-authz/commands/authz_relations_reconcile`: el módulo del
 * COMANDO de ace, que arrastra `@adonisjs/core/ace` y cuyo comodín
 * `./commands/*` existe para el loader, no para API. Desde B7 vive aquí, en un
 * fichero FINO (la función y sus tipos; ni ace ni el comando), con su propio
 * subpath en `exports`, y el módulo del comando ya NO la exporta (el comando
 * la importa de aquí). Un consumidor que la importaba de `./commands/…` cambia
 * la ruta y nada más (README «Upgrading to 2.5.0»).
 *
 * Vive en la raíz de `src/` (como `relations_config_store.ts`): la regla 2 de
 * pureza prohíbe que `src/relations/` tire del manager —ni con `import type`—,
 * y esta función recibe el manager (estructuralmente) para tomar la ventana
 * durable y resolver el driver activo.
 */
import type { RelationsReconcileOptions, RelationsReconcileReport } from './relations/reconcile.js'
import type { AuthorizationManager } from './manager.js'
import { AuthorizationConfigError, StaleSourceRefusedError } from './errors.js'

/**
 * **La ÚNICA vía pública para reconciliar relaciones** (L-1 · J1; cierre del
 * auditor de alpha.10 · R1/R4). `reconcileRelations` (`src/relations/`) es el
 * primitivo: no puede ver al manager de roles (regla 2 de pureza), así que no
 * sabe cuál es el driver ACTIVO ni puede tomar la ventana durable. Hasta el
 * cierre se exportaba desde la raíz del paquete y el README lo recomendaba para
 * K particiones: esa vía llegaba a la dirección rancia sin guard y sin freeze.
 * Ahora sale de la raíz y TODA migración de relaciones pasa por aquí —el
 * comando, un bucle por particiones de la plataforma—, que es el punto único
 * donde viven las dos garantías:
 *
 *  - **la dirección RANCIA** (alpha.10 · S1, gemelo de `manager.reconcile`):
 *    hacia el driver de relaciones activo (`relations.default ?? default`)
 *    ningún origen distinto pasa. **El origen y el destino se RESUELVEN aquí,
 *    por su clave, desde el config del manager** (R4): hasta el cierre la
 *    función recibía las instancias `from`/`to` y, aparte, las ETIQUETAS
 *    `toKey`/`fromKey`/`activeKey`, y juzgaba las etiquetas — un bucle con
 *    `fromKey === toKey` copiado y pegado, o un `activeKey` que contradecía al
 *    manager, escribía la compartición retirada en el activo. La identidad es
 *    la de la factory resuelta: dos claves con la MISMA factory son el mismo
 *    driver (un alias del activo también se niega);
 *  - **la ventana durable**: `--dry-run` **NO congela** (el verificador es
 *    read-only y está hecho para un cron); la pasada que ESCRIBE corre bajo
 *    `withFrozenWrites` con `kind: 'reconcile'` y la ventana del OPERADOR como
 *    contexto propio; un freeze vivo de OTRA pasada es 423; el reporte publica
 *    `frozen` —fence, lease, `window` y **`lapsed`**— y un lease perdido a
 *    mitad significa que la pasada NO se certifica (exit ≠ 0).
 *
 * Límite declarado (auditor · R5): el activo es el que dice el config del
 * PROCESO que ejecuta esto; un Job con otro entorno apaga el guard. El sello
 * durable del driver activo está en el roadmap (2.5).
 */
/**
 * **Las opciones PÚBLICAS de `runRelationsReconcile`** (cierre-2 de alpha.10 · C7):
 * las del primitivo sin `from`/`to` (instancias: retiradas) más las claves. Hasta el
 * cierre-2 la raíz exportaba `RelationsReconcileOptions` —la forma del primitivo, con
 * `from`/`to` obligatorios— y no esta.
 */
export type RunRelationsReconcileOptions = Omit<RelationsReconcileOptions, 'from' | 'to'> & {
  /** Clave (en `relations.drivers` del config del manager) del DESTINO. */
  toKey: string
  /** Clave del ORIGEN (el de `--from` o el elegido por descarte). */
  fromKey: string
  /** La salida humana de `E_AUTHZ_STALE_SOURCE_REFUSED`. */
  allowStaleSource?: boolean
}

/**
 * Límites DECLARADOS de la identidad (cierre-2 de alpha.10 · C1 y C6):
 *  - la identidad es la REFERENCIA de la factory: dos factories DISTINTAS que
 *    construyen el mismo backend (`fga: () => new OpenFgaRelationsDriver(…mismo
 *    store…)`) NO se detectan — el alias pasa el guard. No se construye nada antes
 *    del guard, así que no hay backend que comparar; identidad declarada por el
 *    driver ⇒ roadmap 2.5. Registra un alias con la MISMA referencia
 *    (`const fga = () => …; drivers: { openfga: fga, alias: fga }`) o no lo registres.
 *  - `authorization` es estructural (`Pick<…>`): un objeto que FALSEA
 *    `relationsDriverKey`/`relationsDriverFactory` decide el activo y las factories.
 *    Pásale el manager del servicio, nunca uno construido o envuelto a mano.
 */
export async function runRelationsReconcile(
  authorization: Pick<AuthorizationManager, 'withFrozenWrites' | 'relationsDriverKey' | 'relationsDriverFactory'>,
  options: RunRelationsReconcileOptions
): Promise<RelationsReconcileReport> {
  const { reconcileRelations } = await import('./relations/reconcile.js')
  const raw = options as Record<string, unknown>
  // Entradas que ya no gobiernan nada (L5: una opción inerte no cae en un
  // default en silencio). `from`/`to` como instancias y `activeKey` eran
  // justo las etiquetas desalineables del R4.
  const retiredOptions = ['from', 'to', 'activeKey'].filter((name) => raw[name] !== undefined)
  if (retiredOptions.length > 0) {
    throw new AuthorizationConfigError(
      `runRelationsReconcile: ${retiredOptions.map((n) => `\`${n}\``).join(', ')} ya no se acepta(n) (cierre de 2.4.0-alpha.10): ` +
        'el origen y el destino se resuelven por `fromKey`/`toKey` desde el config del manager, y el driver activo lo ' +
        'dice el manager (`relations.default ?? default`). Pasar instancias o un activo propio permitía que la etiqueta ' +
        'contradijera al driver y la dirección rancia pasara.'
    )
  }
  if (typeof options.toKey !== 'string' || typeof options.fromKey !== 'string') {
    throw new AuthorizationConfigError(
      'runRelationsReconcile: hacen falta `toKey` y `fromKey` (las claves de relations.drivers del destino y del ORIGEN) ' +
        'desde 2.4.0-alpha.10 — sin ellas no se puede negar la dirección rancia (re-escribir en el driver de relaciones ' +
        'ACTIVO lo que el origen dejó de ver en el cutover).'
    )
  }
  const { toKey, fromKey, allowStaleSource, ...rest } = options
  const toFactory = authorization.relationsDriverFactory(toKey)
  const fromFactory = authorization.relationsDriverFactory(fromKey)
  for (const [role, key, factory] of [['destino', toKey, toFactory], ['origen', fromKey, fromFactory]] as const) {
    if (typeof factory !== 'function') {
      throw new AuthorizationConfigError(
        `runRelationsReconcile: el ${role} '${key}' no es una clave de relations.drivers en el config del manager.`
      )
    }
  }
  const active = authorization.relationsDriverKey()
  /** Mismo driver ⇔ misma clave o misma factory resuelta (un alias es el mismo driver). */
  const sameDriver = (a: string, b: string) => a === b || authorization.relationsDriverFactory(a) === authorization.relationsDriverFactory(b)
  if (sameDriver(fromKey, toKey)) {
    throw new AuthorizationConfigError(
      `runRelationsReconcile: el origen '${fromKey}' y el destino '${toKey}' son el MISMO driver ` +
        `(${fromKey === toKey ? 'misma clave' : 'la misma factory bajo dos claves'}): no hay nada que migrar y un --prune ` +
        'se compararía consigo mismo. Nombra el otro driver.'
    )
  }
  const stale = sameDriver(toKey, active)
  const allowStale = allowStaleSource === true
  if (stale && !allowStale && options.dryRun !== true) {
    const alias = toKey === active ? '' : ` (la clave '${toKey}' resuelve la MISMA factory que el activo '${active}')`
    throw new StaleSourceRefusedError(
      `authz:relations:reconcile --to=${toKey} (origen '${fromKey}'): '${toKey}' es el driver de ` +
        `relaciones ACTIVO (relations.default ?? default)${alias} y el origen no lo es. Esa dirección re-escribiría en el driver ` +
        `activo tuplas que el origen ya no refleja: resucitaría las comparticiones retiradas desde el cutover (y con ` +
        `--prune borraría las creadas después). No se ha construido, leído, congelado ni escrito nada. Tras el cutover el driver ` +
        `activo ES la fuente de verdad de las relaciones: no hay nada que migrar hacia él; para volver atrás, migra en ` +
        `la otra dirección (--to=${fromKey} --from=${toKey}) ANTES de cambiar relations.default/default. ` +
        `Si de verdad el origen sigue siendo la fuente de verdad, la decisión humana es --allow-stale-source ` +
        `(allowStaleSource: true).`
    )
  }
  const from = await fromFactory!()
  const to = await toFactory!()
  const pass = () => reconcileRelations({ ...rest, from, to })
  const mark = (report: RelationsReconcileReport) => {
    if (stale) report.staleSource = { to: toKey, from: fromKey, allowed: allowStale }
    return report
  }
  if (options.dryRun === true) return mark(await pass())
  const reason = `authz:relations:reconcile --to=${toKey}`
  return authorization.withFrozenWrites(
    reason,
    async (window) => {
      const report = mark(await pass())
      report.frozen = {
        durable: true,
        lapsed: await window.lapsed(),
        leaseMs: window.leaseMs,
        fence: window.fence,
        ...(window.untilMs === undefined ? {} : { untilMs: window.untilMs }),
        ...(window.window === undefined ? {} : { window: window.window }),
      }
      return report
    },
    { kind: 'reconcile', operatorAsContext: true }
  )
}
