import type { ApplicationService } from '@adonisjs/core/types'
import { AuthorizationManager } from '../src/manager.js'
import { RelationsManager } from '../src/relations/manager.js'
import type { AuthorizationConfig } from '../src/define_config.js'

declare module '@adonisjs/core/types' {
  export interface ContainerBindings {
    'authz.manager': AuthorizationManager
    'authz.relations': RelationsManager
  }
}

/**
 * **Construye el `RelationsManager` de servicio desde el config** (Fase 4-8) —
 * el análogo de resolver el `AuthorizationManager` del provider, pero para el
 * puerto de relaciones. Función PURA (no toca el contenedor) para tener su caso
 * sin montar la app: recibe el config y devuelve el manager cableado.
 *
 * El driver ACTIVO sale de `relations.drivers[relations.default ?? default]`
 * (los drivers de relaciones se nombran igual que los de roles); la config, de
 * `relations.config` (la MISMA que capturan las factories de `drivers`, así que
 * la frontera F-05 del manager y la del driver son la misma). `requireActor` se
 * hereda del config de roles salvo que `relations.requireActor` lo anule para
 * este puerto (2.4.0-alpha.3 · D-5, el mismo patrón que
 * `requireTransactionalWrites`), y los hooks del puerto —`relations.assertWrite`
 * y `relations.onRelationWrite`, un solo home (D-4)— llegan al manager: hasta
 * alpha.3 no se pasaban y por `authz.relations` no había ni gate de policy ni
 * auditoría (hallazgo #1 de COGNITIV).
 *
 * Sin `relations.config` o sin el driver activo lanza con la receta: las
 * relaciones son OPT-IN y este servicio solo existe si el consumidor las
 * declaró.
 */
export async function buildRelationsManager(config: AuthorizationConfig): Promise<RelationsManager> {
  const relations = config.relations
  if (!relations?.config) {
    throw new Error(
      'No hay `relations.config` en config/authorization.ts: declara `relations: { config: ' +
        'defineRelationsConfig({...}), drivers: {...} }` para usar el servicio de relaciones ' +
        '(@jantstack/adonis-authz/services/relations).'
    )
  }
  const driverKey = relations.default ?? config.default
  const factory = relations.drivers?.[driverKey]
  if (!factory) {
    throw new Error(
      `No hay driver de relaciones '${driverKey}' en \`relations.drivers\` de config/authorization.ts ` +
        `(declara la factory bajo esa clave, o fija \`relations.default\`).`
    )
  }
  const driver = await factory()
  return new RelationsManager(driver, relations.config, {
    // alpha.3 · D-5: el flag de relaciones manda; si no está, el del raíz (`??`, no `||`: el `false` explícito anula).
    requireActor: relations.requireActor ?? config.requireActor,
    // alpha.3 · D-4: los hooks del puerto, desde su único home (`relations.*`); `?.` — sin default ruidoso.
    assertWrite: relations.assertWrite,
    onRelationWrite: relations.onRelationWrite,
    // R-15: el MISMO reloj que el motor de roles (`config.clock`, 2.5 · J1).
    clock: config.clock,
    // L-1 · J1: la MISMA barrera del freeze (y su deadline) que el motor de roles.
    freezeTimeoutMs: config.freezeTimeoutMs,
    // L-2 · puerta 2: el flag de relaciones manda; si no está, el del raíz.
    requireTransactionalWrites: relations.requireTransactionalWrites ?? config.requireTransactionalWrites,
    driverName: driverKey,
  })
}

/**
 * Registra los managers de autorización como singletons del contenedor,
 * construidos desde `config/authorization.ts` de la aplicación:
 *
 *  - `authz.manager`: el motor de roles (siempre).
 *  - `authz.relations`: el motor de ReBAC (solo si el consumidor declaró
 *    `relations.config`; si no, resolverlo lanza con la receta).
 */
export default class AuthzProvider {
  constructor(protected app: ApplicationService) {}

  register() {
    this.app.container.singleton('authz.manager', async () => {
      const config = this.app.config.get('authorization') as any
      if (!config) {
        throw new Error(
          'Falta config/authorization.ts — ejecuta: node ace configure @jantstack/adonis-authz'
        )
      }
      return new AuthorizationManager(config)
    })

    this.app.container.singleton('authz.relations', async () => {
      const config = this.app.config.get('authorization') as any
      if (!config) {
        throw new Error(
          'Falta config/authorization.ts — ejecuta: node ace configure @jantstack/adonis-authz'
        )
      }
      return buildRelationsManager(config)
    })
  }
}
