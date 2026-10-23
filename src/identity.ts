import { InvalidIdentityError, InvalidSlugError } from './errors.js'
import { APP_SCOPE_TYPE } from './types.js'
import type { NormalizedRoleQuery, RoleQuery, ScopeRef, SnapshotReads, SubjectRef } from './types.js'

/**
 * Validación de identidad del motor: holder, scope, rol y permiso.
 *
 * Vive en un solo sitio y la aplican el manager (una vez por llamada) Y los
 * drivers (defensa en profundidad: el juez del contrato habla con el driver
 * directamente, y un driver de terceros puede usarse sin manager). Nadie
 * duplica la regla: se importa.
 *
 * Por qué es 422 y no "se acepta lo que venga":
 *  - `uuid: undefined` en el driver openfga escribía `user:undefined`, y a
 *    partir de ahí CUALQUIER holder sin uuid heredaba ese permiso (L0.5).
 *  - `{ type: 'app', uuid: 'X' }` colapsaba a la raíz global en openfga y no
 *    en database: escalada de tenant a plataforma en un driver y `false` en
 *    el otro (L0.10).
 *  - `#`, `:`, `|`, `~`, `*` y espacios son sintaxis de FGA o separadores de
 *    los ids de binding: un componente que los contenga puede fabricar un
 *    userset, un comodín o la clave de OTRO scope (L0.5, L0.8). Desde 3A
 *    (2.2) el slug ya NO viaja en los ids de FGA (van por uuid de catálogo),
 *    pero los tipos y uuids de scope sí, y los slugs serán relaciones del
 *    modelo `facts` (3b): la lista blanca se mantiene entera.
 *  - Las longitudes son las de las columnas `authz_*`: lo que no cabe se
 *    truncaría o fallaría con un error de SQL ilegible.
 */

/**
 * Longitudes de columna del esquema publicado (`stubs/migration.stub`) que
 * la identidad aplica tal cual. El slug NO está aquí: su límite es
 * `MAX_SLUG_LENGTH` (42), más estricto que la columna (100) para que el
 * catálogo sea publicable en FGA (E2).
 */
export const IDENTITY_LIMITS = Object.freeze({
  holderType: 50,
  scopeType: 20,
  uuid: 36,
})

/**
 * Centinela con el que el driver `database` almacena el uuid del scope `app`
 * (NOT NULL + unique). Fuera de `app` sería una identidad de scope que
 * colisiona con la raíz: se rechaza (L0.15).
 */
export const SENTINEL_UUID = '00000000-0000-0000-0000-000000000000'

/**
 * UUID del CATÁLOGO (rol o permiso): la columna `uuid` de `authz_roles` y
 * `authz_permissions` es `uuid` real, y desde 3A (2.2) es lo que viaja en
 * los ids de binding de FGA (`role_binding:<scopeKey>|<roleUuid>`). Se exige
 * canónico y en MINÚSCULAS (RFC 9562, 8-4-4-4-12 hex): PostgreSQL lo
 * normaliza así y MySQL/SQLite lo guardan tal cual, así que un uuid en
 * mayúsculas del spec produciría dos identidades para el mismo rol según el
 * motor, y un id de binding que el propio driver no leería de vuelta. Es más
 * estricto que la gramática de los uuids de holder/scope (esos son del
 * consumidor, `[a-z0-9._-]{1,36}`): un id 1.x con slug (`app|editor`) no
 * puede parecer un id 2.2 (`app|<uuid>`).
 */
const CATALOG_UUID_FORMAT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/** El uuid de un rol o permiso del catálogo (opcional en el spec): canónico y en minúsculas, o 422. */
export function assertCatalogUuid(kind: string, value: unknown): asserts value is string {
  if (typeof value !== 'string' || !CATALOG_UUID_FORMAT.test(value)) {
    throw new InvalidIdentityError(
      `UUID del ${kind} inválido: se esperaba un UUID canónico en minúsculas (8-4-4-4-12 hex) y llegó ${describe(value)}`
    )
  }
}

/** Versión booleana para caminos de LECTURA (ids que vienen del backend): no lanza. */
export function isCatalogUuid(value: unknown): value is string {
  return typeof value === 'string' && CATALOG_UUID_FORMAT.test(value)
}

/**
 * Un componente de identidad: MINÚSCULAS, dígitos, `_`, `.` y `-`. Lista
 * blanca y no negra: lo que no está aquí no se serializa a ningún backend.
 * Excluye por construcción `#`, `:`, `|`, `~`, `*`, `@`, espacios y control.
 *
 * Los TIPOS (de holder y de scope) van en minúsculas desde E4 (auditor H14):
 * en un motor SQL con collation `*_ci` `Users` y `users` serían la misma fila
 * y en FGA dos holders distintos. Los UUIDs también desde 2.5-B · K1
 * (auditor 🔴 1): el árbol del consumidor (tipo `uuid` de PG, `char(36)`
 * `*_ci` de MySQL) fundía `BBBB…` con `bbbb…`, la cadena resolvía con el
 * alias y el deny —escrito canónico en `authz_*`, `utf8mb4_bin`— no casaba.
 * La cadena canónica del resolutor cierra el alias por guiones; el alias por
 * mayúsculas muere aquí, en la puerta, antes de tocar nada. Un id en
 * mayúsculas del consumidor se pasa en minúsculas (`uuid.toLowerCase()`) en
 * su borde: un UUID es el mismo id en cualquier caja.
 */
const COMPONENT_FORMAT = /^[a-z0-9_.-]+$/
const TYPE_FORMAT = COMPONENT_FORMAT

function assertComponent(
  kind: string,
  value: unknown,
  maxLength: number,
  format: RegExp = COMPONENT_FORMAT
): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new InvalidIdentityError(
      `${kind} inválido: se esperaba una cadena no vacía y llegó ${describe(value)}`
    )
  }
  if (value.length > maxLength) {
    throw new InvalidIdentityError(
      `${kind} inválido: '${value}' supera los ${maxLength} caracteres de la columna`
    )
  }
  if (!format.test(value)) {
    throw new InvalidIdentityError(
      `${kind} inválido: '${value}'. Solo se admiten minúsculas, dígitos y . _ - ` +
        `(ni mayúsculas, '#', ':', '|', '~', '*', espacios ni caracteres de control)`
    )
  }
}

function describe(value: unknown): string {
  if (value === undefined) return 'undefined'
  if (value === null) return 'null'
  if (typeof value === 'string') return `'${value}'`
  return typeof value
}

/** `SubjectRef` bien formado: type y uuid presentes, con formato y longitud. */
export function assertSubject(subject: SubjectRef): void {
  if (!subject || typeof subject !== 'object') {
    throw new InvalidIdentityError(`Holder inválido: llegó ${describe(subject)}`)
  }
  assertComponent('Tipo de holder', subject.type, IDENTITY_LIMITS.holderType, TYPE_FORMAT)
  assertComponent(`UUID del holder '${subject.type}'`, subject.uuid, IDENTITY_LIMITS.uuid)
}

/**
 * `ScopeRef` bien formado. `app` es la raíz y NO admite uuid (L0.10): un
 * `{ app, 'X' }` no es "otro app", es una identidad que un driver colapsaría
 * a la global. Fuera de `app` el uuid es obligatorio y no puede ser el
 * centinela con el que `database` representa la raíz (L0.15).
 */
export function assertScope(scope: ScopeRef): void {
  if (!scope || typeof scope !== 'object') {
    throw new InvalidIdentityError(`Scope inválido: llegó ${describe(scope)}`)
  }
  assertComponent('Tipo de scope', scope.type, IDENTITY_LIMITS.scopeType, TYPE_FORMAT)
  if (scope.type === APP_SCOPE_TYPE) {
    if (scope.uuid !== null) {
      throw new InvalidIdentityError(
        `Scope inválido: el scope '${APP_SCOPE_TYPE}' es la raíz y no admite uuid ` +
          `(llegó ${describe(scope.uuid)}). Usa APP_SCOPE.`
      )
    }
    return
  }
  assertComponent(`UUID del scope '${scope.type}'`, scope.uuid, IDENTITY_LIMITS.uuid)
  if (scope.uuid === SENTINEL_UUID) {
    throw new InvalidIdentityError(
      `Scope inválido: '${SENTINEL_UUID}' está reservado para la raíz y no puede ` +
        `identificar un scope de tipo '${scope.type}'`
    )
  }
}

/** Tipo de scope suelto (el de `listRoleScopes`). */
export function assertScopeType(scopeType: string): void {
  assertComponent('Tipo de scope', scopeType, IDENTITY_LIMITS.scopeType, TYPE_FORMAT)
}

/**
 * Longitud máxima del id de un objeto/holder de RELACIÓN (columna
 * `varchar(64)` de `authz_relations`). Más ancha que `IDENTITY_LIMITS.uuid`
 * (36): el `object.id` de ReBAC lo elige el consumidor y no tiene por qué ser
 * un uuid.
 */
export const RELATION_ID_LIMIT = 64

/**
 * **La gramática del id de un objeto de RELACIÓN** (R-16, Fase 4 · lote 4-7).
 *
 * Un `object.id` de relaciones va en la columna `varchar(64)` de
 * `authz_relations` y, en el store compartido, en el id de objeto de FGA
 * (`document:<partitionKey>|<object.id>`). El driver `database` ya lo validaba
 * (`RELATION_ID_FORMAT`), pero ni el manager ni el driver `openfga` lo hacían:
 * el `openfga` solo medía la LONGITUD. Un `object.id` con un `|` dentro
 * (`'a|b'`) se ESCRIBÍA y `check` lo honraba, pero al parsear de vuelta (corte
 * por el ÚLTIMO `|`) la partición salía mal, así que `listObjects` lo filtraba
 * y `enumerateRelations` lo descartaba: una relación que concede y que NO se ve
 * en la enumeración ni migra —pérdida SILENCIOSA en `reconcile`, justo lo que
 * el driver promete que no pasa— y una divergencia con `database`, que lo
 * rechaza con 422. Y los caracteres estructurales (`:`/`#`/espacio) salían como
 * 503 mal clasificado, cuando por invariante 5 una entrada malformada es 422.
 *
 * Misma lista blanca que el resto de la identidad (`COMPONENT_FORMAT`):
 * minúsculas, dígitos y `._-`; excluye `|`, `#`, `:`, `@`, `*`, `~`, espacios y
 * control. La aplican el manager (una vez por llamada) Y cada driver (defensa
 * en profundidad), como el resto de la gramática.
 */
export function assertRelationId(kind: string, value: unknown): asserts value is string {
  assertComponent(kind, value, RELATION_ID_LIMIT)
}

/** Versión booleana para caminos de LECTURA (ids que vienen del backend): no lanza. */
export function isValidRelationId(value: unknown): value is string {
  try {
    assertRelationId('id de relación', value)
    return true
  } catch {
    return false
  }
}

/* ── Clave de scope ─────────────────────────────────────────────────────── */

/**
 * Clave textual de un scope: `app` para la raíz, `<tipo>|<uuid>` para el
 * resto (≤ 57 caracteres). Es la MISMA en todo el paquete: el id de los
 * bindings de FGA (`role_binding:<scopeKey>|<roleUuid>`) y el owner de un
 * rol local (`authz_roles.owner_scope_key`, 3B · B1). `|` es el separador:
 * como ningún componente lo admite (`assertScope`), dos scopes distintos no
 * pueden producir la misma clave, y la clave reservada `global` (el catálogo
 * del config) no la produce ningún scope — la raíz da `app` y todo lo demás
 * lleva `|`. Un scope mal formado (`{app, uuid}`, centinela, mayúsculas) es
 * 422 aquí, antes de serializarse a nada.
 */
export function scopeKey(scope: ScopeRef): string {
  assertScope(scope)
  if (scope.type === APP_SCOPE_TYPE) return APP_SCOPE_TYPE
  return `${scope.type}|${scope.uuid}`
}

/** Un uuid canónico escrito SIN guiones: 32 dígitos hexadecimales. */
const DASHLESS_UUID = /^[0-9a-f]{32}$/

/**
 * **Lo que el tipo `uuid` de PostgreSQL FUNDE de verdad**: 32 hex con, como
 * mucho, UN guion detrás de cada grupo de cuatro. Es la letra de la doc
 * (postgresql.org/docs/current/datatype-uuid.html, «PostgreSQL also accepts
 * the following alternative forms for input: […] omitting some or all
 * hyphens, adding a hyphen after any group of four digits») y está MEDIDO
 * contra PostgreSQL 18 (`select '<forma>'::uuid`, cierre-3 del lote A):
 * funde la canónica, `32 hex`, `8-4-4-16`, `8-8-8-8`, `12-4-4-12`, `8-24` y
 * `4×8` (39 caracteres); RECHAZA `-<32hex>`, `<32hex>-`, `a0e-ebc99…` (guion
 * tras tres) y `8--24` (dos guiones seguidos) con «invalid input syntax for
 * type uuid». Mayúsculas y llaves también las funde, pero no pasan
 * `assertScope` (minúsculas, `[a-z0-9._-]`).
 */
const PG_FUSED_UUID = /^([0-9a-f]{4}-?){7}[0-9a-f]{4}$/

/**
 * **Las formas que PostgreSQL funde con `uuid` — y solo esas** (cierre-3 del
 * lote A, decisión del dueño 2026-10-15 (3)): dado el uuid de un scope tal
 * como lo escribió el llamante, la ortografía CANÓNICA (8-4-4-4-12) con la
 * que un motor pudo fundirlo, o `[]` si no es alias de nada (ya es canónica,
 * o no es un uuid, o es una forma que ningún motor del README funde).
 *
 * Es la regla del FAN-OUT de roles (`scopeSpellings`: la purga sin cadena
 * de `scopes.detached`, `revoke`/`removeDeny`), y es a propósito MÁS
 * ESTRECHA que `isNonCanonicalUuid`, la del 422 de las particiones de
 * relaciones: son DOS propósitos. Rechazar de más (422 por `-<32hex>`) es
 * inocuo, el llamante lo ve y lo corrige; purgar de más NO lo es, porque la
 * canónica que se añade puede ser un scope VIVO de otro tenant en un
 * consumidor con ids de texto elegibles por el usuario (🟡 C2-1/C2-2 del
 * re-ataque al cierre-2: hasta el cierre-3 `scopeSpellings` usaba la ancha y
 * `a0e-<hex de la víctima>` arrastraba a la víctima a la purga). Expandir
 * una forma que ningún motor funde es coste sin beneficio: nunca hay hechos
 * canónicos que sean «suyos».
 *
 * **Formas de más de 36 caracteres** (⚪ C2-4): PG funde también `4×8`
 * (39 caracteres, el ejemplo literal de su doc), pero `IDENTITY_LIMITS.uuid`
 * es 36 —la columna publicada— y `assertScope` la rechaza ANTES de llegar
 * aquí con 422 `E_AUTHZ_INVALID_IDENTITY`: ruidoso y visible para el
 * consumidor, nunca una purga a medias en silencio. El conjunto de este
 * fan-out es, por tanto, «lo que PG funde Y cabe en 36».
 *
 * La inversa NO existe: dada la canónica no se enumeran sus alias (serían
 * 2^7 ortografías); el fan-out va siempre de alias ⇒ canónica.
 */
export function pgFusedSpellings(uuid: string): string[] {
  if (typeof uuid !== 'string' || !PG_FUSED_UUID.test(uuid) || CANONICAL_UUID.test(uuid)) return []
  return [dashedUuid(uuid.replace(/-/g, ''))]
}

/**
 * **Las ORTOGRAFÍAS de un scope con las que hay que limpiar cuando ya no hay
 * cadena con la que canonizar** (3b-2h · 🟠 3, auditor R2).
 *
 * La identidad de un scope es la canónica que devuelve el resolutor
 * (invariante 17) y el paquete la usa para TODOS los hechos… mientras la fila
 * del consumidor existe. `scopes.detached` es justo la operación que admite
 * que ya NO exista (3F · S1: se purga igual, con el scope tal cual), y ahí no
 * hay con qué canonizar: se usa la ortografía del llamante. Medido contra
 * PostgreSQL: el tipo `uuid` funde `01a0…-…` con el mismo uuid SIN guiones,
 * así que el `DELETE` del controlador acierta con el alias, el `detached`
 * llega con el alias, `purgeScope` demuestra cero sobre un objeto que no
 * existe y el scope REAL conserva su `parent` y su `binding`: en modo
 * `facts`, **concede para siempre**. En lectura el mismo alias es
 * fail-closed; en escritura era fail-OPEN.
 *
 * La salida es no elegir: una purga sin cadena limpia la ortografía del
 * llamante **y** la canónica de la que puede ser alias. **La regla de «¿de
 * qué canónica puede ser alias?» es `pgFusedSpellings`**: exactamente lo que
 * el tipo `uuid` de PostgreSQL funde (sin guiones, `8-4-4-16`, `8-8-8-8`,
 * `12-4-4-12`…, medido), ni una forma más. Hasta el cierre-2 del lote A solo
 * se expandía la forma SIN guiones y `8-4-4-16` dejaba la canónica viva
 * (🟠 R1); el cierre-2 pasó a `isNonCanonicalUuid`, que es MÁS ANCHA que lo
 * que PG funde (`-<32hex>`, `<32hex>-`, `a0e-ebc99…`, `--`: ids legales de
 * la gramática que PG rechaza), y eso ampliaba el alcance de una purga sin
 * cadena a scopes VIVOS ajenos (🟡 C2-1); el cierre-3 separa las dos reglas
 * por propósito. El alias por mayúsculas ya muere en la puerta
 * (`assertScope`). Así el consumidor que guarda sus uuids canónicos (el caso
 * normal) no paga NADA, y el que los guarda de otra forma sigue purgando su
 * clave y, además, la canónica. Normalizar en vez de expandir no vale: sin
 * la fila no se sabe cuál de las dos es la buena, y elegir mal deja los
 * hechos vivos, que es el fallo que se está cerrando.
 *
 * Esta función es PURA (no mira el árbol). Quien la consume es UN solo punto
 * de paso, `canonicalScopeTargets` (`backend_guard.ts`; lo usan
 * `scopes.detached` sin cadena en el manager y el fan-out de
 * `revoke`/`removeDeny` en los dos drivers, 3b-8 · A4), que además DESCARTA
 * toda ortografía que el resolutor reconozca como scope VIVO distinto del
 * pedido (cierre-3 · 🟡 C2-2/C2-3): nunca se purga un scope vivo que no es
 * el que se pidió.
 */
export function scopeSpellings(scope: ScopeRef): ScopeRef[] {
  assertScope(scope)
  const uuid = scope.uuid
  if (uuid === null) return [scope]
  return [scope, ...pgFusedSpellings(uuid).map((canonical) => ({ type: scope.type, uuid: canonical }))]
}

/** ¿Es un uuid canónico escrito SIN guiones (32 hex en minúsculas)? */
export function isDashlessUuid(value: unknown): value is string {
  return typeof value === 'string' && DASHLESS_UUID.test(value)
}

/** La forma 8-4-4-4-12 de un uuid de 32 hex (la ortografía CANÓNICA). */
export function dashedUuid(dashless: string): string {
  return `${dashless.slice(0, 8)}-${dashless.slice(8, 12)}-${dashless.slice(12, 16)}-${dashless.slice(16, 20)}-${dashless.slice(20)}`
}

/* ── Partición de RELACIONES (D4, plan 2.5 · lote A) ───────────────────── */

/** La ortografía CANÓNICA de un uuid: exactamente 8-4-4-4-12, minúsculas. */
const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/** ¿Es un uuid en su ortografía CANÓNICA (8-4-4-4-12, minúsculas)? (7.4: la forma del cursor de `enumerate*` de `database`.) */
export function isCanonicalUuid(value: unknown): value is string {
  return typeof value === 'string' && CANONICAL_UUID.test(value)
}

/**
 * **¿Es una ortografía NO canónica de un uuid?** (D4 + cierre 🟠 A2 del
 * auditor del lote A, decisión del dueño 2026-10-15): todo valor que, sin
 * guiones, sea 32 hex y NO esté exactamente en la forma 8-4-4-4-12. Cubre el
 * 32 hex sin guiones (lo único que D4 cerraba) Y cualquier otra colocación de
 * guiones —`8-4-4-16`, cuatro grupos, la canónica sin su último guion…—.
 *
 * **Es la regla ANCHA, y se usa SOLO para el 422 de las particiones de
 * relaciones** (`assertPartition`; cierre-3 del lote A, decisión del dueño
 * 2026-10-15 (3)): es un SUPERCONJUNTO de lo que el tipo `uuid` de
 * PostgreSQL funde —incluye `-<32hex>`, `<32hex>-`, `a0e-ebc99…` o `8--24`,
 * que PG rechaza con «invalid input syntax» (medido, PG 18)— y ahí ser más
 * ancha es inocuo: un 422 de más lo ve y lo corrige el llamante, y una
 * partición que «parece un uuid» sin serlo tampoco merece ser una clave
 * distinta de la canónica. Lo que PG funde DE VERDAD es `pgFusedSpellings`,
 * la regla del fan-out de ROLES, donde expandir de más sí cuesta (purgar un
 * scope vivo ajeno). Un valor que sin guiones no sea 32 hex (31, 33, un
 * carácter no hex, `_`/`.`) NO es un uuid y es un id legal.
 * Es la MISMA función que usa el detector de la receta del README, por
 * construcción (el `upgrade_recipe.spec` lo mide: lo que `assertPartition`
 * rechaza, el detector lo lista).
 */
export function isNonCanonicalUuid(value: unknown): value is string {
  if (typeof value !== 'string') return false
  return DASHLESS_UUID.test(value.replace(/-/g, '')) && !CANONICAL_UUID.test(value)
}

/**
 * **La partición de una relación se escribe en la forma CANÓNICA 8-4-4-4-12,
 * o es 422** (D4, decisión del dueño 2026-10-14; `panel-tenencia-2-juez.md`
 * §5; ampliado el 2026-10-15 a toda ortografía no canónica, 🟠 A2).
 * `assertScope` vale para un scope de ROLES porque ahí la identidad la
 * canoniza la cadena del resolutor (invariante 17) y, donde no hay cadena,
 * `scopeSpellings` barre la ortografía del llamante y la canónica de la que
 * puede ser alias, con SU regla (`pgFusedSpellings`, lo que PG funde de
 * verdad: cierre-3). En RELACIONES no hay cadena con
 * la que canonizar: la clave de partición es un string comparado byte a
 * byte, así que `unit|aaaa…` (32 hex) y `unit|aaaa-…` eran DOS particiones,
 * la purga canónica no veía la otra y, con el 422, las tuplas viejas sin
 * guiones quedaban inalcanzables para siempre (tester H5). Y la clase no era
 * solo «sin guiones»: PostgreSQL funde también `8-4-4-16`, cuatro grupos de
 * ocho, la canónica sin un guion… (🟠 A2) — cualquier colocación de guiones
 * sobre los mismos 32 hex —, así que la regla es «32 hex sin guiones y no
 * exactamente 8-4-4-4-12 ⇒ 422» (`isNonCanonicalUuid`). La regla es una sola
 * y va en un solo sitio: toda operación que recibe una partición —manager,
 * los dos drivers, el doble publicado y `reconcileRelations`— pasa por aquí
 * (o por `partitionKey`, que la llama), y la guardia de superficie
 * (`tests/guard_surface.spec.ts`, columna `partition`) lo sondea en cada
 * operación con las DOS formas (sin guiones y `8-4-4-16`). Las filas escritas
 * antes de 2.5.0 con una ortografía no canónica se detectan, se listan y se
 * BORRAN con la receta del README («Upgrading to 2.5.0», fail-closed por
 * defecto: eran concesiones invisibles a la purga canónica); re-clavarlas es
 * el paso opt-in `--rekey`. La ejecuta `tests/upgrade_recipe.spec.ts` en los
 * tres motores, con las dos ramas.
 *
 * Un id de partición que no sea un uuid sigue valiendo (`[a-z0-9._-]{1,36}`:
 * 32 caracteres no todos hex, 31 o 33 hex…). Los ids de OBJETO y de SUJETO
 * no se rechazan: se comparan byte a byte y el README lo declara.
 */
export function assertPartition(partition: ScopeRef): void {
  assertScope(partition)
  if (partition.uuid !== null && isNonCanonicalUuid(partition.uuid)) {
    const canonical = dashedUuid(partition.uuid.replace(/-/g, ''))
    throw new InvalidIdentityError(
      `Partición inválida: el uuid '${partition.uuid}' del scope '${partition.type}' no está en la forma canónica ` +
        `8-4-4-4-12 (${partition.uuid.includes('-') ? 'guiones mal colocados' : 'sin guiones, 32 hex'}). ` +
        `Las particiones de relaciones se comparan byte a byte y no se canonizan: escríbelo como '${canonical}'. ` +
        `Las tuplas escritas con una ortografía no canónica antes de 2.5.0 se detectan y se borran con la receta ` +
        `del README («Upgrading to 2.5.0»; re-clavarlas es el paso opt-in --rekey).`
    )
  }
}

/**
 * La clave de partición de una RELACIÓN: `scopeKey` con la regla de
 * `assertPartition` delante. Es lo que los dos drivers de relaciones (y el
 * doble) usan para componer `partition_key` / el id de objeto del store: no
 * hay camino hacia el backend que no pase por aquí.
 */
export function partitionKey(partition: ScopeRef): string {
  assertPartition(partition)
  return scopeKey(partition)
}

/**
 * La inversa de `scopeKey` para claves que vienen de la BASE (el owner de un
 * rol): `app` ⇒ la raíz; `<tipo>|<uuid>` ⇒ el scope; cualquier otra forma
 * (incluida `global`, que no es un scope) ⇒ `null`. No lanza: es camino de
 * lectura, y una clave que no es un scope simplemente no resuelve.
 */
export function scopeFromKey(key: string): ScopeRef | null {
  if (key === APP_SCOPE_TYPE) return { type: APP_SCOPE_TYPE, uuid: null }
  const parts = key.split('|')
  if (parts.length !== 2) return null
  const scope: ScopeRef = { type: parts[0], uuid: parts[1] }
  return isValidScope(scope) ? scope : null
}

/* ── Slugs del catálogo ─────────────────────────────────────────────────── */

/**
 * Gramática de un slug: minúsculas, dígitos y . _ - ; los permisos admiten UN
 * `:` (`recurso:accion`), los roles ninguno.
 */
const PERMISSION_FORMAT = /^[a-z0-9][a-z0-9_.-]*(:[a-z0-9][a-z0-9_.-]*)?$/
const ROLE_FORMAT = /^[a-z0-9][a-z0-9_.-]*$/

/**
 * Nombres que el modelo FGA del modo `facts` usa como relaciones propias
 * (`scope#parent`, `role_binding#assignee`, `scope#denied_<P>`…). Un
 * permiso llamado `parent` invalidaría el modelo entero (S14): se rechaza en
 * el núcleo, para ambos drivers, no el día de la migración.
 */
export const RESERVED_SLUGS: ReadonlySet<string> = new Set([
  'parent',
  'binding',
  'ancestor',
  'rooted',
  'role',
  'assignee',
  'denied',
])

/**
 * Familias de relaciones derivadas del modelo (`can_<P>`, `denied_<P>`,
 * `permits_<P>`). Un slug que EMPIECE por una de ellas colisiona con la
 * relación derivada de otro permiso y el generador la colapsaría en silencio
 * (S4: `can_docs_write` anulaba el deny de `docs:write`).
 */
export const RESERVED_SLUG_PREFIXES: readonly string[] = Object.freeze(['can_', 'denied_', 'permits_'])

/**
 * **Los TIPOS de objeto que el modelo `facts` (y el `group` de relaciones) YA
 * declaran** (Fase 4 · ⚪4). Un tipo de objeto de relaciones que se llame como
 * uno de estos DUPLICARÍA un tipo del store compartido: `role_binding` sobre
 * todo —si el driver de relaciones pudiera declararlo, podría componer el id
 * de un binding real y `relate` sería una escalada a `roles.authorize`—. Vive
 * en `identity.ts` (la gramática compartida) porque lo consumen DOS módulos
 * que la frontera de pureza mantiene disjuntos: el generador del modelo
 * (`src/drivers/openfga_facts.ts`, que no puede depender de `relations/`) y
 * `defineRelationsConfig` (`src/relations/`, que no puede depender de
 * `drivers/`). `deny_binding` sigue reservado aunque el modelo (c2r) ya no lo
 * emita: un catálogo migrado del modo `resolver` no puede resucitarlo.
 */
export const RESERVED_FACTS_TYPES: ReadonlySet<string> = Object.freeze(
  new Set(['scope', 'role', 'role_binding', 'deny_binding', 'group'])
) as ReadonlySet<string>

/**
 * Longitud máxima de un slug. Un nombre de relación en FGA admite 50
 * caracteres y el modelo deriva `permits_<slug>` (el prefijo más largo, 8):
 * 42 es lo que cabe con cualquier prefijo. Es más estricto que la columna
 * (100) a propósito: un catálogo legal en `database` tiene que ser publicable
 * en `openfga` (S13), o el cambio de driver no es una migración de hechos.
 */
export const MAX_SLUG_LENGTH = 50 - Math.max(...RESERVED_SLUG_PREFIXES.map((p) => p.length))

export type SlugKind = 'rol' | 'permiso'

/** Slug de rol o permiso válido para AMBOS drivers (formato, longitud, reservados). */
export function assertValidSlug(kind: SlugKind, slug: unknown): asserts slug is string {
  if (typeof slug !== 'string' || slug.length === 0) {
    throw new InvalidSlugError(
      `Slug de ${kind} inválido: se esperaba una cadena no vacía y llegó ${describe(slug)}`
    )
  }
  if (slug.length > MAX_SLUG_LENGTH) {
    // 3b-2a · A4: se nombra el prefijo que lo desborda y la relación que
    // saldría. La cota es del modo `facts`, y quien lee el error tiene que
    // saber por qué 42 y no 100 (que es lo que admite la columna).
    const longest = RESERVED_SLUG_PREFIXES.reduce((a, b) => (a.length >= b.length ? a : b))
    throw new InvalidSlugError(
      `Slug de ${kind} inválido: '${slug}' supera los ${MAX_SLUG_LENGTH} caracteres ` +
        `(50 de una relación FGA menos el prefijo derivado más largo, '${longest}': ` +
        `'${longest}${slug}' serían ${longest.length + slug.length})`
    )
  }
  const format = kind === 'permiso' ? PERMISSION_FORMAT : ROLE_FORMAT
  if (!format.test(slug)) {
    throw new InvalidSlugError(
      `Slug de ${kind} inválido: '${slug}'. Formato: minúsculas/dígitos/._-` +
        (kind === 'permiso' ? " con ':' único opcional (recurso:accion)" : ' (sin ":")') +
        "; '~', '|', '#', '*' y espacios están prohibidos"
    )
  }
  if (RESERVED_SLUGS.has(slug)) {
    throw new InvalidSlugError(
      `Slug de ${kind} inválido: '${slug}' es un nombre reservado del modelo ` +
        `(${[...RESERVED_SLUGS].join(', ')})`
    )
  }
  const family = RESERVED_SLUG_PREFIXES.find((prefix) => slug.startsWith(prefix))
  if (family) {
    throw new InvalidSlugError(
      `Slug de ${kind} inválido: '${slug}' empieza por '${family}', prefijo reservado ` +
        `de las relaciones derivadas (${RESERVED_SLUG_PREFIXES.join(', ')})`
    )
  }
}

/**
 * Cómo se proyecta un slug a un nombre de relación FGA (`:` → `_`). Dos slugs
 * distintos con la misma proyección (`docs:write` / `docs_write`) serían UNA
 * relación: el catálogo los rechaza juntos (L0.8a).
 */
export function slugAsRelation(slug: string): string {
  return slug.replaceAll(':', '_')
}

/** Ningún par de slugs del conjunto colisiona tras proyectarse a relación. */
export function assertNoSlugCollisions(kind: SlugKind, slugs: Iterable<string>): void {
  const seen = new Map<string, string>()
  for (const slug of slugs) {
    const relation = slugAsRelation(slug)
    const other = seen.get(relation)
    if (other !== undefined && other !== slug) {
      throw new InvalidSlugError(
        `Slugs de ${kind} en colisión: '${other}' y '${slug}' se proyectan a la misma ` +
          `relación '${relation}' (':' y '_' son equivalentes en el modelo)`
      )
    }
    seen.set(relation, slug)
  }
}

/** Versiones booleanas para caminos de LECTURA que no deben lanzar (ids que vienen del backend). */
export function isValidScope(scope: ScopeRef): boolean {
  try {
    assertScope(scope)
    return true
  } catch {
    return false
  }
}

export function isValidScopeType(scopeType: unknown): scopeType is string {
  try {
    assertScopeType(scopeType as string)
    return true
  } catch {
    return false
  }
}

export function isValidSlug(kind: SlugKind, slug: string): boolean {
  try {
    assertValidSlug(kind, slug)
    return true
  } catch {
    return false
  }
}

/**
 * La pregunta de `hasRole`, validada: string ⇒ `{ slug }`; objeto ⇒
 * `{ slug, scopeType }` (ambos con la gramática del motor).
 */
export function normalizeRoleQuery(role: RoleQuery): NormalizedRoleQuery {
  if (typeof role === 'string') {
    assertValidSlug('rol', role)
    return { slug: role }
  }
  if (!role || typeof role !== 'object') {
    throw new InvalidIdentityError(`Rol inválido: llegó ${describe(role)}`)
  }
  // 3D · M1(c): `{ uuid }` es la forma EXACTA (sin ambigüedad posible). No se
  // mezcla con `{ slug, scopeType }`: la pregunta es por identidad o por
  // nombre, nunca por las dos a la vez (un `{ uuid, slug }` que no casaran
  // sería una pregunta con dos respuestas).
  if ('uuid' in (role as object)) {
    const query = role as { uuid: unknown; slug?: unknown; scopeType?: unknown }
    if (query.slug !== undefined || query.scopeType !== undefined) {
      throw new InvalidIdentityError(
        `Rol inválido: { uuid } es la forma exacta y no se combina con 'slug'/'scopeType' (llegó ${describe(role)})`
      )
    }
    assertCatalogUuid('rol', query.uuid)
    return { uuid: query.uuid }
  }
  assertValidSlug('rol', (role as any).slug)
  assertScopeType((role as any).scopeType)
  return { slug: (role as any).slug, scopeType: (role as any).scopeType }
}

/**
 * Las claves de la cadena desde cada nivel hacia la raíz (3B · B2; movida
 * aquí en 3D · N5 para que exista UNA sola codificación de clave de scope):
 * `keysFrom[i]` = `chain.slice(i).map(scopeKey)`. Un rol es visible en el
 * nivel `i` si es global o su owner está en `keysFrom[i]` — el owner tiene
 * que ser ancestro-o-igual del scope de la ASIGNACIÓN, no de la pregunta.
 */
export function chainKeysFrom(chain: ScopeRef[]): string[][] {
  const keys = chain.map(scopeKey)
  return keys.map((_, i) => keys.slice(i))
}

/* ── Punto de entrada único ─────────────────────────────────────────────── */

/**
 * `expiresAt` de un `grant`, en sus tres estados legales: omitido, `null` o
 * una `Date` válida. Una cadena, un número o un `Invalid Date` no son una
 * caducidad: un driver lanzaba un TypeError al serializar y el otro persistía
 * basura (D7). Se rechaza como identidad mal formada (422).
 */
export function assertExpiresAt(value: unknown): asserts value is Date | null | undefined {
  if (value === undefined || value === null) return
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    throw new InvalidIdentityError(
      `expiresAt inválido: se esperaba una Date válida, null (sin caducidad) u omitido ` +
        `(preservar la vigente) y llegó ${value instanceof Date ? 'Invalid Date' : describe(value)}`
    )
  }
}

export interface IdentityParts {
  subject?: SubjectRef
  scope?: ScopeRef
  scopeType?: string
  /** Pregunta de `hasRole`: string u objeto `{ slug, scopeType }`. */
  role?: RoleQuery
  /**
   * Slug de rol donde el contrato pide un string (`grant`, `revoke`,
   * `listSubjects`): un `RoleQuery` objeto aquí es 422, no un 503 ni un
   * TypeError (D11).
   */
  roleSlug?: unknown
  permission?: string
  /** Caducidad de un `grant`: `undefined` | `null` | `Date` válida. */
  expiresAt?: unknown
}

/**
 * Valida en un solo paso los componentes que recibe una operación. Se llama
 * ANTES de tocar catálogo, árbol o backend: una pregunta mal formada no
 * cuesta una consulta ni deja rastro.
 */
export function assertIdentity(parts: IdentityParts): void {
  if ('subject' in parts) assertSubject(parts.subject as SubjectRef)
  if ('scope' in parts) assertScope(parts.scope as ScopeRef)
  if ('scopeType' in parts) assertScopeType(parts.scopeType as string)
  if ('role' in parts) normalizeRoleQuery(parts.role as RoleQuery)
  if ('roleSlug' in parts) assertValidSlug('rol', parts.roleSlug)
  if ('permission' in parts) assertValidSlug('permiso', parts.permission)
  if ('expiresAt' in parts) assertExpiresAt(parts.expiresAt)
}

/**
 * La forma de una pregunta a `readSnapshot` (rotación 2 · cierre 3): al menos una de las tres claves y ninguna más;
 * `rolesInChain` un array de scopes válidos, `listScopes` un slug de permiso, `listDenies` exactamente `true`. Lo
 * demás es 422 `E_AUTHZ_INVALID_IDENTITY` antes de tocar el backend. Devuelve la pregunta con las claves presentes.
 */
export function assertSnapshotReads(reads: unknown): SnapshotReads {
  if (reads === null || typeof reads !== 'object' || Array.isArray(reads)) {
    throw new InvalidIdentityError(
      `readSnapshot: se esperaba un objeto { rolesInChain?, listScopes?, listDenies? } y llegó ${Array.isArray(reads) ? 'un array' : typeof reads}`
    )
  }
  const known = new Set(['rolesInChain', 'listScopes', 'listDenies'])
  const present = Object.keys(reads).filter((key) => (reads as Record<string, unknown>)[key] !== undefined)
  const unknown = present.filter((key) => !known.has(key))
  if (unknown.length) throw new InvalidIdentityError(`readSnapshot: clave desconocida ${unknown.map((k) => `'${k}'`).join(', ')}`)
  if (present.length === 0) throw new InvalidIdentityError('readSnapshot: no se pidió ninguna lectura')
  const { rolesInChain, listScopes, listDenies } = reads as SnapshotReads
  if (rolesInChain !== undefined) {
    if (!Array.isArray(rolesInChain)) throw new InvalidIdentityError('readSnapshot: rolesInChain tiene que ser un array de scopes')
    for (const scope of rolesInChain) assertScope(scope)
  }
  if (listScopes !== undefined) assertIdentity({ permission: listScopes })
  if (listDenies !== undefined && listDenies !== true) throw new InvalidIdentityError('readSnapshot: listDenies solo admite true')
  return { rolesInChain, listScopes, listDenies }
}
