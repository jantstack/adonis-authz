/**
 * **Las 41 formas de error del SDK 0.9.6 MEDIDAS en F0 · M-d** (lote «antes de RC» · R3), versionadas en
 * `tests/fixtures/fga_errors/*.json` (copia literal de `.claude/reproducciones/f0-md-fixtures/`, que está fuera de git):
 * procedencia `real` (`:8090`, OpenFGA v1.19.0) o `fake` (servidor HTTP local con el cuerpo del grpc-gateway, para
 * 401/403/408/429/5xx/4xx desconocidos y el error por ítem de deadline).
 *
 * `fgaErrorFromFixture` RECONSTRUYE la instancia con la clase REAL del SDK alimentando su constructor con una respuesta
 * de axios con el `status`, el cuerpo (`responseData`) y las cabeceras medidos — y `assertFixtureShape` comprueba que lo
 * reconstruido tiene la forma medida (`name`, `statusCode`, `apiErrorCode`, las 9 `instanceOf`). Así el clasificador se
 * juzga contra lo que el SDK produce de verdad, sin servidor, y no contra objetos inventados a mano (R3-1 del tester).
 */
import { readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import {
  FgaApiAuthenticationError,
  FgaApiError,
  FgaApiInternalError,
  FgaApiNotFoundError,
  FgaApiRateLimitExceededError,
  FgaApiValidationError,
  FgaError,
  FgaRequiredParamError,
  FgaValidationError,
} from '@openfga/sdk'
import type { FgaFailureKind } from '../../src/shared/backend_guard.js'

export const FGA_FIXTURES_DIR = fileURLToPath(new URL('../fixtures/fga_errors/', import.meta.url))

export interface FgaFixture {
  id: string
  outcome: string
  error?: {
    jsClass: string
    name: string
    instanceOf: Record<string, boolean>
    statusCode: number | null
    statusText: string | null
    apiErrorCode: string | null
    responseData: unknown
    responseHeaderSubset: Record<string, string> | null
    method: string | null
    requestURL: string | null
    message_informativo: string
  }
  response?: any
}

export function loadFgaFixtures(): FgaFixture[] {
  return readdirSync(FGA_FIXTURES_DIR)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => JSON.parse(readFileSync(FGA_FIXTURES_DIR + f, 'utf8')) as FgaFixture)
}

/** Las fixtures que LANZAN (una excepción del SDK). */
export function throwingFgaFixtures(): FgaFixture[] {
  return loadFgaFixtures().filter((f) => f.error !== undefined)
}

const API_CLASSES: Record<string, new (err: any) => Error> = {
  FgaApiError,
  FgaApiValidationError,
  FgaApiNotFoundError,
  FgaApiRateLimitExceededError,
  FgaApiInternalError,
  FgaApiAuthenticationError,
}

/**
 * La instancia del SDK de una fixture que lanza. `message` sustituye el mensaje medido (la propiedad «jamás por el
 * mensaje» lo envenena con el de OTRA clase) en los TRES sitios donde el SDK lo lleva (cierre de R3, 🟡-1 del tester):
 * `error.message`, `apiErrorMessage` y `responseData.message` — el cuerpo de la respuesta se envenena ANTES de construir,
 * así que es el propio SDK quien rellena `apiErrorMessage` con él.
 */
export function fgaErrorFromFixture(fixture: FgaFixture, message?: string): Error {
  const e = fixture.error
  if (!e) throw new Error(`la fixture ${fixture.id} no lanza`)
  const text = message ?? e.message_informativo
  if (e.jsClass === 'FgaError') return new FgaError({ message: text.replace(/^FGA Error: /, '') }, message)
  if (e.jsClass === 'FgaValidationError') return new FgaValidationError('authorizationModelId', text)
  if (e.jsClass === 'FgaRequiredParamError') return new (FgaRequiredParamError as any)('check', 'storeId', text)
  const Klass = API_CLASSES[e.jsClass]
  if (!Klass) throw new Error(`clase del SDK desconocida en ${fixture.id}: ${e.jsClass}`)
  const data =
    message !== undefined && e.responseData !== null && typeof e.responseData === 'object'
      ? { ...(e.responseData as Record<string, unknown>), message }
      : (e.responseData ?? undefined)
  const axiosLike = {
    message: text,
    response: {
      status: e.statusCode ?? undefined,
      statusText: e.statusText ?? undefined,
      data,
      headers: e.responseHeaderSubset ?? {},
    },
    config: { method: e.method ?? 'post', url: e.requestURL ?? '' },
    // La ruta da `endpointCategory` (el SDK la parte por «/»): la medida, no una fija (⚪-5 del tester).
    request: { path: `/stores/01ARZ3NDEKTSV4RRFFQ69G5FAV/${(e as any).endpointCategory ?? 'check'}` },
  }
  const error: any = new Klass(axiosLike)
  if (message !== undefined) {
    error.message = message
    // Un cuerpo que no es objeto (el HTML de un proxy) no lleva `message`: el SDK deja `apiErrorMessage` sin valor; se
    // envenena igual para que la propiedad lo cubra en las 37 formas.
    error.apiErrorMessage = message
  }
  return error
}

/** La forma reconstruida es la MEDIDA (o la fixture no juzga lo que dice juzgar). */
export function assertFixtureShape(assert: any, fixture: FgaFixture, error: any): void {
  const e = fixture.error!
  assert.equal(error.name, e.name, `${fixture.id}: name`)
  assert.equal(error.statusCode ?? null, e.statusCode, `${fixture.id}: statusCode`)
  assert.equal(error.apiErrorCode ?? null, e.apiErrorCode, `${fixture.id}: apiErrorCode`)
  // Cierre de R3 (⚪-5 del tester): también lo que el clasificador NO lee, para que una versión del SDK que añada `cause`
  // o `code` (o cambie las claves propias) no pase muda. Las dos fixtures medidas sin bloque de forma no lo traen.
  const measured = e as FgaFixture['error'] & { ownEnumerableKeys?: string[]; code?: unknown; cause?: unknown; endpointCategory?: string | null }
  if (measured.ownEnumerableKeys !== undefined) {
    assert.deepEqual(Object.keys(error).sort(), [...measured.ownEnumerableKeys].sort(), `${fixture.id}: claves propias`)
    assert.equal(error.code ?? null, measured.code ?? null, `${fixture.id}: code`)
    assert.equal(error.cause ?? null, measured.cause ?? null, `${fixture.id}: cause`)
    if (measured.endpointCategory !== undefined && measured.endpointCategory !== null) {
      assert.equal(error.endpointCategory, measured.endpointCategory, `${fixture.id}: endpointCategory`)
    }
  }
  const classes: Record<string, unknown> = {
    FgaError,
    FgaApiError,
    FgaApiValidationError,
    FgaApiNotFoundError,
    FgaApiRateLimitExceededError,
    FgaApiInternalError,
    FgaApiAuthenticationError,
    FgaValidationError,
    FgaRequiredParamError,
  }
  // Dos fixtures (`real-check-store-absent-no-model`, `real-write-store-absent`) se midieron sin el bloque `instanceOf`.
  for (const [name, expected] of Object.entries(e.instanceOf ?? {})) {
    assert.equal(error instanceof (classes[name] as any), expected, `${fixture.id}: instanceof ${name}`)
  }
}

/**
 * **La tabla de verdad de R3** (decisión del dueño 2026-10-17 (3) y (4), columna «clase» de F0 · M-d): fixture que lanza ⇒
 * clase. `net-connection-refused` es `timeout` por la regla conservadora (no se separa del timeout de axios sin leer el
 * mensaje; nota 1 de M-d); `fake-501-not-implemented` es `transient` por status (nota 4: la CLASE JS lo llevaría a 4xx).
 */
export const FGA_FIXTURE_CLASS: Record<string, FgaFailureKind> = {
  'fake-200-not-json-html-proxy': 'transient',
  'fake-400-unknown-code': 'unknown-4xx',
  'fake-401-unauthenticated': 'deployment',
  'fake-403-forbidden': 'deployment',
  'fake-404-store': 'deployment',
  'fake-408-timeout': 'transient',
  'fake-409-aborted': 'race',
  'fake-418-unknown-4xx': 'unknown-4xx',
  'fake-422-unknown': 'unknown-4xx',
  'fake-429-rate-limit': 'transient',
  'fake-500-internal': 'transient',
  'fake-501-not-implemented': 'transient',
  'fake-503-unavailable': 'transient',
  'fake-504-deadline-exceeded': 'transient',
  'fake-client-timeout-slow-server': 'timeout',
  'net-connection-refused': 'timeout',
  'real-batchcheck-model-absent': 'deployment',
  'real-check-context-absent-request': 'deployment',
  'real-check-context-absent-tuple': 'deployment',
  'real-check-context-empty-tuple': 'deployment',
  'real-check-model-absent': 'deployment',
  'real-check-model-malformed': 'deployment',
  'real-check-resolution-too-complex': 'resolution-limit',
  'real-check-store-absent': 'deployment',
  'real-check-store-absent-no-model': 'deployment',
  'real-check-validation-relation-absent': 'deployment',
  'real-check-validation-type-absent': 'deployment',
  'real-client-timeout': 'timeout',
  'real-delete-absent': 'race',
  'real-read-model-absent': 'deployment',
  'real-write-duplicate': 'race',
  'real-write-exceeded-entity-limit': 'deployment',
  'real-write-race-400_write_failed_due_to_invalid_input': 'race',
  'real-write-race-409_null': 'race',
  'real-write-relation-absent': 'deployment',
  'real-write-store-absent': 'deployment',
  'real-write-type-absent': 'deployment',
}

/** Clase de cada error POR ÍTEM de las dos fixtures de `batchCheck` (por `correlationId`). */
export const FGA_ITEM_CLASS: Record<string, Record<string, FgaFailureKind>> = {
  'fake-batchcheck-item-errors': { b: 'transient', c: 'resolution-limit', d: 'deployment', e: 'transient' },
  'real-batchcheck-mixed-items': { deep: 'resolution-limit', relabs: 'deployment', reqnoctx: 'deployment', tuplenoctx: 'deployment' },
}

/** Lo que ve el LLAMANTE y el relay por cada clase. */
export const FGA_PUBLIC_ERROR: Record<FgaFailureKind, { status: number; code: string; relayTransient: boolean }> = {
  'timeout': { status: 503, code: 'E_AUTHZ_BACKEND_TIMEOUT', relayTransient: true },
  'transient': { status: 503, code: 'E_AUTHZ_BACKEND_UNAVAILABLE', relayTransient: true },
  'resolution-limit': { status: 503, code: 'E_AUTHZ_RESOLUTION_LIMIT', relayTransient: true },
  'deployment': { status: 500, code: 'E_AUTHZ_CONFIG', relayTransient: true },
  // Cierre de R3 (🟠 R3-A1; decisión (3) «carrera ⇒ como hoy»): 409 para el llamante, TRANSITORIA para el relay.
  'race': { status: 409, code: 'E_AUTHZ_WRITE_CONFLICT', relayTransient: true },
  'unknown-4xx': { status: 500, code: 'E_AUTHZ_CONFIG', relayTransient: true },
}

/** Mensajes de OTRAS clases para envenenar el de cada fixture (la clase no puede moverse). */
export const POISONED_MESSAGES = [
  'FGA Error: timeout of 1ms exceeded',
  'context deadline exceeded',
  'resolution depth exceeded',
  'cannot write a tuple which already exists',
  'cannot delete a tuple which does not exist',
  'invalid relation: relation not found',
  'Request failed with status code 401',
  'connect ECONNREFUSED 127.0.0.1:9',
  '',
]
