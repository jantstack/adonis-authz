/**
 * EL reloj del motor (2.5 · J1). Es el ÚNICO sitio de `src/` donde se lee la
 * hora de pared (`new Date()`); lo vigila `tests/clock.spec.ts` con un grep
 * sobre las fuentes. Todo lo que decide con el tiempo —la caducidad en SQL
 * (`whereActive`), el `current_time` de cada check de FGA, el filtro de
 * caducidad en cliente de las enumeraciones y los tres estados de
 * `resolveGrantExpiry`— lo hace con un `now()` inyectable, por defecto este.
 *
 * Por qué: con `new Date()` suelto, la caducidad exacta, la renovación y
 * «expira ahora mismo» solo eran observables durmiendo (el juez esperaba
 * 1,5 s de reloj real). Con el reloj inyectado el juez fija el instante y
 * pregunta; y un consumidor puede congelarlo en sus propios tests.
 *
 * Lo que NO es: no es el reloj MONÓTONO de `forRequest({ maxAgeMs })` ni del
 * memo del catálogo (`everyMs`), que miden ventanas con `performance.now()`
 * y no deben moverse con NTP. Aquí se habla de instantes de pared, que es lo
 * que `expiresAt` significa.
 */
export type Clock = () => Date

/** Reloj de pared del proceso: el default de ambos drivers. */
export const systemClock: Clock = () => new Date()

/** `now` tiene que ser una función; se valida al construir (500 `E_AUTHZ_CONFIG` es del llamante). */
export function isClock(value: unknown): value is Clock {
  return typeof value === 'function'
}
