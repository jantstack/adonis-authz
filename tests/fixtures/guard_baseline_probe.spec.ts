/**
 * **Sonda de la línea base FILTRADA del corredor de mutantes** (cierre 6 de D2 · ⚪ D5-5). Solo registra casos con
 * `AUTHZ_GUARD_BASELINE_PROBE=1` (en `npm test` no registra nada): `B` depende del estado que deja `A`, así que es VERDE
 * en el spec entero y ROJO aislado — exactamente el «falso muerto» que la línea base filtrada tiene que cazar. Lo usa
 * `tests/guard_corridor.spec.ts` con `tests/fixtures/guard_baseline_probe.mutants.json`.
 */
import { test } from '@japa/runner'

if (process.env.AUTHZ_GUARD_BASELINE_PROBE === '1') {
  let primed = false
  test.group('sonda · línea base filtrada (D5-5)', () => {
    test('sonda · A deja el estado', () => {
      primed = true
    })
    test('sonda · B depende de A (verde en el spec entero, ROJO aislado)', ({ assert }) => {
      // probe:mutable
      assert.isTrue(primed)
    })
  })
}
