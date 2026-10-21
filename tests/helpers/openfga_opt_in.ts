/**
 * **La marca del opt-in EXPERIMENTAL de `openfga` para las fixtures** (estrategia 2.5.0, firma 4 del dueño 2026-10-21).
 * En 2.5.x los dos drivers `openfga` no se construyen sin `experimental: 'openfga@2.5'` (500 `E_AUTHZ_CONFIG`, primera
 * línea del constructor). Toda fixture que construye un driver `openfga` la lleva de AQUÍ —un solo sitio, como
 * `TEST_MODEL_ID`—, esparcida al PRINCIPIO de las opciones (`{ ...OPENFGA_OPT_IN, … }`) para que un caso que quiera
 * juzgar la puerta pueda pisarla después. Es el LITERAL, no la constante del paquete: si el token cambia en `src/`, las
 * fixtures se ponen rojas a propósito (el cambio de token es una ruptura que se decide, no un refactor).
 */
export const OPENFGA_OPT_IN = { experimental: 'openfga@2.5' } as const
