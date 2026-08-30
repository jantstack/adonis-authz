/**
 * Hook de resolución para `node:module.register`: hace que importar
 * `@openfga/sdk` lance. Simula un consumidor solo-database que NO instaló el
 * peer opcional (D9): nada de la ruta `database` puede tirar del SDK.
 */
export async function resolve(specifier, context, nextResolve) {
  if (specifier === '@openfga/sdk' || specifier.startsWith('@openfga/sdk/')) {
    const error = new Error(`Cannot find package '@openfga/sdk' (bloqueado por el test)`)
    error.code = 'ERR_MODULE_NOT_FOUND'
    throw error
  }
  return nextResolve(specifier, context)
}
