/**
 * Higiene del paquete. Dos reglas, las dos ejecutables en cada `npm test` y en
 * cada build:
 *
 * 1. **Pureza frente al consumidor**: las fuentes del paquete no pueden importar
 *    aliases de un proyecto anfitrión (`#config`, `#models`, `#services`,
 *    `#start`…). Todo lo del dominio entra por config o inyección.
 *
 * 2. **Grafo de módulos**: ningún archivo bajo `src/<modulo>/` importa
 *    `src/manager.ts` ni `src/drivers/*`. Un módulo opt-in (`catalog/`,
 *    `relations/`… Fases 3-4) compone sobre el PUERTO (`src/types.ts`), los
 *    errores y las utilidades de `src/shared/`; si tira del manager o de un
 *    driver concreto deja de ser opcional y arrastra al driver al bundle del
 *    consumidor. Hoy la lista de módulos está vacía: la regla existe para que
 *    el primer módulo nazca ya vigilado (y `tests/purity.spec.ts` demuestra con
 *    un fixture que la detecta).
 *
 * Se puede apuntar a otra raíz (`--root <dir>`) y declarar módulos extra
 * (`--module <nombre>`, repetible): así el test lo ejercita sobre un fixture
 * sin meter una violación en el repo.
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOTS = ['src', 'providers', 'services', 'commands', 'index.ts', 'configure.ts']

/**
 * Módulos opt-in conocidos: la regla 2 vigila los que EXISTAN bajo `src/`.
 * Hoy ninguno existe; el día que nazca `src/catalog/` queda vigilado sin
 * tocar este script.
 */
const KNOWN_MODULES = ['catalog', 'relations', 'http']

/** Destinos que un módulo NO puede importar (rutas relativas a la raíz, sin extensión). */
const MODULE_FORBIDDEN_TARGETS = [/^src\/manager$/, /^src\/drivers(\/|$)/]

/**
 * Cualquier forma de traer un módulo: `import x from '…'`, `import '…'`
 * (efecto lateral), `export … from '…'`, `import('…')` dinámico y
 * `require('…')`, con comillas simples o dobles. Captura el especificador.
 */
const IMPORT_SPECIFIER = /(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*|^\s*import\s+)(['"])([^'"]+)\1/gm

function specifiers(source) {
  return [...source.matchAll(IMPORT_SPECIFIER)].map((m) => m[2])
}

function modulesIn(root) {
  return KNOWN_MODULES.filter((name) => fs.existsSync(path.join(root, 'src', name)))
}

function walk(target) {
  const stat = fs.existsSync(target) ? fs.statSync(target) : null
  if (!stat) return []
  if (stat.isFile()) return target.endsWith('.ts') ? [target] : []
  return fs.readdirSync(target).flatMap((entry) => walk(path.join(target, entry)))
}

/**
 * Devuelve las violaciones encontradas bajo `root` (vacío = limpio). Es una
 * función pura sobre el sistema de archivos para que el test la ejercite
 * sobre un directorio temporal.
 */
export function checkPurity({ root = process.cwd(), modules = [] } = {}) {
  const offenders = []

  // Regla 1: aliases del consumidor.
  for (const entry of ROOTS) {
    for (const file of walk(path.join(root, entry))) {
      const aliases = specifiers(fs.readFileSync(file, 'utf-8')).filter((s) => s.startsWith('#'))
      if (aliases.length) {
        offenders.push(
          `${path.relative(root, file)} → importa aliases del consumidor: ${[...new Set(aliases)].join(', ')}`
        )
      }
    }
  }

  // Regla 2: grafo de módulos.
  for (const moduleName of new Set([...modulesIn(root), ...modules])) {
    for (const file of walk(path.join(root, 'src', moduleName))) {
      for (const specifier of specifiers(fs.readFileSync(file, 'utf-8'))) {
        if (!specifier.startsWith('.')) continue
        // `../manager` ≡ `../manager.js` ≡ `../manager.ts`: se compara sin extensión.
        const resolved = path
          .relative(root, path.resolve(path.dirname(file), specifier))
          .replace(/\.(ts|js|mts|mjs)$/, '')
        if (MODULE_FORBIDDEN_TARGETS.some((pattern) => pattern.test(resolved))) {
          offenders.push(
            `${path.relative(root, file)} → el módulo '${moduleName}' importa '${resolved}' (solo puede depender del puerto, errores y src/shared/)`
          )
        }
      }
    }
  }

  return offenders
}

function parseArgs(argv) {
  const options = { root: process.cwd(), modules: [] }
  const takeValue = (i, flag) => {
    const value = argv[i + 1]
    if (value === undefined || value.startsWith('--')) throw new Error(`${flag} necesita un valor`)
    return value
  }
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--root') options.root = path.resolve(takeValue(i++, '--root'))
    else if (argv[i] === '--module') options.modules.push(takeValue(i++, '--module'))
    else throw new Error(`Argumento desconocido: ${argv[i]}`)
  }
  return options
}

// realpath en ambos lados: un symlink en la ruta (nvm, npm link) no debe
// convertir la invocación directa en una importación muda.
const invokedDirectly =
  process.argv[1] &&
  fs.existsSync(process.argv[1]) &&
  fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))

if (invokedDirectly) {
  let options
  try {
    options = parseArgs(process.argv.slice(2))
  } catch (error) {
    console.error(`✖ purity: ${error.message}`)
    process.exit(2)
  }
  const offenders = checkPurity(options)
  if (offenders.length) {
    console.error('✖ purity:\n' + offenders.join('\n'))
    process.exit(1)
  }
  console.log('✔ purity: el paquete no depende de ningún proyecto consumidor ni acopla módulos')
}
