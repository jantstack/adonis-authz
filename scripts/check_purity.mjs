/**
 * Higiene del paquete. Tres reglas, todas ejecutables en cada `npm test` y en
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
 * 3. **`@openfga/sdk` es peer opcional**: solo `src/openfga.ts` (la entrada
 *    del subpath `/openfga`), `src/drivers/openfga_driver.ts` y los comandos
 *    `commands/openfga_*.ts` pueden importar el SDK o el driver. Todo lo
 *    demás es la ruta de un consumidor solo-database (`index.ts`, el
 *    manager, `database_driver`, `catalog`, `define_config`, providers,
 *    services…) y no puede tirar de él ni con `import type`: la regla se
 *    aplica al especificador, no a lo que se importa (D9).
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

/** Regla 3: los únicos archivos que pueden importar `@openfga/sdk` o el driver openfga. */
const OPENFGA_ALLOWED_FILES = [/^src\/openfga$/, /^src\/drivers\/openfga_driver$/, /^commands\/openfga_[^/]+$/]
/** Regla 3: destinos que delatan la ruta openfga (relativos, sin extensión). */
const OPENFGA_TARGETS = [/^src\/openfga$/, /^src\/drivers\/openfga_driver$/]
const OPENFGA_SDK = /^@openfga\/sdk(\/|$)/

/**
 * Cualquier forma de traer un módulo: `import x from '…'`, `import '…'`
 * (efecto lateral), `export … from '…'`, `import('…')` dinámico y
 * `require('…')`, con comillas simples, dobles o backticks (un
 * `import(\`#config/${x}\`)` también es un import). Captura el especificador.
 */
const IMPORT_SPECIFIER = /(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*|^\s*import\s+)(['"`])([^'"`]+)\1/gm

/**
 * Quita comentarios `//` y `/* *\/` respetando strings, template literals y
 * regex literales. Un `#config` mencionado en un comentario (una explicación,
 * un ejemplo de cómo NO hacerlo) no es una importación y no debe fallar el
 * build; un `import` real detrás de un `//` en la misma línea que una URL
 * tampoco debe esconderse. No es un parser: es un autómata de seis estados
 * que basta para las fuentes de este paquete y se prueba en
 * `tests/purity.spec.ts` en los dos sentidos.
 */
export function stripComments(source) {
  let out = ''
  let i = 0
  const n = source.length
  // Un `/` empieza una regex cuando lo que le precede no puede ser un operando.
  const REGEX_PRECEDERS = new Set(['(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '%', '<', '>', '~', '^'])
  const lastCode = () => {
    for (let j = out.length - 1; j >= 0; j--) if (!/\s/.test(out[j])) return out[j]
    return ''
  }
  while (i < n) {
    const ch = source[i]
    const next = source[i + 1]
    if (ch === '/' && next === '/') {
      while (i < n && source[i] !== '\n') i++
      continue
    }
    if (ch === '/' && next === '*') {
      const end = source.indexOf('*/', i + 2)
      // Se conservan los saltos de línea para que los números de línea no bailen.
      const body = end === -1 ? source.slice(i) : source.slice(i, end + 2)
      out += body.replace(/[^\n]/g, '')
      i = end === -1 ? n : end + 2
      continue
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      const quote = ch
      out += ch
      i++
      while (i < n && source[i] !== quote) {
        if (source[i] === '\\') {
          out += source[i] + (source[i + 1] ?? '')
          i += 2
          continue
        }
        out += source[i]
        i++
      }
      out += source[i] ?? ''
      i++
      continue
    }
    if (ch === '/' && (lastCode() === '' || REGEX_PRECEDERS.has(lastCode()) || /\breturn$/.test(out.trimEnd()))) {
      out += ch
      i++
      let inClass = false
      while (i < n && source[i] !== '\n') {
        const c = source[i]
        if (c === '\\') {
          out += c + (source[i + 1] ?? '')
          i += 2
          continue
        }
        out += c
        i++
        if (c === '[') inClass = true
        else if (c === ']') inClass = false
        else if (c === '/' && !inClass) break
      }
      continue
    }
    out += ch
    i++
  }
  return out
}

function specifiers(source) {
  return [...stripComments(source).matchAll(IMPORT_SPECIFIER)].map((m) => m[2])
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

  // Regla 3: la ruta database no importa openfga.
  for (const entry of ROOTS) {
    for (const file of walk(path.join(root, entry))) {
      const relative = path.relative(root, file).replace(/\.(ts|js|mts|mjs)$/, '')
      if (OPENFGA_ALLOWED_FILES.some((pattern) => pattern.test(relative))) continue
      const hits = []
      for (const specifier of specifiers(fs.readFileSync(file, 'utf-8'))) {
        if (OPENFGA_SDK.test(specifier)) {
          hits.push(specifier)
          continue
        }
        if (!specifier.startsWith('.')) continue
        const resolved = path
          .relative(root, path.resolve(path.dirname(file), specifier))
          .replace(/\.(ts|js|mts|mjs)$/, '')
        if (OPENFGA_TARGETS.some((pattern) => pattern.test(resolved))) hits.push(resolved)
      }
      if (hits.length) {
        offenders.push(
          `${path.relative(root, file)} → importa la ruta openfga (${[...new Set(hits)].join(', ')}); ` +
            `@openfga/sdk es peer opcional y solo entra por src/openfga.ts, el driver y commands/openfga_*`
        )
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
  console.log('✔ purity: el paquete no depende de ningún proyecto consumidor, no acopla módulos y la ruta database no importa openfga')
}
