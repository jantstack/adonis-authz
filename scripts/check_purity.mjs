/**
 * Higiene del paquete: sus fuentes no pueden importar aliases de un proyecto
 * consumidor (`#config`, `#models`, `#services`, `#start`…). Todo lo del
 * dominio entra por config/inyección. Corre en cada build.
 */
import fs from 'node:fs'
import path from 'node:path'

const ROOTS = ['src', 'providers', 'services', 'commands', 'index.ts', 'configure.ts']
const FORBIDDEN = /from\s+'#[^']+'/g

function walk(target) {
  const stat = fs.existsSync(target) ? fs.statSync(target) : null
  if (!stat) return []
  if (stat.isFile()) return target.endsWith('.ts') ? [target] : []
  return fs.readdirSync(target).flatMap((entry) => walk(path.join(target, entry)))
}

const offenders = []
for (const root of ROOTS) {
  for (const file of walk(root)) {
    const matches = fs.readFileSync(file, 'utf-8').match(FORBIDDEN)
    if (matches) offenders.push(`${file} → ${[...new Set(matches)].join(', ')}`)
  }
}

if (offenders.length) {
  console.error('✖ El paquete importa aliases del consumidor:\n' + offenders.join('\n'))
  process.exit(1)
}
console.log('✔ purity: el paquete no depende de ningún proyecto consumidor')
