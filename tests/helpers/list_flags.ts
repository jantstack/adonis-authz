/**
 * Enumera por REFLEXIÓN (flags booteados del loader `commands/main.ts`, no el
 * fuente) las banderas de los diez comandos, para `scripts/check_flag_mutants.mjs`.
 * Una línea JSON: `[{ command, property, flag, kind }]`.
 *
 *   node --import @poppinss/ts-exec tests/helpers/list_flags.ts
 */
const loader: any = await import('../../commands/main.js')
const out: Array<{ command: string; property: string; flag: string; kind: string }> = []
for (const meta of await loader.getMetaData()) {
  const Command: any = await loader.getCommand(meta)
  Command.boot()
  for (const flag of Command.flags as Array<{ name: string; flagName: string; type: string }>) {
    out.push({ command: meta.commandName, property: flag.name, flag: `--${flag.flagName}`, kind: flag.type })
  }
}
console.log(JSON.stringify(out))
