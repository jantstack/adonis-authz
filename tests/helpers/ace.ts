/**
 * **Un kernel de ace de verdad, en proceso** (2.4.0-alpha.4; panel alpha.4,
 * tester §1.1). Hasta alpha.3 ningún caso ejecutaba un comando del paquete
 * por el kernel: los nueve se juzgaban por sus funciones puras con el config
 * a mano, y así se publicó un `openfga:provision` que reventaba en su primera
 * línea (`this.app.config` no existe con `startApp: false`) y un barrel de
 * comandos que ni siquiera era un loader de ace. Este harness cierra ese
 * punto ciego con dos reglas que NO son de gusto, están medidas:
 *
 * 1. **`AppFactory`, JAMÁS `IgnitorFactory`/`AceFactory`.** `Ignitor.createApp()`
 *    llama a `setApp()` y REEMPLAZA el servicio global `@adonisjs/core/services/app`,
 *    del que cuelgan `services/main.ts` y `@adonisjs/lucid/services/db` (los dos
 *    hacen `await app.booted(...)` sobre el global al importarse): una app
 *    fixture creada con el ignitor dentro de la suite se lleva por delante la
 *    app de `bootApp()`. `AppFactory` no llama a `setApp` (medido: la app
 *    global sigue siendo la de la suite tras cada `exec`).
 *
 * 2. **`kernel.exec` NO relanza.** `BaseCommand.exec` guarda `this.error` y
 *    relanza; el `#exec` del kernel lo captura y se lo entrega al
 *    `errorHandler`. Por eso la aserción va SIEMPRE sobre `cmd.error` /
 *    `exitCode`, nunca sobre `assert.rejects`: un caso escrito con
 *    `assert.rejects` pasaría en verde sin probar nada.
 *    **Excepción medida** (2.4.0-alpha.10, tester del panel de metodología):
 *    lo que ace rechaza al PARSEAR, antes de `run()` —una bandera con valor
 *    vacío, `--partition-uuid=` ⇒ «Missing value for option»—, **SÍ relanza**
 *    desde `kernel.exec`. Para ese caso, captura (`try/catch` o
 *    `assert.rejects`) en vez de mirar `cmd.error`.
 *
 * El hook `loading` copia la regla de arranque del ignitor real
 * (`@adonisjs/core`, `AceProcess.handle`): la app SOLO bootea si el comando
 * declara `startApp`. Copiar esa condición es el punto — si el harness
 * booteara siempre, el caso 1 de `openfga:provision` no probaría nada.
 */
import { AppFactory } from '@adonisjs/core/factories/app'
import { Kernel, ListLoader } from '@adonisjs/core/ace'
import http from 'node:http'

const REPO = new URL('../../', import.meta.url)

export interface AceRun {
  /** La instancia del comando (o `undefined` si el kernel no lo encontró). */
  cmd: any
  /** El error que el comando guardó (el kernel NO relanza). */
  error: any
  exitCode: number | undefined
  /** Los mensajes del logger, en modo `raw` (para afirmar la LETRA). */
  logs: string[]
}

export interface AceHarness {
  app: any
  kernel: any
  exec(argv?: string[]): Promise<AceRun>
}

export interface AceOptions {
  /** Lo que `config/authorization.ts` diría; `undefined` = sin esa clave. */
  authorization?: unknown
  /** Otras claves del config (p. ej. `app`). */
  config?: Record<string, unknown>
  /** Providers del consumidor, como los declararía `adonisrc.ts`. */
  providers?: Array<() => Promise<{ default: any }>>
}

/**
 * Un kernel con UN comando registrado por `ListLoader`, sobre una app
 * `initiated` (el estado en el que el ignitor de ace deja la app antes de
 * mirar `startApp`).
 */
export async function aceFor(Command: any, options: AceOptions = {}): Promise<AceHarness> {
  const app: any = new AppFactory().create(REPO, (id: string) => import(id))
  if (options.providers) {
    // Una función suelta es la forma corta del `adonisrc.ts` (`providers: [() => import(...)]`).
    app.rcContents({ providers: options.providers })
  }
  app.useConfig({ ...(options.config ?? {}), ...(options.authorization !== undefined ? { authorization: options.authorization } : {}) })
  await app.init()
  const kernel: any = new Kernel(app)
  kernel.loading(async (metaData: any) => {
    if (metaData.options.startApp && !app.isReady) {
      await app.boot()
      await app.start(() => {})
    }
  })
  kernel.addLoader(new ListLoader([Command]))
  kernel.ui.switchMode('raw')
  kernel.errorHandler = { async render() {} }
  return {
    app,
    kernel,
    async exec(argv: string[] = []) {
      const cmd = await kernel.exec(Command.commandName, argv)
      return {
        cmd,
        error: cmd?.error,
        exitCode: cmd?.exitCode,
        logs: kernel.ui.logger.getLogs().map((line: any) => String(line.message)),
      }
    },
  }
}

export interface FgaStub {
  url: string
  /** Cada request recibida, en orden. */
  seen: Array<{ method: string; url: string; body: string }>
  close(): Promise<void>
}

/**
 * Un servidor HTTP MUDO que anota cada request y responde 400 (el SDK de FGA
 * no reintenta un 4xx): lo que convierte «no explotó» en «llegó a la red con
 * ESTE config». 14× más rápido que un puerto muerto (133 ms frente a ~2 s de
 * ECONNREFUSED con los reintentos de axios), medido por el tester.
 */
export async function fgaStub(): Promise<FgaStub> {
  const seen: FgaStub['seen'] = []
  const server = http.createServer((req, res) => {
    let body = ''
    req.on('data', (chunk) => (body += chunk))
    req.on('end', () => {
      seen.push({ method: req.method!, url: req.url!, body })
      res.statusCode = 400
      res.setHeader('content-type', 'application/json')
      res.end(JSON.stringify({ code: 'validation_error', message: 'stub: aquí no hay un OpenFGA de verdad' }))
    })
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address() as any
  return {
    url: `http://127.0.0.1:${port}`,
    seen,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  }
}
