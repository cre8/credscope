import { readFileSync } from 'node:fs'
import { defineConfig } from 'tsdown'

const { version } = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'))

// The command line tool, with every dependency bundled, so it runs with Node.js alone
export default defineConfig({
  entry: { credscope: 'src/cli.ts' },
  format: 'esm',
  platform: 'node',
  outDir: 'dist/cli',
  dts: false,
  sourcemap: true,
  define: { __INSPECTOR_VERSION__: JSON.stringify(version) },
  deps: { alwaysBundle: [/./], onlyBundle: false },
})
