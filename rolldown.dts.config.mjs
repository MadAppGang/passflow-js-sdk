// Bundles the per-file declarations `tsc` emits into dist/.tsc into ONE self-contained
// declaration file, then writes it twice: index.d.ts (ESM, `import` condition) and
// index.d.cts (CJS, `require` condition). One file has no relative specifiers, so it
// resolves under node16/nodenext/bundler alike, and an identical .d.cts copy is safe.
import { readFileSync } from 'node:fs';
import { defineConfig } from 'rolldown';
import { dts } from 'rolldown-plugin-dts';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

export default defineConfig({
  input: { index: 'dist/.tsc/lib/index.d.ts' },
  external: [...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.peerDependencies ?? {})],
  plugins: [
    // `dtsInput`: bundle declarations tsc already wrote; the plugin never runs a compiler,
    // so it does not depend on which TypeScript (7.0 here) produced them.
    dts({ generator: 'oxc', dtsInput: true, emitDtsOnly: true, tsconfig: false, sourcemap: false }),
    {
      name: 'emit-dcts-twin',
      generateBundle(_options, bundle) {
        const chunk = bundle['index.d.ts'];
        if (!chunk || chunk.type !== 'chunk') this.error('expected an index.d.ts chunk');
        this.emitFile({ type: 'asset', fileName: 'index.d.cts', source: chunk.code });
      },
    },
  ],
  output: { dir: 'dist', format: 'es' },
});
