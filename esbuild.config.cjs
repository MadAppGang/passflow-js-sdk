const { build } = require('esbuild');
const pkg = require('./package.json');

const external = Object.keys({
  ...pkg.dependencies,
  ...pkg.peerDependencies,
});

const commonConfig = {
  entryPoints: ['./lib/index.ts'],
  outdir: 'dist',
  target: 'es2020',
  bundle: true,
  tsconfig: 'tsconfig.json',
  external: [...external],
  sourcemap: true,
};

Promise.all([
  build({
    ...commonConfig,
    format: 'cjs',
    minify: true,
  }),
  build({
    ...commonConfig,
    format: 'esm',
    outExtension: {
      '.js': '.mjs',
    },
    minify: true,
  }),
]).catch(() => process.exit(1));
