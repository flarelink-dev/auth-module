// Bundle auth-module/worker.ts into a single ESM file for Workers upload.
// Run via `npm run build:auth-module`. The output lives at dist/worker.mjs
// and is what the deploy flow uploads via the CF Scripts API.

import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

await build({
  entryPoints: [join(here, 'worker.ts')],
  outfile: join(here, 'dist', 'worker.mjs'),
  bundle: true,
  format: 'esm',
  // Workers runtime is V8 + Web APIs, not Node. The workerd condition
  // picks up Workers-tuned exports in better-auth / drizzle.
  platform: 'browser',
  target: 'es2022',
  conditions: ['workerd', 'worker', 'browser'],
  external: ['cloudflare:*'],
  legalComments: 'none',
  minify: true,
  metafile: true,
}).then((result) => {
  const bytes = Object.values(result.metafile.outputs)[0]?.bytes ?? 0;
  console.log(`auth-module bundled → dist/worker.mjs (${(bytes / 1024).toFixed(1)} KB)`);
});
