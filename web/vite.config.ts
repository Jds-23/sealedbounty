import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: './',
  // shared/ is linked from ../shared; use web's copies of its deps (one ethers in the bundle).
  resolve: { dedupe: ['ethers', 'tweetnacl'] },
  // ../fixtures: the tour imports fixtures/exploits/*.md?raw (bundled at build time).
  server: { fs: { allow: ['.', '../shared', '../fixtures'] } },
  test: { environment: 'node', server: { deps: { inline: ['@sealedbounty/shared'] } } },
});
