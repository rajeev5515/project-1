import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// Built into web/dist, which the Node server serves. In dev, /api is proxied
// to the server on :3000 so cookies stay same-origin.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { outDir: 'dist', emptyOutDir: true, sourcemap: false, chunkSizeWarningLimit: 1500 },
  server: { proxy: { '/api': 'http://localhost:3000' } },
});
