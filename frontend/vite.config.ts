import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    // Loopback only, matching the API's own gate: there is no authentication yet, and a dev
    // server bound to every interface is the same mistake one layer up (ADR-0016).
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      // P21 wires the real calls; the proxy exists now so the app and the API share an
      // origin from the start and nobody reaches for CORS as a workaround.
      '/api': { target: 'http://127.0.0.1:8000', changeOrigin: false },
    },
  },
});
