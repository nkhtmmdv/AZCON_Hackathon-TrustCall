import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig, loadEnv} from 'vite';

export default defineConfig(({mode}) => {
  const env = loadEnv(mode, '.', '');
  return {
    plugins: [react(), tailwindcss()],
    define: {
      'process.env.GEMINI_API_KEY': JSON.stringify(''),
      // SECURITY: GEMINI_API_KEY must NOT be bundled into client-side JS.
      // Use it only server-side. The empty string here prevents accidental leakage.
    },
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modifyâfile watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      watch: {
        // Prevent frontend full-page reloads when backend/data files change.
        ignored: ['**/server/**', '**/dist/**'],
      },
      proxy: {
        '/api': {
          target: `http://localhost:${process.env.API_PORT || 5175}`,
          changeOrigin: true,
        },
      },
    },
  };
});
