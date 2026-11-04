import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Proxies /targets to the Express API so we don't need CORS in dev.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/targets': 'http://localhost:3001'
    }
  }
});
