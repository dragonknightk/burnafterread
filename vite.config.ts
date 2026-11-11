import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Served by the Worker under https://<host>/moho (see worker/index.ts BASE)
// https://vite.dev/config/
export default defineConfig({
  base: '/moho/',
  plugins: [react()],
  build: {
    outDir: 'dist/client',
    emptyOutDir: true,
  },
})
