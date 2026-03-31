import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      // Proxy all backend API calls to the FastAPI server on port 8000.
      // This avoids CORS issues entirely during development.
      '/health':          { target: 'http://localhost:8000', changeOrigin: true },
      '/pipeline':        { target: 'http://localhost:8000', changeOrigin: true },
      '/ingest_file':     { target: 'http://localhost:8000', changeOrigin: true },
      '/ingest_json':     { target: 'http://localhost:8000', changeOrigin: true },
    },
  },
})
