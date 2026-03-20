import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    proxy: {
      '/auth': 'http://127.0.0.1:8080',
      '/danmu': 'http://127.0.0.1:8080',
      '/api': 'http://127.0.0.1:8080',
      '/photos': 'http://127.0.0.1:8080',
      '/photos.json': 'http://127.0.0.1:8080',
    }
  },
  build: {
    outDir: '../docs',
    emptyOutDir: false,
  }
})
