import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 开发态把 /api 代理到 Go 后端；生产构建产物由 Go 直接静态托管。
export default defineConfig({
  plugins: [vue()],
  base: '/',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 1500
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8848',
        changeOrigin: true
      }
    }
  }
})
