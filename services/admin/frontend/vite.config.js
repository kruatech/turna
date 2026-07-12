import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
// Build output goes to ../dist (services/admin/dist), which the Rust binary
// serves at runtime. In dev, /api is proxied to the turna-admin backend.
export default defineConfig({
    plugins: [react()],
    build: {
        outDir: '../dist',
        emptyOutDir: true,
    },
    server: {
        port: 5173,
        proxy: {
            '/api': { target: 'http://127.0.0.1:8080', changeOrigin: true },
        },
    },
});
