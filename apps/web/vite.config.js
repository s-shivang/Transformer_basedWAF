import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
export default defineConfig({
    plugins: [react()],
    resolve: {
        alias: {
            '@': path.resolve(__dirname, './src'),
        },
    },
    server: {
        host: true, // Listen on 0.0.0.0 for host and Docker container access
        port: 5173,
        strictPort: true,
        watch: {
            usePolling: true, // Essential for Windows and Docker volume mounts
            interval: 100,
        },
        hmr: {
            clientPort: 5173,
            overlay: true,
        },
    },
    build: {
        chunkSizeWarningLimit: 600,
        rollupOptions: {
            output: {
                manualChunks: {
                    'vendor-react': ['react', 'react-dom', 'react-router-dom'],
                    'vendor-query': ['@tanstack/react-query'],
                    'vendor-charts': ['recharts'],
                    'vendor-icons': ['lucide-react'],
                },
            },
        },
    },
    // @ts-expect-error Vitest configuration field
    test: {
        globals: true,
        environment: 'jsdom',
        setupFiles: './src/test/setup.ts',
        css: false,
    },
});
