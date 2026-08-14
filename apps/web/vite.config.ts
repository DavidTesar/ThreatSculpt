import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    port: 5173,
  },
  build: {
    target: 'es2022',
    // No sourcemaps in the production bundle. A `.map` served next to a minified chunk
    // hands anyone who asks for it the original TypeScript — file paths, comments, and
    // the shape of the auth flow — which is free reconnaissance against a security
    // product. It is also how the removed MSW worker stayed readable in `dist` after it
    // had been stripped from the JS.
    //
    // The right answer once an error tracker exists is to generate maps and upload them
    // to it rather than serve them. Nothing on this branch collects errors, so `false`
    // is correct today; revisit this line, not this decision, when one is wired up.
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          react: ['react', 'react-dom', 'react-router-dom'],
          charts: ['recharts'],
          query: ['@tanstack/react-query'],
        },
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    restoreMocks: true,
    // Rendering a full 50-row findings table through user-event is comfortably under a
    // second normally, but v8 coverage instrumentation multiplies that. The default 5s
    // makes the suite pass bare and flake under --coverage, which is the worst outcome.
    testTimeout: 20_000,
    hookTimeout: 20_000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: [
        'src/**/*.test.{ts,tsx}',
        'src/mocks/**',
        'src/test/**',
        'src/main.tsx',
        'src/**/*.d.ts',
      ],
    },
  },
});
