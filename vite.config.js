
import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    rollupOptions: {
      input: {
        main: 'index.html',
        home: 'home.html',
        scanner: 'scanner.html',
        resources: 'resources.html',
      },
    },
  },
  server: {
    port: 3000,
    open: true,
    historyApiFallback: true, 
  }
});