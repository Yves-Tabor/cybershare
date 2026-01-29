
import { defineConfig } from 'vite';

export default defineConfig({
  // This ensures Vite treats both HTML files as independent pages
  build: {
    rollupOptions: {
      input: {
        main: 'index.html',
        home: 'home.html',
      },
    },
  },
  server: {
    // This prevents Vite from forcing index.html on every route
    historyApiFallback: false, 
  }
});