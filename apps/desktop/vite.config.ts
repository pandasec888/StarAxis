import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  build: {
    // Tauri's production CSP intentionally rejects data: images. Keep imported
    // artwork as same-origin files instead of letting Vite inline small assets.
    assetsInlineLimit: 0,
    rollupOptions: {
      input: {
        main: "index.html",
        unlock: "unlock.html",
      },
    },
  },
  server: {
    host: "127.0.0.1",
    port: 1420,
    strictPort: true,
  },
  test: {
    environment: "jsdom",
  },
});
