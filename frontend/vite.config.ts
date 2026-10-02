import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    // The SPA talks to the FastAPI backend through the dev server so that the
    // browser only ever sees one origin. That keeps CORS out of the picture and
    // means VITE_API_BASE_URL can be a bare "" (same-origin) in development.
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});