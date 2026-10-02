import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

/**
 * GitHub Pages serves this project from https://<user>.github.io/1s5i5h/, so
 * every asset URL and router path must carry the repo-name prefix. Without it
 * the built HTML requests /assets/... instead of /1s5i5h/assets/... and the
 * page renders blank.
 */
const REPO = "1s5i5h";

export default defineConfig(({ mode }) => ({
  // "." is the frontend package root: Vite is always invoked from there, and
  // using a literal keeps this file free of node globals so `tsc` stays strict.
  // VITE_BASE overrides the prefix for a root host or a local static server.
  base: loadEnv(mode, ".", "").VITE_BASE ?? `/${REPO}/`,
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
}));