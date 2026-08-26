import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../internal/adminui/dist",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    proxy: { "/health": "http://127.0.0.1:8080", "/v1": "http://127.0.0.1:8080" },
  },
});
