import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  publicDir: "../brand/exports",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
});
