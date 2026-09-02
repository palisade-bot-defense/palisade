import { defineConfig } from "vite";

export default defineConfig({
  build: {
    lib: {
      entry: "src/index.ts",
      name: "PalisadeVerifier",
      formats: ["es", "umd"],
      fileName: (format) => format === "es" ? "palisade-verifier.js" : "palisade-verifier.umd.cjs",
    },
    sourcemap: true,
  },
});
