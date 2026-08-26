import { defineConfig } from "vite";

export default defineConfig({
  build: {
    lib: {
      entry: "src/index.ts",
      name: "PalisadeSensor",
      formats: ["es", "umd"],
      fileName: (format) => format === "es" ? "palisade-sensor.js" : "palisade-sensor.umd.cjs",
    },
    sourcemap: true,
  },
});
