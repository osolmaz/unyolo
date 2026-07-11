import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  root: "ui",
  base: "/plugins/brokerkit/ui/",
  build: { outDir: "../dist/ui", emptyOutDir: false, sourcemap: false },
});
