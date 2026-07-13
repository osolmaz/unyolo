import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

const cspHeaders = {
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:",
};

export default defineConfig({
  plugins: [react(), tailwindcss()],
  root: "ui",
  base: "/plugins/brokerkit/ui/",
  preview: { headers: cspHeaders },
  build: { outDir: "../dist/ui", emptyOutDir: false, sourcemap: false },
});
