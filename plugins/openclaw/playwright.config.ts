import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "test/browser",
  use: { baseURL: "http://127.0.0.1:4179", screenshot: "only-on-failure" },
  webServer: {
    command: "pnpm exec vite --host 127.0.0.1 --port 4179",
    port: 4179,
    reuseExistingServer: false,
  },
  projects: [
    { name: "desktop", use: { viewport: { width: 1280, height: 800 } } },
    { name: "mobile", use: { viewport: { width: 390, height: 844 } } },
  ],
});
