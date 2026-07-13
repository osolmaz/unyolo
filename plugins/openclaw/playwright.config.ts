import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "test/browser",
  use: { baseURL: "http://127.0.0.1:4179", screenshot: "only-on-failure" },
  webServer: {
    command:
      "pnpm run build && pnpm exec vite preview --host 127.0.0.1 --port 4179",
    port: 4179,
    reuseExistingServer: false,
  },
  projects: [
    ...["chromium", "firefox", "webkit"].flatMap((browserName) => [
      {
        name: `${browserName}-desktop`,
        use: {
          browserName: browserName as "chromium" | "firefox" | "webkit",
          viewport: { width: 1280, height: 800 },
        },
      },
      {
        name: `${browserName}-mobile`,
        use: {
          browserName: browserName as "chromium" | "firefox" | "webkit",
          viewport: { width: 390, height: 844 },
        },
      },
    ]),
  ],
});
