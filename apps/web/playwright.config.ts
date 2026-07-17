import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 45_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: "http://127.0.0.1:3011",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
  },
  webServer: [
    {
      command: "\"..\\..\\.venv\\Scripts\\python.exe\" -m uvicorn mcp_sentinel_api.main:app --host 127.0.0.1 --port 8011",
      url: "http://127.0.0.1:8011/api/v1/health",
      timeout: 60_000,
      reuseExistingServer: true,
    },
    {
      command: "pnpm serve:e2e",
      url: "http://127.0.0.1:3011",
      timeout: 120_000,
      reuseExistingServer: true,
    },
  ],
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 1000 } } },
  ],
});
