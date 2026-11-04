import { defineConfig, devices } from "@playwright/test";

const python = process.env.PYTHON || (process.platform === "win32"
  ? "../../.venv/Scripts/python.exe"
  : "python");
const quote = (value: string) => `"${value.replaceAll('"', '\\"')}"`;

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
      command: `${quote(python)} -m uvicorn mcp_sentinel_api.main:app --host 127.0.0.1 --port 8011`,
      url: "http://127.0.0.1:8011/api/v1/health",
      timeout: 60_000,
      reuseExistingServer: !process.env.CI,
      env: {
        SENTINEL_DATABASE_URL: "sqlite:///./sentinel-e2e.db",
        SENTINEL_SIGNING_KEY_PATH: ".sentinel/e2e-signing-key.pem",
      },
    },
    {
      command: "pnpm serve:e2e",
      url: "http://127.0.0.1:3011",
      timeout: 120_000,
      reuseExistingServer: !process.env.CI,
    },
  ],
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 1000 } } },
  ],
});
