import { expect, test } from "@playwright/test";
import path from "node:path";
import { login, stable } from "./helpers";

const output = path.resolve(__dirname, "../../../screenshots");

const desktop: Array<[string, string, string | RegExp, "dark" | "light"]> = [
  ["01-dashboard.png", "/dashboard", /Good evening/, "dark"],
  ["02-server-registry.png", "/servers", "Server registry", "light"],
  ["03-server-risk-assessment.png", "/servers/risk", /Malicious Fixture|Risky Shell/, "dark"],
  ["04-tool-capabilities.png", "/tools", "Tool capabilities", "dark"],
  ["05-policy-list.png", "/policies", "Policy library", "light"],
  ["06-policy-editor.png", "/policies/editor", "Edit policy controls", "dark"],
  ["07-policy-tester.png", "/policies/tester", "Policy tester", "light"],
  ["08-live-sessions.png", "/sessions", "Live sessions", "dark"],
  ["09-session-overview.png", "/sessions/overview", /Codex Local/, "light"],
  ["10-session-timeline.png", "/sessions/timeline", /Codex Local/, "dark"],
  ["11-tool-request-details.png", "/requests/details", /Codex Local/, "dark"],
  ["12-approval-queue.png", "/approvals", "Approval queue", "light"],
  ["13-approval-details.png", "/approvals/details", /filesystem|terminal|messaging|cloud/, "dark"],
  ["14-secret-redaction.png", "/security/secrets", "Secret redaction", "dark"],
  ["15-injection-warning.png", "/security/injections", "Injection warnings", "light"],
  ["16-sandbox-manager.png", "/sandboxes", "Sandbox manager", "dark"],
  ["17-risk-dashboard.png", "/risk", "Risk dashboard", "light"],
  ["18-replay-comparison.png", "/replay", /Codex Local/, "dark"],
  ["19-report-builder.png", "/reports", "Reports and evidence", "light"],
  ["20-audit-export.png", "/audit", "Audit export", "dark"],
  ["21-settings.png", "/settings", "Settings", "light"],
];

test("capture deterministic desktop and mobile gallery", async ({ page }) => {
  await login(page);
  for (const [filename, route, heading, theme] of desktop) {
    await page.evaluate((value) => localStorage.setItem("sentinel_theme", value), theme);
    await page.goto(route);
    await stable(page, heading);
    if (route === "/policies/tester") {
      await page.getByRole("button", { name: "Run policy evaluation" }).click();
      await expect(page.getByText("Rule trace")).toBeVisible();
    }
    if (route === "/replay") {
      await page.getByRole("button", { name: "Run simulation" }).click();
      await expect(page.getByText("SIMULATED")).toBeVisible();
    }
    await page.screenshot({ path: path.join(output, filename), animations: "disabled" });
  }

  await page.setViewportSize({ width: 390, height: 844 });
  const mobile: Array<[string, string, string | RegExp]> = [
    ["22-mobile-dashboard.png", "/dashboard", /Good evening/],
    ["23-mobile-approval.png", "/approvals/details", /filesystem|terminal|messaging|cloud/],
    ["24-mobile-session.png", "/sessions/timeline", /Codex Local/],
  ];
  for (const [filename, route, heading] of mobile) {
    await page.goto(route);
    await stable(page, heading);
    await page.screenshot({ path: path.join(output, filename), animations: "disabled" });
  }
});
