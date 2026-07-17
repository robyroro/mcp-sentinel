import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { login, stable } from "./helpers";

test.beforeEach(async ({ page }) => {
  await login(page);
});

test("dashboard is backed by seeded security data and has no serious accessibility violations", async ({ page }) => {
  await stable(page, /Good evening/);
  await expect(page.getByText("520")).toBeVisible();
  await expect(page.getByText("Live enforcement")).toBeVisible();
  const results = await new AxeBuilder({ page }).disableRules(["color-contrast"]).analyze();
  expect(results.violations.filter((violation) => ["critical", "serious"].includes(violation.impact ?? ""))).toEqual([]);
});

test("policy tester returns deterministic trace without calling a server", async ({ page }) => {
  await page.goto("/policies/tester");
  await stable(page, "Policy tester");
  await page.getByRole("button", { name: "Run policy evaluation" }).click();
  await expect(page.getByText("Deny", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("deny-secret-access", { exact: true })).toBeVisible();
  await expect(page.getByText("SIMULATION ONLY")).toBeVisible();
});

test("English and Romanian navigation switch without losing the session", async ({ page }) => {
  await page.getByRole("button", { name: "Language" }).click();
  await expect(page.getByText("Prezentare de securitate")).toBeVisible();
  await page.getByRole("button", { name: "Limbă" }).click();
  await expect(page.getByText("Security overview")).toBeVisible();
});

test("approval detail exposes risk, policy context, and required rationale", async ({ page }) => {
  await page.goto("/approvals/details");
  await stable(page, /filesystem|terminal|messaging|cloud/);
  await expect(page.getByText("Contextual risk")).toBeVisible();
  await expect(page.getByLabel("Approval decision rationale")).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve once" })).toBeEnabled();
});

test("session replay is simulation-only and returns a comparison", async ({ page }) => {
  await page.goto("/replay");
  await stable(page, /Codex Local/);
  await page.getByRole("button", { name: "Run simulation" }).click();
  await expect(page.getByText("SIMULATED")).toBeVisible();
  await expect(page.getByText("NO SIDE EFFECTS")).toBeVisible();
});
