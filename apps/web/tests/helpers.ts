import { expect, type Page } from "@playwright/test";

export async function login(page: Page): Promise<void> {
  await page.goto("/dashboard");
  const loginHeading = page.getByRole("heading", { name: "Enter the control room" });
  const dashboardHeading = page.getByRole("heading", { name: /Good evening/ });
  await expect(loginHeading.or(dashboardHeading)).toBeVisible();
  if (await loginHeading.isVisible()) {
    await page.getByLabel("Email address").fill("admin@example.com");
    await page.getByLabel("Password").fill("SentinelDemo!2026");
    await Promise.all([
      page.waitForResponse((response) => response.url().endsWith("/api/v1/auth/login") && response.status() === 200),
      page.getByRole("button", { name: "Open security console" }).click(),
    ]);
  }
  await expect(dashboardHeading).toBeVisible();
}

export async function stable(page: Page, heading: string | RegExp): Promise<void> {
  await expect(page.getByRole("heading", { name: heading, level: 1 })).toBeVisible();
  await page.waitForLoadState("networkidle");
  await expect(page.locator(".error-state")).toHaveCount(0);
  await page.evaluate(() => document.fonts.ready);
}
