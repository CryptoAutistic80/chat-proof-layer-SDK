import { expect, test } from "@playwright/test";

test("homepage to guided demo to proof/share pages stays understandable", async ({ page }) => {
  await page.goto("/");

  await expect(
    page.getByRole("heading", {
      level: 1,
      name: "Prove what your AI system did, without relying on ordinary logs."
    })
  ).toBeVisible();

  await page.getByRole("link", { name: "Try guided demo" }).click();
  await page.waitForURL(/\/guided/);

  await expect(
    page.getByRole("heading", {
      level: 1,
      name: "Start with the business story, not the technical settings"
    })
  ).toBeVisible();

  await expect(page.getByLabel("Capture mode")).toHaveValue("synthetic");
  await page.getByRole("button", { name: "Run this scenario" }).click();

  await page.waitForURL(/\/what-happened\/.+/);
  await expect(page.getByRole("heading", { level: 2, name: /Investor summary completed/i })).toBeVisible();
  await expect(page.getByText("What the AI returned")).toBeVisible();

  await page
    .getByRole("navigation", { name: "Demo" })
    .getByRole("link", { name: "What You Can Prove" })
    .click();
  await page.waitForURL(/\/what-you-can-prove(\/.+)?/);
  await expect(page.getByRole("heading", { level: 2, name: "What a reviewer can independently confirm" })).toBeVisible();

  await page
    .getByRole("navigation", { name: "Demo" })
    .getByRole("link", { name: "What You Can Share" })
    .click();
  await page.waitForURL(/\/what-you-can-share(\/.+)?/);
  await expect(page.getByRole("heading", { level: 2, name: "How this proof record leaves the system" })).toBeVisible();

  const downloadLink = page.getByRole("link", { name: /download/i });
  const emptyDisclosure = page.getByText(
    "No disclosure package is available for this run with the current sharing profile."
  );
  await expect(downloadLink.or(emptyDisclosure)).toBeVisible();



  await page.goto("/chat-demo");
  await expect(page.getByRole("heading", { level: 1, name: "Run a chat, seal it, and get proof metadata instantly" })).toBeVisible();

  await page.goto("/verify");
  await expect(page.getByRole("heading", { level: 1, name: "See tamper evidence in action" })).toBeVisible();

  await page.goto("/share");
  await page.waitForURL(/\/records\?view=share/);
  await expect(page.getByRole("tab", { name: /Share/i })).toBeVisible();

  await page.getByRole("link", { name: "Docs" }).click();
  await page.waitForURL(/\/docs/);
  await expect(page.getByRole("heading", { level: 1, name: "Start with the path that fits your role" })).toBeVisible();
});
