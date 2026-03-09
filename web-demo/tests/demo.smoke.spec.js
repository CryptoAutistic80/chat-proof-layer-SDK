import { expect, test } from "@playwright/test";

test("synthetic playground flow routes through results, examination, and exports", async ({
  page
}) => {
  await page.goto("/playground");

  await expect(
    page.getByRole("heading", { level: 2, name: "Configure the run" })
  ).toBeVisible();
  await expect(page.getByLabel("Capture mode")).toHaveValue("synthetic");

  await page.getByRole("button", { name: "Run proof workflow" }).click();

  await page.waitForURL(/\/results\/.+/);
  await expect(page.getByRole("heading", { level: 2, name: "Current run" })).toBeVisible();
  await expect(page.locator(".mode-badge")).toHaveText("synthetic_demo_capture");
  await expect(page.getByText("Response content")).toBeVisible();

  await page.getByRole("navigation").getByRole("link", { name: "Examination" }).click();
  await page.waitForURL(/\/examination(\/.+)?/);
  await expect(page.getByRole("heading", { level: 2, name: "Trust checks" })).toBeVisible();
  await expect(page.getByText("Bundle verification")).toBeVisible();

  await page.getByRole("navigation").getByRole("link", { name: "Exports" }).click();
  await page.waitForURL(/\/exports(\/.+)?/);
  await expect(page.getByRole("heading", { level: 2, name: "Pack assembly" })).toBeVisible();

  const downloadLink = page.getByRole("link", { name: /download/i });
  const emptyDisclosure = page.getByText(
    "No disclosure pack to export for this run with the selected profile."
  );
  await expect(downloadLink.or(emptyDisclosure)).toBeVisible();
});
