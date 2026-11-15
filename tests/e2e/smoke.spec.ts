import { expect, test, type Page } from '@playwright/test';

const BASE_URL = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:4173';

async function openApp(page: Page) {
  await page.goto(new URL('/index.html', BASE_URL).toString());
  await expect(page.locator('#loading')).toHaveClass(/hidden/, { timeout: 60_000 });
  await expect(page.locator('.header-title')).toHaveText('AttackFlow');
}

test.describe('Smoke', () => {
  test('loads shell and initial ATT&CK list', async ({ page }) => {
    await openApp(page);

    await expect(page).toHaveTitle(/AttackFlow/);
    await expect.poll(async () => page.locator('#list-attack .entity-item').count(), {
      timeout: 30_000,
    }).toBeGreaterThan(0);
  });

  test('switches between core views', async ({ page }) => {
    await openApp(page);

    await page.click('#view-relationship');
    await expect(page.locator('#relationship-container')).toHaveClass(/visible/);
    await expect(page.locator('#content-title')).toHaveText('Kill Chain Relationships');

    await page.click('#view-explorer');
    await expect(page.locator('.app')).toHaveClass(/explorer-view/);

    await page.click('#view-killchain');
    await expect(page.locator('#content-title')).toHaveText('Unified Kill Chain');
  });
});
