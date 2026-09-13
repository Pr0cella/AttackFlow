import { expect, test } from '@playwright/test';

test('import validation runner passes every fixture against the current app', async ({ page }) => {
  await page.route('**/*', route => {
    const url = new URL(route.request().url());
    return url.hostname === '127.0.0.1' ? route.continue() : route.abort();
  });
  await page.goto('/tests/import-validation/test-runner.html');
  await page.getByRole('button', { name: 'Run All Tests' }).click();
  await expect(page.locator('.test-card.pending')).toHaveCount(0, { timeout: 90_000 });

  const cards = await page.locator('.test-card').evaluateAll(elements => elements.map(card => ({
    name: card.querySelector('.test-name')?.textContent || '',
    status: card.querySelector('.test-status')?.textContent || '',
    details: card.querySelector('.test-details')?.textContent || '',
    error: card.querySelector('.test-error')?.textContent || '',
  })));

  const notPassing = cards.filter(card => card.status !== 'PASS');
  expect(cards.length).toBeGreaterThan(0);
  expect(notPassing, JSON.stringify(notPassing, null, 2)).toEqual([]);
});
