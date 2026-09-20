import { expect, test, type Page } from '@playwright/test';

const BASE_URL = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:4173';

async function openBuilder(page: Page) {
  await page.goto(new URL('/stix-builder.html', BASE_URL).toString());
  await expect(page.locator('#add-type')).toBeVisible();
}

test.describe('STIX Builder hardening', () => {
  test('preserves valid indicator pattern syntax during import sanitization', async ({ page }) => {
    await openBuilder(page);

    const indicator = await page.evaluate(() => {
      return (window as any).sanitizeImportedObject({
        type: 'indicator',
        spec_version: '2.1',
        id: 'indicator--22222222-2222-4222-8222-222222222222',
        created: '2026-01-01T00:00:00.000Z',
        modified: '2026-01-01T00:00:00.000Z',
        name: 'Suspicious IP',
        pattern: "[ipv4-addr:value = '192.0.2.1']",
        pattern_type: 'stix',
        valid_from: '2026-01-01T00:00:00.000Z',
      });
    });

    // Prerequisite: the sanitizer ran and returned an object at all. Only the pattern
    // projection below is the known gap, so a null result here is unexpected.
    expect(indicator, 'sanitizeImportedObject returned nothing').toBeTruthy();
    expect(indicator.type).toBe('indicator');

    test.fail(true, 'Known gap AF-RC-003: Composer import sanitization strips STIX pattern brackets and quotes');
    expect(indicator.pattern).toBe("[ipv4-addr:value = '192.0.2.1']");
  });

  test('rejects bundle imports with invalid objects without replacing the current bundle', async ({ page }) => {
    await openBuilder(page);

    await page.evaluate(() => (window as any).addObject('identity'));
    const bundlePreview = page.locator('#bundle-preview');
    const beforePreview = (await bundlePreview.textContent()) || '';

    page.on('dialog', (dialog) => dialog.accept());
    await page.locator('#bundle-file').setInputFiles({
      name: 'invalid-object-bundle.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify({
        type: 'bundle',
        id: 'bundle--33333333-3333-4333-8333-333333333333',
        objects: [
          {
            type: 'identity',
            spec_version: '2.1',
            id: 'identity--44444444-4444-4444-8444-444444444444',
            name: 'Valid Identity',
          },
          {
            type: 'indicator',
            spec_version: '2.1',
            id: 'indicator--55555555-5555-4555-8555-555555555555',
            name: 'Missing required pattern',
          },
        ],
      }), 'utf8'),
    });

    test.fail(true, 'Known gap AF-RC-003: Composer import silently skips invalid objects and replaces state');
    await expect(page.locator('#toast')).toHaveClass(/visible/);
    await expect(page.locator('#toast')).toContainText('Invalid STIX object');
    expect((await bundlePreview.textContent()) || '').toBe(beforePreview);
  });

  // AF-RC-004 REMAINS AN OPEN FINDING. Its coverage, however, is BLOCKED, not proven:
  // the case below calls enforceVisualizerBudgets(), which does not exist, so it threw a
  // ReferenceError and that exception was being credited as a reproduced graph-budget
  // failure. A missing function is not a real-path rendering-boundary result.
  //
  // Repairing it needs an approved budget contract and a test that drives the actual
  // render entry point with bounded data and an intercepted renderer. Inventing a
  // threshold here would fabricate a product requirement, so the case stays disabled and
  // the finding stays open and explicitly unverified.
  test.fixme('rejects visualizer edge counts over budget before rendering', async ({ page }) => {
    await openBuilder(page);

    const message = await page.evaluate(() => {
      const refs = Array.from({ length: 10_001 }, (_, index) => (
        `identity--${String(index).padStart(8, '0')}-0000-4000-8000-000000000000`
      ));
      return (window as any).enforceVisualizerBudgets({
        type: 'bundle',
        objects: [
          {
            type: 'report',
            id: 'report--66666666-6666-4666-8666-666666666666',
            object_refs: refs,
          },
        ],
      });
    });

    expect(message).toContain('Visualizer edge limit exceeded');
  });

  test('encodes numeric editor values before rendering attributes', async ({ page }) => {
    await openBuilder(page);

    const confidenceField = await page.evaluate(() => {
      (window as any).addObject('identity');
      const object = (window as any).getActiveObject();
      object.confidence = '1" autofocus onfocus="alert(1)';
      (window as any).renderEditor();
      return document.querySelector('[data-field="confidence"]')?.outerHTML || '';
    });

    // Prerequisite: the numeric field rendered at all. An empty string here means the
    // editor or selector changed, which is a real failure rather than the known gap.
    expect(confidenceField, 'confidence field did not render').not.toBe('');

    test.fail(true, 'Known gap AF-RC-007: Composer number inputs interpolate values into attributes unencoded');
    expect(confidenceField).toContain('1&quot; autofocus onfocus=&quot;alert(1)');
    expect(confidenceField).not.toContain('" autofocus');
  });
});
