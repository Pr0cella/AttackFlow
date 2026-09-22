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

    // The Composer's import sanitizer removes [ ] { } ; " ' ` from every string it
    // accepts. A STIX pattern is built almost entirely from those characters, so a valid
    // indicator arrives as unparseable text rather than being rejected or preserved.
    test.fail(true, 'Known gap: import sanitization removes the bracket and quote characters a STIX pattern is made of');
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

    // The import replaces the current bundle BEFORE validating the incoming objects, then
    // drops each unusable one with no message. A partly invalid file therefore lands as a
    // silent partial import, and the bundle it overwrote is already gone.
    test.fail(true, 'Known gap: a partly invalid bundle replaces the current one and its bad objects are dropped without a diagnostic');
    await expect(page.locator('#toast')).toHaveClass(/visible/);
    await expect(page.locator('#toast')).toContainText('Invalid STIX object');
    expect((await bundlePreview.textContent()) || '').toBe(beforePreview);
  });

  // THE VISUALIZER EDGE-BUDGET GAP IS OPEN, AND ITS COVERAGE IS BLOCKED, NOT PROVEN.
  //
  // The case below calls enforceVisualizerBudgets(), which does not exist in
  // stix-builder.html. It therefore threw a ReferenceError, and because the case carried a
  // "known gap" marker that exception was being counted as a reproduced graph-budget
  // failure. A missing function is not a rendering-boundary result: it demonstrates
  // neither the defect nor a fix.
  //
  // Repairing it needs an agreed budget threshold plus a test that drives the real render
  // entry point with bounded data and an intercepted renderer. Inventing a threshold here
  // would invent a product requirement, so the case stays disabled and reports as skipped
  // rather than as a satisfied gap.
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

  // Numeric editor fields render their value into a value="..." attribute, so it must be
  // entity-encoded. Import and editing already coerce these fields to numbers, so the
  // hostile cases write text straight into the active object to test the sink itself.
  const NUMERIC_FIELD_ATTRIBUTES = ['type', 'data-field', 'data-type', 'value'];

  async function renderHostileNumericValue(page: Page, type: string, key: string, payload: string) {
    return page.evaluate(({ objectType, fieldKey, value }) => {
      (window as any).__numericSinkCanary = 0;
      (window as any).addObject(objectType);
      const object = (window as any).getActiveObject();
      object[fieldKey] = value;
      const before = JSON.stringify(object);
      (window as any).renderEditor();
      return before;
    }, { objectType: type, fieldKey: key, value: payload });
  }

  async function inspectNumericField(page: Page, key: string) {
    // Focus the field so an injected onfocus handler would fire, then let any injected
    // image finish loading or failing before the canary is read.
    await page.locator(`#editor-panel [data-field="${key}"]`).first().focus();
    return page.evaluate(async (fieldKey) => {
      const panel = document.getElementById('editor-panel')!;
      await Promise.all(Array.from(panel.querySelectorAll('img')).map((img) => (
        img.complete ? null : new Promise((resolve) => {
          img.addEventListener('load', resolve, { once: true });
          img.addEventListener('error', resolve, { once: true });
        })
      )));
      const inputs = Array.from(panel.querySelectorAll<HTMLInputElement>(`[data-field="${fieldKey}"]`));
      const input = inputs[0];
      const container = input?.closest('.field-input');
      return {
        count: inputs.length,
        type: input?.getAttribute('type') ?? null,
        attributes: input ? input.getAttributeNames() : [],
        valueAttribute: input?.getAttribute('value') ?? null,
        containerChildren: container
          ? Array.from(container.children).map((child) => `${child.tagName}${child.className ? '.' + child.className : ''}`)
          : [],
        injected: panel.querySelectorAll('[data-injected], [autofocus], [onfocus], [onerror], img').length,
        canary: (window as any).__numericSinkCanary,
        storedAfter: JSON.stringify((window as any).getActiveObject()),
      };
    }, key);
  }

  test('encodes numeric editor values before rendering attributes', async ({ page }) => {
    await openBuilder(page);

    // The trailing comment carries literal entity text, a backslash, an apostrophe and a
    // backtick: an encoder that skipped `&` would hand back a bare quote for the literal
    // entity, and one that encoded twice would hand back the entity text.
    const payload = '1" autofocus onfocus="window.__numericSinkCanary = 1 // &quot; &amp; \\ \' `';
    const before = await renderHostileNumericValue(page, 'identity', 'confidence', payload);
    const field = await inspectNumericField(page, 'confidence');

    // Prerequisite: the integer field rendered at all. A zero count means the editor or
    // selector changed, which is a real failure rather than a sink result.
    expect(field.count, 'confidence field did not render').toBe(1);
    expect(field.type).toBe('number');

    expect(field.attributes, 'a quote in the value added attributes to the input').toEqual(NUMERIC_FIELD_ATTRIBUTES);
    expect(field.injected, 'injected markup exists in the editor').toBe(0);
    expect(field.valueAttribute, 'the value attribute is not the stored value verbatim').toBe(payload);
    expect(field.canary, 'an injected handler ran').toBe(0);
    expect(field.containerChildren).toEqual(['INPUT', 'DIV.hint']);
    expect(field.storedAfter, 'rendering changed the stored object').toBe(before);
  });

  test('keeps a tag-closing numeric editor value inside its attribute', async ({ page }) => {
    await openBuilder(page);

    const payload = '"><img src="x" data-injected="1" onerror="window.__numericSinkCanary = 2">';
    const before = await renderHostileNumericValue(page, 'location', 'latitude', payload);
    const field = await inspectNumericField(page, 'latitude');

    expect(field.count, 'latitude field did not render').toBe(1);
    expect(field.type).toBe('number');

    expect(field.injected, 'a closed tag let markup into the editor').toBe(0);
    expect(field.containerChildren, 'the field holds nodes other than its input and hint').toEqual(['INPUT', 'DIV.hint']);
    expect(field.attributes).toEqual(NUMERIC_FIELD_ATTRIBUTES);
    expect(field.valueAttribute, 'the value attribute is not the stored value verbatim').toBe(payload);
    expect(field.canary, 'an injected handler ran').toBe(0);
    expect(field.storedAfter, 'rendering changed the stored object').toBe(before);
  });

  test('renders imported zero, negative, decimal and absent numeric values unchanged', async ({ page }) => {
    await openBuilder(page);

    const ids = {
      zero: 'identity--77777777-7777-4777-8777-777777777777',
      location: 'location--88888888-8888-4888-8888-888888888888',
      absent: 'identity--99999999-9999-4999-8999-999999999999',
    };
    await page.locator('#bundle-file').setInputFiles({
      name: 'numeric-values-bundle.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify({
        type: 'bundle',
        id: 'bundle--66666666-6666-4666-8666-666666666666',
        objects: [
          {
            type: 'identity', spec_version: '2.1', id: ids.zero,
            created: '2026-01-01T00:00:00.000Z', modified: '2026-01-01T00:00:00.000Z',
            name: 'Zero Confidence', confidence: 0,
          },
          {
            type: 'location', spec_version: '2.1', id: ids.location,
            created: '2026-01-01T00:00:00.000Z', modified: '2026-01-01T00:00:00.000Z',
            name: 'Sydney', latitude: -33.8688, longitude: 151.2093, precision: 0,
          },
          {
            type: 'identity', spec_version: '2.1', id: ids.absent,
            created: '2026-01-01T00:00:00.000Z', modified: '2026-01-01T00:00:00.000Z',
            name: 'No Confidence',
          },
        ],
      }), 'utf8'),
    });
    await expect(page.locator('#toast')).toContainText('Bundle imported');

    const readField = (key: string) => page.locator(`#editor-panel [data-field="${key}"]`).evaluate(
      (input: HTMLInputElement) => ({ attribute: input.getAttribute('value'), value: input.value }),
    );

    // Zero is falsy and is the value an encoder written as `value || ''` would lose.
    await page.locator('#object-list .object-item', { hasText: ids.zero }).click();
    expect(await readField('confidence')).toEqual({ attribute: '0', value: '0' });

    await page.locator('#object-list .object-item', { hasText: ids.location }).click();
    expect(await readField('latitude')).toEqual({ attribute: '-33.8688', value: '-33.8688' });
    expect(await readField('longitude')).toEqual({ attribute: '151.2093', value: '151.2093' });
    expect(await readField('precision')).toEqual({ attribute: '0', value: '0' });

    await page.locator('#object-list .object-item', { hasText: ids.absent }).click();
    expect(await readField('confidence')).toEqual({ attribute: '', value: '' });
  });

  test('edits numeric fields through the editor as numbers', async ({ page }) => {
    await openBuilder(page);

    await page.locator('#add-type').selectOption('location');
    await page.locator('#add-object').click();
    const latitude = page.locator('#editor-panel [data-field="latitude"]');
    const confidence = page.locator('#editor-panel [data-field="confidence"]');
    await expect(latitude).toBeVisible();

    await latitude.fill('-12.5');
    await confidence.fill('0');
    const stored = await page.evaluate(() => {
      const object = (window as any).getActiveObject();
      return { id: object.id, latitude: object.latitude, confidence: object.confidence };
    });
    expect(stored.latitude).toBe(-12.5);
    expect(stored.confidence).toBe(0);

    // Re-render through the real list selection and read the values back out of the DOM.
    await page.locator('#object-list .object-item', { hasText: stored.id }).click();
    await expect(latitude).toHaveValue('-12.5');
    await expect(confidence).toHaveValue('0');

    await latitude.fill('');
    expect(await page.evaluate(() => (window as any).getActiveObject().latitude)).toBeNull();
  });
});
