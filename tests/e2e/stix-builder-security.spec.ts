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

    expect(indicator, 'sanitizeImportedObject returned nothing').toBeTruthy();
    expect(indicator.type).toBe('indicator');

    // A STIX pattern is built almost entirely from brackets and quotes. Import keeps evidence
    // text verbatim and leaves encoding to the output sinks.
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

// Evidence text keeps every printable character and is encoded at each sink. Structural
// values follow a fixed grammar: an invalid one rejects the imported file, is refused by
// the editor and is reported by validation, without relying on typing guards.
test.describe('Composer evidence and structural values', () => {
  const T0 = '2026-01-01T00:00:00.000Z';
  const EVIDENCE = 'Quote "q" \'a\' [b] {c} ; <x> & `t` \\ back';
  const PATTERN = "[file:size > 10 AND file:name = 'a--b.exe'] OR [domain-name:value = 'x.example']";
  const HOSTILE = '"><img src="x" data-injected="1" onerror="window.__evidenceCanary = 1">';
  const ENTITY = 'literal &lt;b&gt; &amp; &quot;';

  const stixId = (type: string, hex: string) =>
    `${type}--${hex.repeat(8)}-${hex.repeat(4)}-4${hex.repeat(3)}-8${hex.repeat(3)}-${hex.repeat(12)}`;
  const sdo = (type: string, hex: string, extra: Record<string, unknown> = {}) => ({
    type, spec_version: '2.1', id: stixId(type, hex), created: T0, modified: T0, ...extra,
  });
  const sco = (type: string, hex: string, extra: Record<string, unknown> = {}) => ({
    type, spec_version: '2.1', id: stixId(type, hex), ...extra,
  });
  const TLP = stixId('marking-definition', 'f');

  let uploads = 0;
  async function uploadBundle(page: Page, objects: unknown[], bundleId = stixId('bundle', 'e')) {
    const dialogs: string[] = [];
    const onDialog = (dialog: any) => { dialogs.push(dialog.message()); dialog.accept(); };
    page.on('dialog', onDialog);
    try {
      await page.locator('#toast').evaluate((element) => { element.textContent = ''; });
      await page.locator('#bundle-file').setInputFiles({
        name: `upload-${++uploads}.json`,
        mimeType: 'application/json',
        buffer: Buffer.from(JSON.stringify({
          type: 'bundle', id: bundleId, spec_version: '2.1', objects,
        }), 'utf8'),
      });
      await expect(page.locator('#toast')).not.toBeEmpty();
    } finally {
      page.off('dialog', onDialog);
    }
    return { toast: (await page.locator('#toast').textContent()) || '', dialogs };
  }

  const bundleState = (page: Page) => page.evaluate(() => JSON.stringify((eval('state') as any).bundle));
  const objectState = (page: Page, id: string) => page.evaluate(
    (objectId) => JSON.parse(JSON.stringify((eval('state') as any).objectsById.get(objectId))), id,
  );

  test('imports punctuation-rich evidence verbatim and renders it only as text', async ({ page }) => {
    await openBuilder(page);
    await page.evaluate(() => { (window as any).__evidenceCanary = 0; });

    const indicator = sdo('indicator', 'a', {
      name: EVIDENCE, description: HOSTILE, pattern: PATTERN, pattern_type: 'stix', valid_from: T0,
      labels: [EVIDENCE, ENTITY, HOSTILE],
      external_references: [{
        source_name: EVIDENCE, description: HOSTILE, external_id: ENTITY,
        url: 'https://example.test/path?q=1&r=two',
      }],
    });
    const process = sco('process', 'b', { environment_variables: { PATH: EVIDENCE, HOME: HOSTILE } });
    const { toast } = await uploadBundle(page, [indicator, process]);
    expect(toast).toBe('Bundle imported');

    const stored = await objectState(page, indicator.id);
    expect(stored.name).toBe(EVIDENCE);
    expect(stored.description).toBe(HOSTILE);
    expect(stored.pattern).toBe(PATTERN);
    expect(stored.labels).toEqual([EVIDENCE, ENTITY, HOSTILE]);
    expect(stored.external_references[0]).toMatchObject({
      source_name: EVIDENCE, description: HOSTILE, external_id: ENTITY,
      url: 'https://example.test/path?q=1&r=two',
    });
    expect((await objectState(page, process.id)).environment_variables).toEqual({ PATH: EVIDENCE, HOME: HOSTILE });

    // The editor shows the stored text exactly: attributes are encoded once, not stripped,
    // and literal entity text stays literal.
    const shown = await page.evaluate(() => {
      const panel = document.getElementById('editor-panel')!;
      const read = (selector: string) => Array.from(panel.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>(selector))
        .map((element) => element.value);
      return {
        name: read('[data-field="name"]'),
        pattern: read('[data-field="pattern"]'),
        labels: read('input[data-list-field="labels"]'),
        references: read('input[data-ref-field="external_references"]'),
      };
    });
    expect(shown.name).toEqual([EVIDENCE]);
    expect(shown.pattern).toEqual([PATTERN]);
    expect(shown.labels).toEqual([EVIDENCE, ENTITY, HOSTILE]);
    expect(shown.references).toEqual([EVIDENCE, HOSTILE, 'https://example.test/path?q=1&r=two', ENTITY]);

    await page.locator('#type-tabs .tab', { hasText: /^SCO$/ }).click();
    await page.locator('#object-list .object-item', { hasText: process.id }).click();
    const dictionaryValues = await page.locator('#editor-panel [data-dict-role="value"]').evaluateAll(
      (inputs) => inputs.map((input) => (input as HTMLInputElement).value),
    );
    expect(dictionaryValues.sort()).toEqual([EVIDENCE, HOSTILE].sort());

    for (const input of await page.locator('#editor-panel input, #editor-panel textarea').all()) {
      await input.focus();
    }
    await page.evaluate(async () => {
      await Promise.all(Array.from(document.images).map((img) => (
        img.complete ? null : new Promise((resolve) => {
          img.addEventListener('load', resolve, { once: true });
          img.addEventListener('error', resolve, { once: true });
        })
      )));
    });
    expect(await page.locator('[data-injected]').count(), 'imported markup became elements').toBe(0);
    expect(await page.evaluate(() => (window as any).__evidenceCanary), 'an injected handler ran').toBe(0);
  });

  test('a keystroke in the editor commits the displayed evidence unchanged', async ({ page }) => {
    await openBuilder(page);
    const identity = sdo('identity', 'c', { name: EVIDENCE });
    expect((await uploadBundle(page, [identity])).toast).toBe('Bundle imported');

    const name = page.locator('#editor-panel [data-field="name"]');
    await name.click();
    await page.keyboard.press('End');
    await page.keyboard.type('Z');
    expect((await objectState(page, identity.id)).name).toBe(`${EVIDENCE}Z`);
  });

  test('typing and pasting punctuation into evidence fields stores it verbatim', async ({ page }) => {
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    await openBuilder(page);
    await page.locator('#add-type').selectOption('indicator');
    await page.locator('#add-object').click();

    const typed = `[a:b = 'c']; {x} "y" <z> \\ \``;
    await page.locator('#editor-panel [data-field="name"]').pressSequentially(typed);
    await page.locator('#editor-panel [data-field="pattern"]').pressSequentially(PATTERN);

    await page.evaluate((text) => navigator.clipboard.writeText(text), EVIDENCE);
    await page.locator('#editor-panel [data-field="description"]').focus();
    await page.keyboard.press('ControlOrMeta+V');

    const stored = await page.evaluate(() => {
      const object = (window as any).getActiveObject();
      return { name: object.name, pattern: object.pattern, description: object.description };
    });
    expect(stored).toEqual({ name: typed, pattern: PATTERN, description: EVIDENCE });
  });

  // One case per structural value class. The first object in each file is valid, so a
  // partial import would be visible as a changed bundle.
  const INVALID_STRUCTURAL = [
    { label: 'dictionary key', field: 'environment_variables', object: sco('process', '1', { environment_variables: { 'BAD[KEY]': 'x' } }) },
    { label: 'hash key', field: 'hashes', object: sco('file', '2', { name: 'a.exe', hashes: { 'SHA 256': 'ab' } }) },
    { label: 'extension key', field: 'extensions', object: sco('file', '3', { name: 'a.exe', extensions: { 'ntfs"ext': { k: 'v' } } }) },
    { label: 'non-string kill chain value', field: 'kill_chain_phases', object: sdo('malware', '6', { name: 'm', is_family: false, kill_chain_phases: [{ kill_chain_name: 5, phase_name: 'execution' }] }) },
    { label: 'granular marking selector', field: 'granular_markings', object: sdo('identity', '7', { name: 'i', granular_markings: [{ selectors: ['description]'], marking_ref: TLP }] }) },
    { label: 'granular marking ref', field: 'granular_markings', object: sdo('identity', '8', { name: 'i', granular_markings: [{ selectors: ['description'], marking_ref: 'marking-definition--nope' }] }) },
    { label: 'object ref', field: 'object_refs', object: sdo('report', '9', { name: 'r', published: T0, object_refs: ['identity--"bad"'] }) },
    { label: 'identifier field', field: 'created_by_ref', object: sdo('identity', 'a', { name: 'i', created_by_ref: 'identity--x" onmouseover="1' }) },
    { label: 'timestamp field', field: 'valid_from', object: sdo('indicator', 'b', { name: 'n', pattern: '[x:y = 1]', pattern_type: 'stix', valid_from: 'Jan 1 2026' }) },
    { label: 'created timestamp', field: 'created', object: { ...sdo('identity', 'c', { name: 'i' }), created: '2026-01-01 00:00:00' } },
    { label: 'impossible calendar date', field: 'modified', object: { ...sdo('identity', 'f', { name: 'i' }), modified: '2026-02-30T00:00:00Z' } },
    // null is not a JSON string or array, and a granular marking needs selectors plus
    // exactly one of marking_ref or lang (STIX 2.1 section 7.2.3.1).
    { label: 'null granular marking', field: 'granular_markings[0]', object: sdo('identity', '1', { name: 'i', granular_markings: [null] }) },
    { label: 'granular marking without marking_ref or lang', field: 'granular_markings[0].marking_ref', object: sdo('identity', '2', { name: 'i', granular_markings: [{ selectors: ['description'] }] }) },
    { label: 'granular marking with marking_ref and lang', field: 'granular_markings[0]', object: sdo('identity', '3', { name: 'i', granular_markings: [{ selectors: ['description'], marking_ref: TLP, lang: 'en' }] }) },
    { label: 'granular marking without selectors', field: 'granular_markings[0].selectors', object: sdo('identity', '4', { name: 'i', granular_markings: [{ marking_ref: TLP }] }) },
    { label: 'non-list granular marking selectors', field: 'granular_markings[0].selectors', object: sdo('identity', 'b', { name: 'i', granular_markings: [{ selectors: 'description', marking_ref: TLP }] }) },
    { label: 'non-string granular marking lang', field: 'granular_markings[0].lang', object: sdo('identity', 'c', { name: 'i', granular_markings: [{ selectors: ['description'], lang: 5 }] }) },
    { label: 'granular marking with empty lang and no marking_ref', field: 'granular_markings[0].marking_ref', object: sdo('identity', 'f', { name: 'i', granular_markings: [{ selectors: ['description'], lang: '' }] }) },
    { label: 'null granular marking selector', field: 'granular_markings[0].selectors[0]', object: sdo('identity', '5', { name: 'i', granular_markings: [{ selectors: [null], marking_ref: TLP }] }) },
    { label: 'null created timestamp', field: 'created', object: { ...sdo('identity', '6', { name: 'i' }), created: null } },
    { label: 'null timestamp field', field: 'valid_from', object: sdo('indicator', '7', { name: 'n', pattern: '[x:y = 1]', pattern_type: 'stix', valid_from: null }) },
    { label: 'null object ref', field: 'object_refs[0]', object: sdo('report', '8', { name: 'r', published: T0, object_refs: [null] }) },
    { label: 'null kill chain phase', field: 'kill_chain_phases[0]', object: sdo('malware', '9', { name: 'm', is_family: false, kill_chain_phases: [null] }) },
    { label: 'kill chain phase without phase_name', field: 'kill_chain_phases[0].phase_name', object: sdo('malware', 'a', { name: 'm', is_family: false, kill_chain_phases: [{ kill_chain_name: 'mitre-attack' }] }) },
    // Extension names must be a defined extension name or an extension id (STIX 2.1 sections
    // 6.7 and 6.12). fromEntries makes '__proto__' an own key instead of setting the prototype.
    { label: '__proto__ extension name', field: 'extensions', object: sco('file', 'c', { name: 'a.exe', extensions: Object.fromEntries([['__proto__', { k: 'v' }]]) }) },
    { label: 'constructor extension name', field: 'extensions', object: sco('file', 'd', { name: 'a.exe', extensions: Object.fromEntries([['constructor', { k: 'v' }]]) }) },
    { label: 'prototype extension name', field: 'extensions', object: sco('file', 'e', { name: 'a.exe', extensions: Object.fromEntries([['prototype', { k: 'v' }]]) }) },
  ];

  for (const { label, field, object } of INVALID_STRUCTURAL) {
    test(`rejects the whole file for an invalid ${label}, leaving the current bundle untouched`, async ({ page }) => {
      await openBuilder(page);
      expect((await uploadBundle(page, [sdo('identity', 'd', { name: 'Existing' })])).toast).toBe('Bundle imported');
      const before = await bundleState(page);

      const { toast, dialogs } = await uploadBundle(page, [sdo('identity', 'e', { name: 'Valid first' }), object]);

      expect(toast).toMatch(/^Import failed: object 2 /);
      expect(toast).toContain(field);
      expect(dialogs, 'a rejected file must not ask to replace anything').toEqual([]);
      expect(await bundleState(page)).toBe(before);
    });
  }

  // A language marking (selectors plus lang, no marking_ref) is spec-valid under STIX 2.1
  // section 7.2.3.1, so it must not reject the file.
  test('does not reject a file for a granular language marking', async ({ page }) => {
    await openBuilder(page);
    const identity = sdo('identity', 'b', { name: 'i', granular_markings: [{ selectors: ['description'], lang: 'en' }] });
    const { toast, dialogs } = await uploadBundle(page, [identity]);
    expect(toast).toBe('Bundle imported');
    expect(dialogs).toEqual([]);
    expect(await page.evaluate((id) => (eval('state') as any).objectsById.has(id), identity.id)).toBe(true);
  });

  test('keeps valid structural values exactly, including selectors with list indexes', async ({ page }) => {
    await openBuilder(page);
    const identity = sdo('identity', '1', {
      name: 'Marked', created: '2026-01-01T00:00:00.123456Z', created_by_ref: stixId('identity', '2'),
      external_references: [{ source_name: 'src', url: 'https://example.test/' }],
      granular_markings: [{ selectors: ['description', 'external_references.[0].url'], marking_ref: TLP }],
    });
    const malware = sdo('malware', '3', {
      name: 'm', is_family: false, kill_chain_phases: [{ kill_chain_name: 'mitre-attack', phase_name: 'initial-access' }],
    });
    const file = sco('file', '4', {
      name: 'a.exe', hashes: { 'SHA-256': 'ab', x_custom_hash: 'cd' }, extensions: { 'ntfs-ext': { sid: 'S-1-5' } },
    });
    const process = sco('process', '5', { environment_variables: { Path_Var_1: 'C:\\x', 'X-Mailer': 'y' } });

    expect((await uploadBundle(page, [identity, malware, file, process])).toast).toBe('Bundle imported');
    const storedIdentity = await objectState(page, identity.id);
    expect(storedIdentity.created).toBe('2026-01-01T00:00:00.123456Z');
    expect(storedIdentity.created_by_ref).toBe(stixId('identity', '2'));
    expect(storedIdentity.granular_markings).toEqual([{ selectors: ['description', 'external_references.[0].url'], marking_ref: TLP }]);
    expect((await objectState(page, malware.id)).kill_chain_phases).toEqual([{ kill_chain_name: 'mitre-attack', phase_name: 'initial-access' }]);
    const storedFile = await objectState(page, file.id);
    expect(storedFile.hashes).toEqual({ 'SHA-256': 'ab', x_custom_hash: 'cd' });
    expect(storedFile.extensions).toEqual({ 'ntfs-ext': { sid: 'S-1-5' } });
    expect((await objectState(page, process.id)).environment_variables).toEqual({ Path_Var_1: 'C:\\x', 'X-Mailer': 'y' });
  });

  // STIX 2.1 section 2.3 allows any dictionary key made of letters, digits, '-' and '_', so
  // observed names such as __proto__ are evidence. fromEntries creates them as own keys.
  const PROTO_KEYS: [string, string][] = [['__proto__', 'p'], ['constructor', 'c'], ['prototype', 't'], ['PATH', '/bin']];
  const protoDictionary = () => Object.fromEntries(PROTO_KEYS);
  // Extension property names must be lowercase letters, digits or '_' (section 7.3.2.1).
  const PROTO_EXTENSION_KEYS: [string, string][] = [['__proto__', 'p'], ['constructor', 'c'], ['prototype', 't'], ['sid', 'S-1-5']];
  const protoExtension = () => ({ 'ntfs-ext': Object.fromEntries(PROTO_EXTENSION_KEYS) });
  // Reads a stored dictionary as entries, because '__proto__' would not survive a plain
  // object passing between the page and the test.
  const dictionaryView = (page: Page, id: string, field: string) => page.evaluate(({ objectId, key }) => {
    const view = (dict: any): any => ({
      nullPrototype: Object.getPrototypeOf(dict) === null,
      entries: Object.entries(dict).map(([k, v]) => [k, v && typeof v === 'object' ? view(v) : v]),
    });
    return view((eval('state') as any).objectsById.get(objectId)[key]);
  }, { objectId: id, key: field });
  const prototypeSnapshot = (page: Page) => page.evaluate(() => ({
    names: Object.getOwnPropertyNames(Object.prototype).sort(),
    plainObjectProto: Object.getPrototypeOf({}) === Object.prototype,
  }));
  const PROTO_VIEW = { nullPrototype: true, entries: PROTO_KEYS };

  test('keeps dictionary keys named like JavaScript prototype properties as inert data', async ({ page }) => {
    await openBuilder(page);
    const before = await prototypeSnapshot(page);
    const process = sco('process', '1', { environment_variables: protoDictionary() });
    const file = sco('file', '3', { name: 'a.exe', extensions: protoExtension() });
    expect((await uploadBundle(page, [process, file])).toast).toBe('Bundle imported');

    expect(await dictionaryView(page, process.id, 'environment_variables')).toEqual(PROTO_VIEW);
    expect(await dictionaryView(page, file.id, 'extensions'))
      .toEqual({ nullPrototype: true, entries: [['ntfs-ext', { nullPrototype: true, entries: PROTO_EXTENSION_KEYS }]] });
    expect(await prototypeSnapshot(page)).toEqual(before);
    expect(await page.evaluate(() => (window as any).validateBundle())).toEqual([]);
  });

  test('prototype-named dictionary keys survive an edit, export and reimport byte for byte', async ({ page }) => {
    await openBuilder(page);
    const process = sco('process', '4', { environment_variables: protoDictionary() });
    expect((await uploadBundle(page, [process])).toast).toBe('Bundle imported');
    await page.locator('#type-tabs .tab', { hasText: /^SCO$/ }).click();
    await page.locator('#object-list .object-item', { hasText: process.id }).click();
    const keys = await page.locator('#editor-panel [data-dict-field="environment_variables"][data-dict-role="key"]').evaluateAll(
      (inputs) => inputs.map((input) => (input as HTMLInputElement).value),
    );
    await page.locator('#editor-panel [data-dict-field="environment_variables"][data-dict-role="value"]').nth(keys.indexOf('PATH')).fill('/usr/bin');

    const download = async () => {
      const [file] = await Promise.all([page.waitForEvent('download'), page.locator('#export-bundle').click()]);
      return require('node:fs').readFileSync((await file.path())!, 'utf8') as string;
    };
    const first = await download();
    expect(Object.entries(JSON.parse(first).objects[0].environment_variables))
      .toEqual([['__proto__', 'p'], ['constructor', 'c'], ['prototype', 't'], ['PATH', '/usr/bin']]);

    await openBuilder(page);
    expect((await uploadBundle(page, JSON.parse(first).objects)).toast).toBe('Bundle imported');
    expect(await download()).toBe(first);
  });

  test('the editor commits prototype-named dictionary keys as data but refuses them as extension names', async ({ page }) => {
    await openBuilder(page);
    const before = await prototypeSnapshot(page);
    await page.locator('#add-type').selectOption('process');
    await page.locator('#add-object').click();
    const addRow = page.locator('#editor-panel [data-action="add-dict"][data-dict-field="environment_variables"]');
    await addRow.click();
    await addRow.click();
    const keys = page.locator('#editor-panel [data-dict-field="environment_variables"][data-dict-role="key"]');
    const values = page.locator('#editor-panel [data-dict-field="environment_variables"][data-dict-role="value"]');
    await keys.nth(0).fill('__proto__');
    await values.nth(0).fill('p');
    await keys.nth(1).fill('constructor');
    await values.nth(1).fill('c');
    const processId = await page.evaluate(() => (window as any).getActiveObject().id);
    expect(await dictionaryView(page, processId, 'environment_variables'))
      .toEqual({ nullPrototype: true, entries: [['__proto__', 'p'], ['constructor', 'c']] });
    expect(await keys.nth(0).getAttribute('aria-invalid')).toBeNull();
    await page.locator('#editor-panel [data-action="remove-dict"][data-dict-field="environment_variables"]').nth(1).click();
    expect(await dictionaryView(page, processId, 'environment_variables'))
      .toEqual({ nullPrototype: true, entries: [['__proto__', 'p']] });

    await page.locator('#add-type').selectOption('file');
    await page.locator('#add-object').click();
    await page.locator('#editor-panel [data-action="add-ext"][data-ext-field="extensions"]').click();
    await page.locator('#editor-panel [data-action="add-extdict"]').click();
    // An extension name is committed together with its body, so each name change is
    // followed by an edit inside the extension.
    const extensionName = page.locator('#editor-panel [data-ext-field="extensions"][data-ext-role="key"]');
    const bodyValue = page.locator('#editor-panel [data-extdict-role="value"]');
    await extensionName.fill('ntfs-ext');
    await page.locator('#editor-panel [data-extdict-role="key"]').fill('__proto__');
    await bodyValue.fill('S-1-5');
    const fileId = await page.evaluate(() => (window as any).getActiveObject().id);
    const committed = { nullPrototype: true, entries: [['ntfs-ext', { nullPrototype: true, entries: [['__proto__', 'S-1-5']] }]] };
    expect(await dictionaryView(page, fileId, 'extensions')).toEqual(committed);

    for (const name of ['__proto__', 'constructor', 'prototype']) {
      await extensionName.fill(name);
      await bodyValue.fill('S-1-6');
      expect(await extensionName.getAttribute('aria-invalid'), `extension name ${name}`).toBe('true');
      expect(await dictionaryView(page, fileId, 'extensions')).toEqual(committed);
    }
    expect(await prototypeSnapshot(page)).toEqual(before);
  });

  test('validation accepts prototype-named dictionary keys but reports them as extension names', async ({ page }) => {
    await openBuilder(page);
    const result = await page.evaluate(() => {
      const safe = (pairs: [string, unknown][]) => {
        const out = Object.create(null);
        pairs.forEach(([k, v]) => { out[k] = v; });
        return out;
      };
      (window as any).addObject('process');
      const process = (window as any).getActiveObject();
      process.environment_variables = safe([['__proto__', 'p'], ['constructor', 'c']]);
      (window as any).addObject('file');
      const file = (window as any).getActiveObject();
      file.name = 'a.exe';
      file.extensions = safe([['__proto__', safe([['sid', 'S-1-5']])]]);
      return { fileId: file.id, issues: (window as any).validateBundle() as string[] };
    });
    expect(result.issues).toEqual([`file ${result.fileId} invalid extensions key`]);
  });

  // The visualizer's selection panel must show dictionaries and external references as text.
  test('the visualizer panel shows objects with dictionaries and external references', async ({ page }) => {
    await openBuilder(page);
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(String(error)));
    const identity = sdo('identity', '5', {
      name: 'i', identity_class: 'individual', external_references: [{ source_name: 'src', url: 'https://example.test/' }],
    });
    const process = sco('process', '6', { environment_variables: protoDictionary() });
    const file = sco('file', '7', { name: 'a.exe', extensions: protoExtension() });
    expect((await uploadBundle(page, [identity, process, file])).toast).toBe('Bundle imported');

    await page.locator('#mode-visualizer').click();
    await page.locator('#visualize-bundle').click();
    await expect(page.locator('#canvas canvas')).toHaveCount(1);
    await expect(page.locator('#canvas-container')).not.toHaveClass(/is-loading/);
    await page.locator('#type-tabs .tab', { hasText: /^All$/ }).click();

    const selection = page.locator('#selection');
    const expected = [
      [identity.id, ['source_name', 'https://example.test/']],
      [process.id, ['__proto__', 'constructor', 'prototype', 'PATH']],
      [file.id, ['ntfs-ext', '__proto__', 'constructor', 'prototype', 'S-1-5']],
    ] as const;
    for (const [id, shown] of expected) {
      await page.locator('#object-list .object-item', { hasText: id }).click();
      await expect.poll(async () => errors.length > 0 || ((await selection.textContent()) || '').includes(id)).toBe(true);
      expect(errors, `selecting ${id}`).toEqual([]);
      for (const text of shown) await expect(selection).toContainText(text);
    }
  });

  // The editor stores '' for structural fields that are not filled in yet: required refs and
  // timestamps of a new object, an added kill-chain or ref row. Import must treat those as
  // absent, as it always has, or the Composer could not reopen its own work in progress.
  test('reimports its own bundle while structural fields are still unfilled', async ({ page }) => {
    await openBuilder(page);
    const add = async (type: string) => {
      await page.locator('#add-type').selectOption(type);
      await page.locator('#add-object').click();
    };
    await add('relationship');
    await add('indicator');
    await add('malware');
    await page.locator('#editor-panel [data-action="add-kc"]').click();
    await add('report');
    await page.locator('#editor-panel [data-action="add-list"][data-list-field="object_refs"]').click();
    await page.locator('#editor-panel [data-action="add-gm"]').click();

    const source = await page.evaluate(() => JSON.parse(JSON.stringify((eval('state') as any).bundle.objects)));
    expect(source.find((o: any) => o.type === 'relationship').source_ref).toBe('');
    expect(source.find((o: any) => o.type === 'malware').kill_chain_phases).toEqual([{ kill_chain_name: 'unified-kill-chain', phase_name: '' }]);
    expect(source.find((o: any) => o.type === 'report').object_refs).toEqual(['']);
    expect(source.find((o: any) => o.type === 'report').granular_markings).toEqual([{ selectors: [], marking_ref: '' }]);

    // Validation reports the unfilled required fields, so export asks before downloading.
    page.once('dialog', (dialog) => dialog.accept());
    const [download] = await Promise.all([page.waitForEvent('download'), page.locator('#export-bundle').click()]);
    const fs = require('node:fs');
    const exported = JSON.parse(fs.readFileSync((await download.path())!, 'utf8'));

    await openBuilder(page);
    const { toast } = await uploadBundle(page, exported.objects);
    expect(toast).toBe('Bundle imported');
    const byType = async (type: string) => objectState(page, source.find((o: any) => o.type === type).id);
    expect(Object.prototype.hasOwnProperty.call(await byType('relationship'), 'source_ref')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(await byType('indicator'), 'valid_from')).toBe(false);
    expect((await byType('malware')).kill_chain_phases).toEqual([]);
    expect((await byType('report')).object_refs).toEqual([]);

    // The unfilled marking row stays so the analyst can finish it, and validation flags it.
    const report = await byType('report');
    expect(report.granular_markings).toEqual([{ selectors: [], marking_ref: '' }]);
    const issues = await page.evaluate(() => (window as any).validateBundle() as string[]);
    expect(issues).toEqual(expect.arrayContaining([
      `report ${report.id} granular_markings entry missing selectors`,
      `report ${report.id} granular_markings entry missing marking_ref`,
    ]));
  });

  test('the editor refuses invalid structural values without relying on typing guards', async ({ page }) => {
    await openBuilder(page);
    // Writing .value and dispatching input is exactly what a user bypassing any keyboard
    // guard can do, so the commit path itself must refuse the value.
    const bypass = (selector: string, value: string) => page.locator(selector).first().evaluate((element, text) => {
      (element as HTMLInputElement).value = text;
      element.dispatchEvent(new Event('input', { bubbles: true }));
    }, value);
    const invalid = (selector: string) => page.locator(selector).first().getAttribute('aria-invalid');

    await page.locator('#add-type').selectOption('process');
    await page.locator('#add-object').click();
    await page.locator('#editor-panel [data-action="add-dict"][data-dict-field="environment_variables"]').click();
    const keyInput = '#editor-panel [data-dict-field="environment_variables"][data-dict-role="key"]';
    const readKeys = () => page.evaluate(() => Object.keys((window as any).getActiveObject().environment_variables || {}));
    const generatedKeys = await readKeys();
    expect(generatedKeys).toHaveLength(1);

    for (const bad of ['BAD[KEY]', 'a"b', 'x'.repeat(251)]) {
      await bypass(keyInput, bad);
      expect(await readKeys(), `dictionary key ${bad.slice(0, 20)} was committed`).toEqual(generatedKeys);
      expect(await invalid(keyInput)).toBe('true');
    }
    await bypass(keyInput, 'GOOD_KEY-1');
    expect(await readKeys()).toEqual(['GOOD_KEY-1']);
    expect(await invalid(keyInput)).toBeNull();

    await page.locator('#add-type').selectOption('identity');
    await page.locator('#add-object').click();
    const readIdentity = () => page.evaluate(() => {
      const object = (window as any).getActiveObject();
      return { created_by_ref: object.created_by_ref ?? null, created: object.created };
    });
    const original = await readIdentity();

    await bypass('#editor-panel [data-field="created_by_ref"]', 'identity--x" onmouseover="1');
    await bypass('#editor-panel [data-field="created"]', 'Jan 1 2026');
    expect(await readIdentity()).toEqual(original);
    expect(await invalid('#editor-panel [data-field="created_by_ref"]')).toBe('true');
    expect(await invalid('#editor-panel [data-field="created"]')).toBe('true');

    const ref = stixId('identity', '6');
    await bypass('#editor-panel [data-field="created_by_ref"]', ref);
    expect((await readIdentity()).created_by_ref).toBe(ref);
    expect(await invalid('#editor-panel [data-field="created_by_ref"]')).toBeNull();

    // One selector per line; every line must be a valid selector or nothing is committed.
    await page.locator('#editor-panel [data-action="add-gm"]').click();
    const selectorBox = '#editor-panel [data-gm-key="selectors"]';
    const readSelectors = () => page.evaluate(() => (window as any).getActiveObject().granular_markings[0].selectors);
    await bypass(selectorBox, 'description\nexternal_references.[0].url');
    expect(await readSelectors()).toEqual(['description', 'external_references.[0].url']);
    await bypass(selectorBox, 'description\nbad]');
    expect(await readSelectors()).toEqual(['description', 'external_references.[0].url']);
    expect(await invalid(selectorBox)).toBe('true');
    await bypass(selectorBox, 'id\nexternal_references.[0].hashes.SHA-256');
    expect(await readSelectors()).toEqual(['id', 'external_references.[0].hashes.SHA-256']);
    expect(await invalid(selectorBox)).toBeNull();
    for (const bad of ['id\nab', 'Description']) {
      await bypass(selectorBox, bad);
      expect(await readSelectors(), `selectors ${bad}`).toEqual(['id', 'external_references.[0].hashes.SHA-256']);
      expect(await invalid(selectorBox)).toBe('true');
    }

    // A leap second is valid only as 23:59:60 on the last day of a month (RFC 3339 section 5.7).
    await bypass('#editor-panel [data-field="created"]', '2026-06-15T23:59:60Z');
    expect((await readIdentity()).created).toBe(original.created);
    expect(await invalid('#editor-panel [data-field="created"]')).toBe('true');
    await bypass('#editor-panel [data-field="created"]', '1990-12-31T23:59:60Z');
    expect((await readIdentity()).created).toBe('1990-12-31T23:59:60Z');
    expect(await invalid('#editor-panel [data-field="created"]')).toBeNull();
  });

  test('validation reports invalid structural values that reached state by another route', async ({ page }) => {
    await openBuilder(page);
    const issues = await page.evaluate(({ tlp }) => {
      (window as any).addObject('identity');
      const object = (window as any).getActiveObject();
      object.name = 'Direct';
      object.created = 'Jan 1 2026';
      object.created_by_ref = 'nope';
      object.granular_markings = [
        { selectors: ['bad]'], marking_ref: tlp },
        { selectors: [], marking_ref: tlp },
        { selectors: ['description'], marking_ref: '' },
      ];
      object.external_references = [{ source_name: 's', hashes: { 'bad key': 'x' } }];
      return (window as any).validateBundle() as string[];
    }, { tlp: TLP });

    const id = await page.evaluate(() => (window as any).getActiveObject().id);
    expect(issues).toEqual(expect.arrayContaining([
      `identity ${id} invalid created timestamp`,
      `identity ${id} invalid created_by_ref`,
      `identity ${id} invalid granular_markings selector`,
      `identity ${id} granular_markings entry missing selectors`,
      `identity ${id} granular_markings entry missing marking_ref`,
      `identity ${id} invalid external_references key`,
    ]));
  });

  async function exportObjects(page: Page) {
    const dialogs: string[] = [];
    const onDialog = (dialog: any) => { dialogs.push(dialog.message()); dialog.accept(); };
    page.on('dialog', onDialog);
    try {
      const [download] = await Promise.all([page.waitForEvent('download'), page.locator('#export-bundle').click()]);
      const exported = JSON.parse(require('node:fs').readFileSync((await download.path())!, 'utf8'));
      return { id: exported.id as string, objects: exported.objects as any[], dialogs };
    } finally {
      page.off('dialog', onDialog);
    }
  }

  // The whole path of a spec-valid value: import, state, clean validation, export and a fresh
  // reimport of that export must all keep it exactly.
  async function expectRoundTrip(page: Page, objects: any[], id: string, expected: Record<string, unknown>) {
    expect((await uploadBundle(page, objects)).toast).toBe('Bundle imported');
    expect(await objectState(page, id)).toMatchObject(expected);
    expect(await page.evaluate(() => (window as any).validateBundle())).toEqual([]);
    const { objects: exported, dialogs } = await exportObjects(page);
    expect(dialogs).toEqual([]);
    expect(exported.find((o) => o.id === id)).toMatchObject(expected);
    await openBuilder(page);
    expect((await uploadBundle(page, exported)).toast).toBe('Bundle imported');
    expect(await objectState(page, id)).toMatchObject(expected);
  }

  const isValid = (page: Page, kind: string, values: string[]) => page.evaluate(
    ({ k, list }) => list.map((v) => [v, (window as any).isValidStructuralValue(k, v)]), { k: kind, list: values },
  );

  // Selector components are property names, dictionary keys (letters, digits, '-', '_') or
  // [n] list indexes; the first names a property: 3-250 lowercase characters, or 'id'
  // (STIX 2.1 sections 7.2.3.1, 2.3 and 3.1).
  test('the selector grammar follows STIX 2.1', async ({ page }) => {
    await openBuilder(page);
    const valid = [
      'id', 'description', 'labels.[0]', 'hashes.SHA-256', 'x_acme_org_scoring.score',
      `extensions.${stixId('extension-definition', 'd')}.rank`, 'external_references.[0].hashes.SHA-256',
      'environment_variables.X', 'a'.repeat(250),
    ];
    const invalid = [
      'ab', 'Description', '1abc', '_abc', 'labels.', '.labels', 'labels..x', 'labels.[x]', 'labels.[-1]',
      'labels.a b', 'description]', '', 'a'.repeat(251), `labels.${'k'.repeat(251)}`,
    ];
    expect(await isValid(page, 'selector', [...valid, ...invalid]))
      .toEqual([...valid.map((v) => [v, true]), ...invalid.map((v) => [v, false])]);
  });

  test('keeps spec-valid selectors through import, export and reimport', async ({ page }) => {
    await openBuilder(page);
    const selectors = ['id', 'description', 'external_references.[0].hashes.SHA-256', 'external_references.[0].url'];
    const identity = sdo('identity', '1', {
      name: 'i', identity_class: 'individual', description: 'd',
      external_references: [{ source_name: 'src', url: 'https://example.test/', hashes: { 'SHA-256': 'ab' } }],
      granular_markings: [{ selectors, marking_ref: TLP }],
    });
    await expectRoundTrip(page, [identity], identity.id, { granular_markings: [{ selectors, marking_ref: TLP }] });
  });

  // STIX 2.1 section 2.11 only says kill-chain values SHOULD be lowercase and hyphenated, so
  // any other text is kept exactly as imported.
  test('keeps kill-chain names and phases as free text through import, export and reimport', async ({ page }) => {
    await openBuilder(page);
    const phases = [
      { kill_chain_name: 'Acme Kill Chain', phase_name: 'Initial Access' },
      { kill_chain_name: 'mitre_attack', phase_name: 'Initial Access' },
      { kill_chain_name: 'Mitre Attack', phase_name: 'exec[ution]' },
      { kill_chain_name: 'mitre-attack', phase_name: HOSTILE },
    ];
    const malware = sdo('malware', '2', { name: 'm', is_family: false, kill_chain_phases: phases });
    await expectRoundTrip(page, [malware], malware.id, { kill_chain_phases: phases });
  });

  // RFC 3339, which STIX 2.1 section 2.16 requires, allows a leap second as 23:59:60 at the
  // end of a month (RFC 3339 sections 5.6 to 5.8).
  test('keeps leap-second timestamps through import, export and reimport', async ({ page }) => {
    await openBuilder(page);
    const identity = { ...sdo('identity', '3', { name: 'i', identity_class: 'individual' }), created: '1990-12-31T23:59:60Z', modified: '1998-12-31T23:59:60.25Z' };
    await expectRoundTrip(page, [identity], identity.id, { created: '1990-12-31T23:59:60Z', modified: '1998-12-31T23:59:60.25Z' });
  });

  test('the timestamp grammar allows a leap second only at the end of a month', async ({ page }) => {
    await openBuilder(page);
    const valid = [
      '1990-12-31T23:59:60Z', '1972-06-30T23:59:60Z', '1998-12-31T23:59:60.25Z', '2024-02-29T23:59:60Z',
      '2023-02-28T23:59:60Z', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00.123456Z',
    ];
    const invalid = [
      '2026-06-15T23:59:60Z', '2024-02-28T23:59:60Z', '2016-12-31T12:00:60Z', '2016-12-31T23:58:60Z',
      '2016-12-31T23:59:61Z', '2016-12-31T23:59:60+00:00', '2016-12-31T23:59:60.Z', '2026-02-30T00:00:00Z',
    ];
    expect(await isValid(page, 'timestamp', [...valid, ...invalid]))
      .toEqual([...valid.map((v) => [v, true]), ...invalid.map((v) => [v, false])]);
  });

  // Browsers cannot represent 23:59:60, so the timeline must still render and order it.
  test('the visualizer timeline renders and orders a leap second', async ({ page }) => {
    await openBuilder(page);
    const errors: string[] = [];
    const dialogs: string[] = [];
    page.on('pageerror', (error) => errors.push(String(error)));
    page.on('dialog', (dialog) => { dialogs.push(dialog.message()); dialog.accept(); });
    const before = { ...sdo('identity', '4', { name: 'before', identity_class: 'individual' }), modified: '1990-12-31T23:59:59Z' };
    const leap = { ...sdo('identity', '5', { name: 'leap', identity_class: 'individual' }), created: '1990-12-31T23:59:59Z', modified: '1990-12-31T23:59:60Z' };
    expect((await uploadBundle(page, [before, leap])).toast).toBe('Bundle imported');

    await page.locator('#mode-visualizer').click();
    await page.locator('#visualize-bundle').click();
    await expect(page.locator('#canvas canvas')).toHaveCount(1);
    await expect(page.locator('#canvas-container')).not.toHaveClass(/is-loading/);
    expect(errors).toEqual([]);
    expect(dialogs).toEqual([]);
    const label = page.locator('label[for="timeline"]');
    await expect(label).toHaveText('Timeline: 1990-12-31T23:59:59.999Z');
    await page.locator('#timeline').evaluate((slider) => {
      (slider as HTMLInputElement).value = '0';
      slider.dispatchEvent(new Event('input', { bubbles: true }));
      slider.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await expect(label).toHaveText('Timeline: 1990-12-31T23:59:59.000Z');
    expect(errors).toEqual([]);
  });

  test('validation reports kill-chain values, selectors and timestamps that break the grammar', async ({ page }) => {
    await openBuilder(page);
    const result = await page.evaluate(({ tlp }) => {
      const add = (type: string, fields: Record<string, unknown>) => {
        (window as any).addObject(type);
        const object = (window as any).getActiveObject();
        Object.assign(object, fields);
        return object.id;
      };
      const ids = {
        control: add('malware', { name: 'm', is_family: false, kill_chain_phases: [{ kill_chain_name: 'acme\u0001chain', phase_name: 'x' }] }),
        blank: add('malware', { name: 'm', is_family: false, kill_chain_phases: [{ kill_chain_name: 'acme', phase_name: ' \t ' }] }),
        long: add('malware', { name: 'm', is_family: false, kill_chain_phases: [{ kill_chain_name: 'k'.repeat(5001), phase_name: 'x' }] }),
        short: add('identity', { name: 'i', identity_class: 'individual', granular_markings: [{ selectors: ['ab'], marking_ref: tlp }] }),
        upper: add('identity', { name: 'i', identity_class: 'individual', granular_markings: [{ selectors: ['Description'], marking_ref: tlp }] }),
        leap: add('identity', { name: 'i', identity_class: 'individual', created: '2026-06-15T23:59:60Z' }),
      };
      return { ids, issues: (window as any).validateBundle() as string[] };
    }, { tlp: TLP });
    const { ids, issues } = result;
    expect(issues).toEqual(expect.arrayContaining([
      `malware ${ids.control} invalid kill_chain_phases kill chain value`,
      `malware ${ids.blank} invalid kill_chain_phases kill chain value`,
      `malware ${ids.long} invalid kill_chain_phases kill chain value`,
      `identity ${ids.short} invalid granular_markings selector`,
      `identity ${ids.upper} invalid granular_markings selector`,
      `identity ${ids.leap} invalid created timestamp`,
    ]));
  });

  // Kill-chain values are data: names such as constructor or __proto__ must not be looked up
  // on the prototype of the configuration object.
  for (const name of ['constructor', '__proto__', 'toString']) {
    test(`opens the editor for an object whose kill chain is named ${name}`, async ({ page }) => {
      await openBuilder(page);
      const errors: string[] = [];
      page.on('pageerror', (error) => errors.push(String(error)));
      const malware = sdo('malware', '6', { name: 'm', is_family: false, kill_chain_phases: [{ kill_chain_name: name, phase_name: 'execution' }] });
      expect((await uploadBundle(page, [malware])).toast).toBe('Bundle imported');
      await page.locator('#object-list .object-item', { hasText: malware.id }).click();
      const selects = page.locator('#editor-panel select[data-kc-field="kill_chain_phases"]');
      await expect(selects).toHaveCount(2);
      expect(await selects.evaluateAll((list) => list.map((s) => (s as HTMLSelectElement).value))).toEqual([name, 'execution']);
      expect(errors).toEqual([]);
    });
  }

  // A kill chain or phase that the configuration does not list is shown as stored, so the
  // editor neither misrepresents it nor overwrites it when its select commits (an input event).
  test('shows a kill chain missing from the configuration as stored and keeps it when its selects commit', async ({ page }) => {
    await openBuilder(page);
    await page.evaluate(() => { (window as any).__evidenceCanary = 0; });
    const phases = [{ kill_chain_name: 'mitre-attack', phase_name: 'execution' }, { kill_chain_name: 'unified-kill-chain', phase_name: HOSTILE }];
    const malware = sdo('malware', '7', { name: 'm', is_family: false, kill_chain_phases: phases });
    expect((await uploadBundle(page, [malware])).toast).toBe('Bundle imported');
    await page.locator('#object-list .object-item', { hasText: malware.id }).click();

    const selects = page.locator('#editor-panel select[data-kc-field="kill_chain_phases"]');
    expect(await selects.evaluateAll((list) => list.map((s) => (s as HTMLSelectElement).value)))
      .toEqual(['mitre-attack', 'execution', 'unified-kill-chain', HOSTILE]);
    expect(await page.locator('#editor-panel img').count()).toBe(0);
    expect(await page.evaluate(() => (window as any).__evidenceCanary)).toBe(0);

    await page.locator('#editor-panel [data-field="name"]').fill('m2');
    for (const index of [0, 1, 2, 3]) {
      await selects.nth(index).evaluate((select) => select.dispatchEvent(new Event('input', { bubbles: true })));
    }
    expect((await objectState(page, malware.id)).kill_chain_phases).toEqual(phases);
  });

  // Hash keys need 3 to 250 characters (STIX 2.1 section 2.7); other dictionary keys have no
  // minimum (section 2.3).
  test('hash keys need at least three characters, other dictionary keys do not', async ({ page }) => {
    await openBuilder(page);
    const file = sco('file', '8', { name: 'a.exe', hashes: { 'SHA-256': 'ab', MD5: 'cd', x_foo_hash: 'ef' } });
    const identity = sdo('identity', '9', { name: 'i', identity_class: 'individual', external_references: [{ source_name: 's', hashes: { SHA3: 'aa' } }] });
    const process = sco('process', 'a', { environment_variables: { ab: 'x', Z: 'y' } });
    expect((await uploadBundle(page, [file, identity, process])).toast).toBe('Bundle imported');
    expect((await objectState(page, file.id)).hashes).toEqual({ 'SHA-256': 'ab', MD5: 'cd', x_foo_hash: 'ef' });
    expect((await objectState(page, identity.id)).external_references[0].hashes).toEqual({ SHA3: 'aa' });
    expect((await objectState(page, process.id)).environment_variables).toEqual({ ab: 'x', Z: 'y' });
    expect(await page.evaluate(() => (window as any).validateBundle())).toEqual([]);

    const issues = await page.evaluate(({ fileId, identityId }) => {
      const appState = eval('state');
      appState.objectsById.get(fileId).hashes = { MD: 'x' };
      appState.objectsById.get(identityId).external_references[0].hashes = { MD: 'x' };
      return (window as any).validateBundle() as string[];
    }, { fileId: file.id, identityId: identity.id });
    expect(issues).toEqual([`file ${file.id} invalid hashes key`, `identity ${identity.id} invalid external_references key`]);
  });

  test('the editor refuses hash keys shorter than three characters', async ({ page }) => {
    await openBuilder(page);
    const bypass = (selector: string, value: string) => page.locator(selector).first().evaluate((element, text) => {
      (element as HTMLInputElement).value = text;
      element.dispatchEvent(new Event('input', { bubbles: true }));
    }, value);
    const readActive = (field: string) => page.evaluate((key) => JSON.parse(JSON.stringify((window as any).getActiveObject()[key] ?? null)), field);

    await page.locator('#add-type').selectOption('file');
    await page.locator('#add-object').click();
    await page.locator('#editor-panel [data-action="add-hash"][data-hash-field="hashes"]').click();
    const hashKey = '#editor-panel [data-hash-field="hashes"][data-hash-role="key"]';
    const generated = await readActive('hashes');
    await bypass(hashKey, 'MD');
    expect(await readActive('hashes')).toEqual(generated);
    expect(await page.locator(hashKey).getAttribute('aria-invalid')).toBe('true');
    await bypass(hashKey, 'SHA-256');
    expect(Object.keys(await readActive('hashes'))).toEqual(['SHA-256']);

    await page.locator('#add-type').selectOption('identity');
    await page.locator('#add-object').click();
    await page.locator('#editor-panel [data-action="add-ref"]').click();
    await page.locator('#editor-panel [data-action="add-refhash"]').click();
    const refHashKey = '#editor-panel [data-refhash-role="key"]';
    const generatedRef = (await readActive('external_references'))[0].hashes;
    await bypass(refHashKey, 'MD');
    expect((await readActive('external_references'))[0].hashes).toEqual(generatedRef);
    expect(await page.locator(refHashKey).getAttribute('aria-invalid')).toBe('true');
    await bypass(refHashKey, 'MD5');
    expect(Object.keys((await readActive('external_references'))[0].hashes)).toEqual(['MD5']);
  });

  // STIX 2.1 section 2.9 requires an RFC 4122 UUID, whose hex digits are case insensitive on
  // input (RFC 4122 section 3); the type prefix is a type name and always lowercase.
  test('the identifier grammar accepts uppercase UUID hex but not an uppercase type prefix', async ({ page }) => {
    await openBuilder(page);
    const valid = [
      'indicator--f81d4fae-7dec-11d0-a765-00a0c91e6bf6', 'indicator--F81D4FAE-7DEC-11D0-A765-00A0C91E6BF6',
      'indicator--f81D4fae-7DEC-11d0-A765-00a0c91e6Bf6', 'indicator--00000000-0000-0000-0000-000000000000',
      'x-acme-widget--F81D4FAE-7DEC-11D0-A765-00A0C91E6BF6',
    ];
    const invalid = [
      'Indicator--f81d4fae-7dec-11d0-a765-00a0c91e6bf6', 'INDICATOR--F81D4FAE-7DEC-11D0-A765-00A0C91E6BF6',
      'indicator--F81D4FAE7DEC11D0A76500A0C91E6BF6', 'indicator--G81D4FAE-7DEC-11D0-A765-00A0C91E6BF6', '',
    ];
    expect(await isValid(page, 'identifier', [...valid, ...invalid]))
      .toEqual([...valid.map((v) => [v, true]), ...invalid.map((v) => [v, false])]);
  });

  // Uppercase UUID hex in ids and refs is accepted and stored lowercase, so a ref still finds
  // its object; the import reports how many values were lowercased.
  test('imports uppercase UUID hex in ids and refs, stores and exports them lowercase', async ({ page }) => {
    await openBuilder(page);
    const marking = sdo('marking-definition', 'F', { definition_type: 'tlp', definition: { tlp: 'white' } });
    const author = sdo('identity', 'A', {
      name: 'Author', identity_class: 'organization', object_marking_refs: [marking.id],
      granular_markings: [{ selectors: ['name'], marking_ref: marking.id }],
    });
    const target = sdo('identity', 'B', { name: 'Target', identity_class: 'organization', created_by_ref: author.id });
    const link = sdo('relationship', 'C', { relationship_type: 'related-to', source_ref: target.id, target_ref: author.id });
    const lower = {
      bundle: stixId('bundle', 'e'), marking: stixId('marking-definition', 'f'),
      author: stixId('identity', 'a'), target: stixId('identity', 'b'), link: stixId('relationship', 'c'),
    };
    const expected = {
      [lower.author]: { object_marking_refs: [lower.marking], granular_markings: [{ selectors: ['name'], marking_ref: lower.marking }] },
      [lower.target]: { created_by_ref: lower.author },
      [lower.link]: { source_ref: lower.target, target_ref: lower.author },
    };

    // 4 object ids, 5 refs and the bundle id.
    const { toast } = await uploadBundle(page, [marking, author, target, link], stixId('bundle', 'E'));
    expect(toast).toBe('Bundle imported, 10 identifiers lowercased');
    expect(await page.evaluate(() => (eval('state') as any).bundle.id)).toBe(lower.bundle);
    for (const [id, props] of Object.entries(expected)) expect(await objectState(page, id)).toMatchObject(props);
    expect(await page.evaluate(() => (window as any).validateBundle())).toEqual([]);

    const exported = await exportObjects(page);
    expect(exported.dialogs).toEqual([]);
    expect(exported.id).toBe(lower.bundle);
    expect(exported.objects.map((o) => o.id)).toEqual([lower.marking, lower.author, lower.target, lower.link]);
    for (const [id, props] of Object.entries(expected)) expect(exported.objects.find((o) => o.id === id)).toMatchObject(props);

    await openBuilder(page);
    expect((await uploadBundle(page, exported.objects)).toast).toBe('Bundle imported');
    for (const [id, props] of Object.entries(expected)) expect(await objectState(page, id)).toMatchObject(props);

    // The type prefix is still lowercase only: in a ref it rejects the file, and an object
    // whose id carries it is not imported.
    const mixedRef = sdo('identity', 'd', { name: 'd', identity_class: 'individual', created_by_ref: 'Identity--' + lower.author.split('--')[1] });
    expect((await uploadBundle(page, [mixedRef])).toast).toBe('Import failed: object 1 created_by_ref is invalid');
    const plain = sdo('identity', 'd', { name: 'd', identity_class: 'individual' });
    const mixedId = { ...sdo('identity', 'e', { name: 'e', identity_class: 'individual' }), id: 'Identity--' + stixId('identity', 'e').split('--')[1] };
    expect((await uploadBundle(page, [plain, mixedId])).toast).toBe('Bundle imported');
    expect(await page.evaluate(() => (eval('state') as any).bundle.objects.map((o: any) => o.id))).toEqual([plain.id]);
  });

  test('the editor commits uppercase UUID hex lowercased and refuses an uppercase type prefix', async ({ page }) => {
    await openBuilder(page);
    const bypass = (selector: string, value: string) => page.locator(selector).first().evaluate((element, text) => {
      (element as HTMLInputElement).value = text;
      element.dispatchEvent(new Event('input', { bubbles: true }));
    }, value);
    const field = (selector: string) => page.locator(selector).first();
    const readActive = () => page.evaluate(() => JSON.parse(JSON.stringify((window as any).getActiveObject())));

    await page.locator('#add-type').selectOption('identity');
    await page.locator('#add-object').click();
    const idInput = '#editor-panel [data-field="id"]';
    const refInput = '#editor-panel [data-field="created_by_ref"]';

    // The field is rewritten to the stored lowercase form, so it shows what will be exported.
    await bypass(idInput, stixId('identity', 'B'));
    expect((await readActive()).id).toBe(stixId('identity', 'b'));
    expect(await page.evaluate((id) => (eval('state') as any).objectsById.has(id), stixId('identity', 'b'))).toBe(true);
    await expect(field(idInput)).toHaveValue(stixId('identity', 'b'));
    await expect(field(idInput)).not.toHaveAttribute('aria-invalid');
    // Overtyping one digit mid-id keeps the caret there, so the next keystroke lands in place.
    await field(idInput).evaluate((element) => { (element as HTMLInputElement).focus(); (element as HTMLInputElement).setSelectionRange(10, 11); });
    await page.keyboard.type('C');
    await expect(field(idInput)).toHaveValue(`identity--c${'b'.repeat(7)}-bbbb-4bbb-8bbb-${'b'.repeat(12)}`);
    expect(await field(idInput).evaluate((element) => (element as HTMLInputElement).selectionStart)).toBe(11);

    await bypass(refInput, stixId('identity', 'A'));
    expect((await readActive()).created_by_ref).toBe(stixId('identity', 'a'));
    await expect(field(refInput)).toHaveValue(stixId('identity', 'a'));
    await bypass(refInput, 'Identity--' + stixId('identity', 'c').split('--')[1]);
    expect((await readActive()).created_by_ref).toBe(stixId('identity', 'a'));
    await expect(field(refInput)).toHaveAttribute('aria-invalid', 'true');

    await page.locator('#editor-panel [data-action="add-list"][data-list-field="object_marking_refs"]').click();
    const listInput = '#editor-panel [data-list-field="object_marking_refs"][data-index="0"]';
    await bypass(listInput, stixId('marking-definition', 'F'));
    expect((await readActive()).object_marking_refs).toEqual([stixId('marking-definition', 'f')]);
    await expect(field(listInput)).toHaveValue(stixId('marking-definition', 'f'));

    await page.locator('#editor-panel [data-action="add-gm"]').click();
    const gmInput = '#editor-panel [data-gm-key="marking_ref"]';
    await bypass(gmInput, stixId('marking-definition', 'F'));
    expect((await readActive()).granular_markings[0].marking_ref).toBe(stixId('marking-definition', 'f'));
    await expect(field(gmInput)).toHaveValue(stixId('marking-definition', 'f'));
  });

  // An extension key that is an extension-definition id must match that definition's id
  // (STIX 2.1 section 7.3), so it is lowercased like the id. Keys that differ only in case would
  // then clash (section 2.3), so they are kept as written and the import says so.
  test('lowercases extension keys that are extension-definition ids and keeps keys that differ only in case', async ({ page }) => {
    await openBuilder(page);
    const extUpper = stixId('extension-definition', 'D');
    const extLower = stixId('extension-definition', 'd');
    const mixedPrefix = 'Extension-Definition--' + extUpper.split('--')[1];
    const definition = sdo('extension-definition', 'D', {
      name: 'rank', description: 'd', schema: 'https://example.com/schema.json', version: '1.0', extension_types: ['property-extension'],
    });
    const fileOne = sco('file', '1', { name: 'a.exe', extensions: {
      [extUpper]: { extension_type: 'property-extension', rank: '5' }, 'ntfs-ext': { sid: 'S-1' }, 'x-acme-EXT': { a: 'b' }, [mixedPrefix]: { m: 'n' },
    } });
    const clashA = stixId('extension-definition', 'E');
    const clashB = stixId('extension-definition', 'e');
    const fileTwo = sco('file', '2', { name: 'b.exe', extensions: { [clashA]: { v: '1' }, [clashB]: { v: '2' }, [extUpper]: { v: '3' } } });
    const keysOf = (objects: any[], id: string) => Object.keys(objects.find((o) => o.id === id).extensions);
    const expectedOne = [extLower, 'ntfs-ext', 'x-acme-EXT', mixedPrefix];
    const expectedTwo = [clashA, clashB, extLower];

    // The definition's id and one key in each file are lowercased; both clashing keys are kept.
    const { toast } = await uploadBundle(page, [definition, fileOne, fileTwo]);
    expect(toast).toBe('Bundle imported, 3 identifiers lowercased, 2 extension keys kept as written (they differ only in case)');
    expect(Object.keys((await objectState(page, fileOne.id)).extensions)).toEqual(expectedOne);
    expect(Object.keys((await objectState(page, fileTwo.id)).extensions)).toEqual(expectedTwo);
    expect((await objectState(page, fileTwo.id)).extensions[clashB]).toEqual({ v: '2' });
    expect(await objectState(page, extLower)).toMatchObject({ name: 'rank' });
    expect(await page.evaluate(() => (window as any).validateBundle())).toEqual([]);

    const exported = await exportObjects(page);
    expect(keysOf(exported.objects, fileOne.id)).toEqual(expectedOne);
    expect(keysOf(exported.objects, fileTwo.id)).toEqual(expectedTwo);
    await openBuilder(page);
    expect((await uploadBundle(page, exported.objects)).toast)
      .toBe('Bundle imported, 2 extension keys kept as written (they differ only in case)');
    expect(Object.keys((await objectState(page, fileTwo.id)).extensions)).toEqual(expectedTwo);
  });

  test('the editor lowercases an extension-definition id used as an extension key unless it clashes', async ({ page }) => {
    await openBuilder(page);
    const readKeys = () => page.evaluate(() => Object.keys((window as any).getActiveObject().extensions || {}));
    await page.locator('#add-type').selectOption('file');
    await page.locator('#add-object').click();
    await page.locator('#editor-panel [data-action="add-ext"][data-ext-field="extensions"]').click();
    await page.locator('#editor-panel [data-action="add-extdict"]').first().click();
    // An extension name is committed together with its body, so each name change is
    // followed by an edit inside the extension.
    const names = page.locator('#editor-panel [data-ext-field="extensions"][data-ext-role="key"]');
    const bodies = page.locator('#editor-panel [data-extdict-role="value"]');
    await names.nth(0).fill(stixId('extension-definition', 'D'));
    await bodies.nth(0).fill('5');
    expect(await readKeys()).toEqual([stixId('extension-definition', 'd')]);
    await expect(names.nth(0)).toHaveValue(stixId('extension-definition', 'd'));

    await page.locator('#editor-panel [data-action="add-ext"][data-ext-field="extensions"]').click();
    await page.locator('#editor-panel [data-action="add-extdict"]').nth(1).click();
    await names.nth(1).fill(stixId('extension-definition', 'D'));
    await bodies.nth(1).fill('6');
    expect(await readKeys()).toEqual([stixId('extension-definition', 'd'), stixId('extension-definition', 'D')]);
    await expect(names.nth(1)).toHaveValue(stixId('extension-definition', 'D'));
    await expect(names.nth(1)).not.toHaveAttribute('aria-invalid');

    // While another name is invalid nothing is committed, so no field is rewritten either.
    await page.locator('#editor-panel [data-action="add-ext"][data-ext-field="extensions"]').click();
    await page.locator('#editor-panel [data-action="add-extdict"]').nth(2).click();
    await names.nth(2).fill('bad key');
    await names.nth(0).fill(stixId('extension-definition', 'F'));
    await bodies.nth(0).fill('7');
    expect((await readKeys()).slice(0, 2)).toEqual([stixId('extension-definition', 'd'), stixId('extension-definition', 'D')]);
    await expect(names.nth(0)).toHaveValue(stixId('extension-definition', 'F'));

    // Removing one of two clashing names leaves the other free to be stored lowercase.
    await page.locator('#editor-panel [data-action="remove-ext"][data-ext-field="extensions"]').nth(2).click();
    await page.locator('#editor-panel [data-action="remove-ext"][data-ext-field="extensions"]').nth(0).click();
    expect(await readKeys()).toEqual([stixId('extension-definition', 'd')]);
    await expect(names.nth(0)).toHaveValue(stixId('extension-definition', 'd'));
  });

  // An object type is supported only if the configuration defines it as its own entry;
  // 'constructor' is a valid custom type name (STIX 2.1 section 11.2.1), not a supported one.
  test('does not treat an object of type constructor as a supported type', async ({ page }) => {
    await openBuilder(page);
    const identity = sdo('identity', 'b', { name: 'i', identity_class: 'individual' });
    const custom = sdo('constructor', 'c', { name: 'c' });
    expect((await uploadBundle(page, [identity, custom])).toast).toBe('Bundle imported');
    await page.locator('#type-tabs .tab', { hasText: /^All$/ }).click();
    await expect(page.locator('#object-list')).toContainText(identity.id);
    await expect(page.locator('#object-list')).not.toContainText(custom.id);
    expect(await page.evaluate(() => ['constructor', 'toString', '__proto__', 'hasOwnProperty']
      .map((type) => (window as any).getStixObjectDefinition(type)))).toEqual([null, null, null, null]);

    const issues = await page.evaluate((object) => {
      eval('state').bundle.objects.push(object);
      return (window as any).validateBundle() as string[];
    }, custom);
    expect(issues).toContain('Unknown object type: constructor');
  });
});
