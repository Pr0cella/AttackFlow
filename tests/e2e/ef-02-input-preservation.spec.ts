import { expect, test, type Page } from '@playwright/test';
import { exportNative } from './helpers/roundtrip';

const indicatorId = 'indicator--11111111-1111-4111-8111-111111111111';
const groupingId = 'grouping--22222222-2222-4222-8222-222222222222';

async function openApp(page: Page) {
  await page.route('**/*', route => {
    const hostname = new URL(route.request().url()).hostname;
    return hostname === '127.0.0.1' || hostname === 'localhost'
      ? route.continue()
      : route.abort();
  });
  await page.goto('/index.html');
  await expect(page.locator('#loading')).toHaveClass(/hidden/, { timeout: 60_000 });
}

async function importKillChain(page: Page, payload: unknown) {
  await page.locator('#import-killchain-input').setInputFiles({
    name: 'ef-02-kill-chain.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(payload), 'utf8'),
  });
  await expect(page.locator('#toast')).toContainText('Imported kill chain');
}

async function importStixBundle(page: Page, payload: unknown) {
  await page.locator('input[onchange="importStixBundle(event)"]').setInputFiles({
    name: 'ef-02-stix-bundle.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(payload), 'utf8'),
  });
  await expect(page.locator('#toast')).toContainText('Imported 1 STIX object');
}

async function readJsonDownload(page: Page) {
  // Reuses the shared export helper, which drives the real menu control rather than
  // calling exportJSON() directly, so an unwired control fails this suite too.
  return (await exportNative(page)).json;
}

test.beforeEach(async ({ page }) => {
  await openApp(page);
});

test('kill-chain import preserves printable evidence and outer JSON customLibrary values', async ({ page }) => {
  const title = 'Case ---- "quoted" [alpha] {beta}; `tick` & <title> \\path';
  const description = 'Description -- [] {}; "quotes" `ticks` & <evidence> \\server';
  const comments = 'Comment </textarea><script>window.__ef02Executed=true</script> -- evidence';
  const linkLabel = 'Reference -- "A" <label> & literal';
  const linkUrl = 'https://example.com/a--b?q=one&next=two';
  const observable = 'artifact -- [x] {y}; "z" `t` & <raw> \\value';
  const pattern = "[(file:name = 'a\\\\b') AND file:size < 10 OR file:size > 20]";
  const literalEntity = '&lt;script&gt;literal&lt;/script&gt;';
  const reference = 'indicator--33333333-3333-4333-8333-333333333333';

  await page.evaluate(() => {
    (window as any).__ef02Executed = false;
  });
  await importKillChain(page, {
    schema: 'killchain-export-lite',
    title: `  ${title}  `,
    description: `  ${description}  `,
    assignments: {
      'IN:reconnaissance': {
        techniques: [{
          id: 'T1595',
          instanceId: 'itm-ef02-import',
          metadata: {
            comments,
            hyperlinks: [{ label: linkLabel, url: linkUrl }],
            observables: [{ type: 'other', value: observable }],
          },
        }],
        capecs: [],
        cwes: [],
        customItems: [{ id: indicatorId, instanceId: 'itm-ef02-indicator' }],
        groups: [{
          groupId: 'grp-ef02-1',
          label: 'Group -- "quoted" <name>',
          items: [],
        }],
        layout: [],
      },
    },
    customLibrary: {
      [indicatorId]: {
        id: indicatorId,
        stixType: 'indicator',
        name: 'Indicator -- "quoted" <name>',
        description: literalEntity,
        labels: ['label--one', 'label "two" <three>'],
        pattern,
        pattern_type: 'stix',
        valid_from: '2026-01-01T00:00:00.000Z',
      },
      [groupingId]: {
        id: groupingId,
        stixType: 'grouping',
        name: 'Grouping -- evidence',
        context: 'suspicious-activity',
        object_refs: [reference],
      },
    },
  });

  const stored = await page.evaluate(({ indicatorId, groupingId }) => {
    const appState = eval('state');
    const assignment = appState.assignments['IN:reconnaissance'].techniques[0];
    return {
      title: appState.title,
      description: appState.description,
      metadata: assignment.metadata,
      indicator: appState.library.custom[indicatorId],
      grouping: appState.library.custom[groupingId],
      executed: (window as any).__ef02Executed,
    };
  }, { indicatorId, groupingId });

  expect(stored.title).toBe(title);
  expect(stored.description).toBe(description);
  expect(stored.metadata.comments).toBe(comments);
  expect(stored.metadata.hyperlinks).toEqual([{ label: linkLabel, url: linkUrl }]);
  expect(stored.metadata.observables).toEqual([{ type: 'other', value: observable }]);
  expect(stored.indicator.pattern).toBe(pattern);
  expect(stored.indicator.description).toBe(literalEntity);
  expect(stored.grouping.object_refs).toEqual([reference]);
  expect(stored.executed).toBe(false);
  await expect(page.locator('#kill-chain-title')).toHaveValue(title);
  await expect(page.locator('#kc-desc-textarea')).toHaveValue(description);
  await expect(page.locator('.tag-comment-content').first()).toHaveText(comments);
  await expect(page.locator('[data-ef02-injected], #ef02-injected')).toHaveCount(0);

  const exported = await readJsonDownload(page);
  expect(exported.title).toBe(title);
  expect(exported.description).toBe(description);
  expect(exported.customLibrary[indicatorId].pattern).toBe(pattern);
  expect(exported.customLibrary[indicatorId].description).toBe(literalEntity);
  expect(exported.customLibrary[groupingId].object_refs).toEqual([reference]);
});

test('STIX bundle import and editor rendering preserve hostile-looking values as inert data', async ({ page }) => {
  const name = 'Indicator -- "quoted" <name> & literal';
  const description = 'Description </textarea><img data-ef02-injected src=x onerror="window.__ef02Executed=true"> -- end';
  const pattern = "[(file:name = 'a\\\\b') AND file:size < 10 OR file:size > 20]";
  const label = '&lt;img src=x onerror=alert(1)&gt;';

  await page.evaluate(() => {
    (window as any).__ef02Executed = false;
  });
  await importStixBundle(page, {
    type: 'bundle',
    id: 'bundle--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    objects: [{
      type: 'indicator',
      spec_version: '2.1',
      id: indicatorId,
      created: '2026-01-01T00:00:00.000Z',
      modified: '2026-01-01T00:00:00.000Z',
      name,
      description,
      labels: [label],
      pattern,
      pattern_type: 'stix',
      valid_from: '2026-01-01T00:00:00.000Z',
    }],
  });

  const customCard = page.locator('.entity-item.custom').filter({ hasText: name });
  await expect(customCard).toHaveCount(1);
  await expect(customCard).toHaveAttribute('title', description);
  await expect(page.locator('[data-ef02-injected]')).toHaveCount(0);

  await page.evaluate(id => (window as any).openStixEditor(id), indicatorId);
  await expect(page.locator('#stix-edit-name')).toHaveValue(name);
  await expect(page.locator('#stix-edit-description')).toHaveValue(description);
  await expect(page.locator('#stix-edit-labels')).toHaveValue(label);
  await expect(page.locator('#stix-edit-pattern')).toHaveValue(pattern);
  await expect(page.locator('[data-ef02-injected]')).toHaveCount(0);

  await page.evaluate(id => (window as any).openEntityModal('custom', id), indicatorId);
  await expect(page.locator('#entity-modal-name')).toHaveText(name);
  await expect(page.locator('#entity-modal-content')).toContainText(description);
  expect(await page.evaluate(() => (window as any).__ef02Executed)).toBe(false);
});

test('typing, selection replacement, paste, drop, and input guards preserve punctuation', async ({ page }) => {
  const typed = 'Typed -- "quote" [x] {y}; `tick` & <tag> \\path';
  const title = page.locator('#kill-chain-title');
  await title.click();
  await title.pressSequentially(typed);
  await title.blur();
  await expect(title).toHaveValue(typed);
  expect(await page.evaluate(() => eval('state').title)).toBe(typed);

  await title.fill('start END finish');
  await title.evaluate((element: HTMLInputElement) => element.setSelectionRange(6, 9));
  const replacement = '--"[]{};`<>&\\';
  await title.pressSequentially(replacement);
  await expect(title).toHaveValue(`start ${replacement} finish`);

  const pasted = 'paste -- "[]{};`<>&\\';
  const pasteResult = await title.evaluate((element: HTMLInputElement, value) => {
    element.value = 'beforeAFTER';
    element.setSelectionRange(6, 11);
    const transfer = new DataTransfer();
    transfer.setData('text', value + '\u0000');
    const event = new ClipboardEvent('paste', { bubbles: true, cancelable: true, clipboardData: transfer });
    return { dispatched: element.dispatchEvent(event), value: element.value };
  }, pasted);
  expect(pasteResult.dispatched).toBe(false);
  expect(pasteResult.value).toBe(`before${pasted}`);

  const dropped = 'drop -- "[]{};`<>&\\';
  const description = page.locator('#kc-desc-textarea');
  const dropResult = await description.evaluate((element: HTMLTextAreaElement, value) => {
    element.value = 'leftRIGHT';
    element.setSelectionRange(4, 9);
    const transfer = new DataTransfer();
    transfer.setData('text', value + '\u0001');
    const event = new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: transfer });
    return { dispatched: element.dispatchEvent(event), value: element.value };
  }, dropped);
  expect(dropResult.dispatched).toBe(false);
  expect(dropResult.value).toBe(`left${dropped}`);

  const inputResult = await description.evaluate((element: HTMLTextAreaElement) => {
    element.value = 'input -- "[]{};`<>&\\\u0002kept';
    element.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText' }));
    return element.value;
  });
  expect(inputResult).toBe('input -- "[]{};`<>&\\kept');
});

test('STIX editor save and reopen preserve representative scalar and list fields', async ({ page }) => {
  await page.evaluate(({ indicatorId }) => {
    eval('state').library.custom[indicatorId] = {
      id: indicatorId,
      stixType: 'indicator',
      name: 'Initial',
      description: '',
      labels: [],
      pattern: "[domain-name:value = 'initial.example']",
      pattern_type: 'stix',
      valid_from: '2026-01-01T00:00:00.000Z',
      created: '2026-01-01T00:00:00.000Z',
      modified: '2026-01-01T00:00:00.000Z',
    };
    (window as any).openStixEditor(indicatorId);
  }, { indicatorId });

  const name = 'Edited -- "name" <safe> & literal';
  const description = 'Edited </textarea> {description}; `tick` \\path';
  const pattern = "[(file:name = 'a\\\\b') AND file:size < 10 OR file:size > 20]";
  const labels = ['label--one', '&lt;literal&gt;'];
  await page.locator('#stix-edit-name').fill(name);
  await page.locator('#stix-edit-description').fill(description);
  await page.locator('#stix-edit-labels').fill(labels.join(', '));
  await page.locator('#stix-edit-pattern').fill(pattern);
  await page.locator('.btn-stix-save').click();

  const stored = await page.evaluate(id => eval('state').library.custom[id], indicatorId);
  expect(stored).toMatchObject({ name, description, labels, pattern });

  await page.evaluate(id => (window as any).openStixEditor(id), indicatorId);
  await expect(page.locator('#stix-edit-name')).toHaveValue(name);
  await expect(page.locator('#stix-edit-description')).toHaveValue(description);
  await expect(page.locator('#stix-edit-labels')).toHaveValue(labels.join(', '));
  await expect(page.locator('#stix-edit-pattern')).toHaveValue(pattern);
});

test('metadata sinks preserve inert evidence and render only validated HTTP(S) links', async ({ page }) => {
  await importKillChain(page, {
    schema: 'killchain-export-lite',
    assignments: {
      'IN:reconnaissance': {
        techniques: [{ id: 'T1595', instanceId: 'itm-ef02-metadata' }],
        capecs: [],
        cwes: [],
      },
    },
  });
  await page.evaluate(() => {
    (window as any).__ef02Executed = false;
    (window as any).openMetadataEditor('attack', 'T1595', 'IN:reconnaissance', 'itm-ef02-metadata');
    (window as any).addHyperlinkRow();
    (window as any).addHyperlinkRow();
    (window as any).addHyperlinkRow();
    (window as any).addHyperlinkRow();
    (window as any).addObservableRow('threat-actor');
  });

  const comment = 'Comment </textarea><img data-comment-injected src=x onerror="window.__ef02Executed=true"> -- end';
  const label = 'Link <img data-link-injected src=x onerror="window.__ef02Executed=true"> -- label';
  const validUrl = 'https://example.com/a--b?q=one&next=two';
  const links = page.locator('#hyperlink-list .hyperlink-item');
  const values = [
    [label, validUrl],
    ['mixed case script', 'JaVaScRiPt:alert(1)'],
    ['whitespace script', ' javascript:alert(1)'],
    ['mixed case data', 'DaTa:text/html,<script>alert(1)</script>'],
  ];
  for (let index = 0; index < values.length; index++) {
    await links.nth(index).locator('input').nth(0).fill(values[index][0]);
    await links.nth(index).locator('input').nth(1).fill(values[index][1]);
  }
  const observable = 'observable -- "[]{};`<>&\\ value';
  await page.locator('#meta-comments').fill(comment);
  await page.locator('#observable-list .observable-item input').fill(observable);
  await page.locator('.metadata-btn-save').click();

  const metadata = await page.evaluate(() => {
    const assignment = eval('state').assignments['IN:reconnaissance'].techniques[0];
    return assignment.metadata;
  });
  expect(metadata.comments).toBe(comment);
  expect(metadata.hyperlinks).toEqual([{ label, url: validUrl }]);
  expect(metadata.observables).toEqual([{ type: 'threat-actor', value: observable }]);

  await page.evaluate(() => (window as any).openEntityModal(
    'attack', 'T1595', 'IN:reconnaissance', 'itm-ef02-metadata',
  ));
  const anchor = page.locator('#entity-modal-content a').filter({ hasText: label });
  await expect(anchor).toHaveCount(1);
  await expect(anchor).toHaveAttribute('href', validUrl);
  await expect(anchor).toHaveAttribute('rel', 'noopener noreferrer');
  await expect(anchor).toHaveText(/Link <img data-link-injected/);
  await expect(page.locator('[data-comment-injected], [data-link-injected]')).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).__ef02Executed)).toBe(false);
});

test('control, type, length, budget, and prototype defenses remain in force', async ({ page }) => {
  const result = await page.evaluate(() => {
    const links = Array.from({ length: 55 }, (_, index) => ({
      label: `link-${index}`,
      url: `https://example.test/a--b?index=${index}`,
    }));
    const observables = Array.from({ length: 105 }, (_, index) => ({
      type: 'other',
      value: `observable--${index}`,
    }));
    const sanitized = (window as any).sanitizeImportedData({
      assignments: {
        'IN:reconnaissance': {
          techniques: [{ id: 'T1595', metadata: { hyperlinks: links, observables } }],
          capecs: [],
          cwes: [],
        },
      },
    });
    const metadata = sanitized.assignments['IN:reconnaissance'].techniques[0].metadata;
    const parsed = (window as any).parseJsonSafe(
      '{"assignments":{},"__proto__":{"polluted":true},"constructor":{"polluted":true}}',
    );
    return {
      imported: (window as any).sanitizeImportedString('  a\u0000b -- "[]{};`<>&\\  ', 100),
      importedWrongType: (window as any).sanitizeImportedString(42, 100),
      importedLimited: (window as any).sanitizeImportedString('abcdef', 4),
      stored: (window as any).sanitizeForStorage('  a\u0001b -- "[]{};`<>&\\  ', 100),
      liveLimited: (window as any).sanitizeUserInputText('x'.repeat(10005)).length,
      frameworkBoundary: (window as any).stripAngleBracketsFromJson('<framework>'),
      hyperlinkCount: metadata.hyperlinks.length,
      observableCount: metadata.observables.length,
      hasProto: Object.prototype.hasOwnProperty.call(parsed, '__proto__'),
      hasConstructor: Object.prototype.hasOwnProperty.call(parsed, 'constructor'),
      polluted: ({} as any).polluted,
    };
  });

  expect(result.imported).toBe('ab -- "[]{};`<>&\\');
  expect(result.importedWrongType).toBe('');
  expect(result.importedLimited).toBe('abcd');
  expect(result.stored).toBe('ab -- "[]{};`<>&\\');
  expect(result.liveLimited).toBe(10_000);
  expect(result.frameworkBoundary).toBe('&lt;framework&gt;');
  expect(result.hyperlinkCount).toBe(50);
  expect(result.observableCount).toBe(100);
  expect(result.hasProto).toBe(false);
  expect(result.hasConstructor).toBe(false);
  expect(result.polluted).toBeUndefined();
});
