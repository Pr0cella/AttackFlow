import { expect, test, type Page } from '@playwright/test';
import { exportNative } from './helpers/roundtrip';

const phaseKey = 'IN:reconnaissance';
const otherPhase = 'IN:resource-development';
const groupId = 'grp-meta-1';
const identityId = 'identity--11111111-1111-4111-8111-111111111111';
const malwareId = 'malware--22222222-2222-4222-8222-222222222222';
const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const baseURL = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:4173';
const destinations = { attack: 'techniques', capec: 'capecs', cwe: 'cwes', custom: 'customItems' };

function assignment(type: string, id: string, number: number) {
  return {
    type, id, instanceId: `itm-meta-${number}`,
    metadata: {
      score: number % 2 ? 'high' : 'medium', confidence: 50 + number,
      comments: `Evidence ${number} -- [x] {y}; "quote" & <img data-group-injected src=x onerror="window.groupInjected=true">`,
      cveEntries: [{ id: `CVE-2026-${1000 + number}`, score: 9.8, vector }],
      hyperlinks: [{ label: `Reference ${number}`, url: `https://example.test/ref-${number}` }],
      observables: [{ type: 'ipv4-addr', value: `192.0.2.${number}` }],
    },
  };
}

function fixture() {
  const items = [
    assignment('attack', 'T1595', 1), assignment('custom', identityId, 2),
    assignment('capec', 'CAPEC-1', 3), assignment('custom', malwareId, 4),
    assignment('cwe', 'CWE-79', 5), assignment('custom', identityId, 6),
  ];
  return {
    schema: 'killchain-export-lite',
    assignments: {
      [phaseKey]: {
        techniques: [assignment('attack', 'T1059', 7)], capecs: [], cwes: [],
        customItems: [assignment('custom', malwareId, 8)],
        groups: [
          { groupId, label: 'Mixed group', items },
          { groupId: 'grp-meta-2', label: 'Keep group', items: [assignment('cwe', 'CWE-89', 9)] },
        ],
        layout: [
          { kind: 'item', type: 'custom', instanceId: 'itm-meta-8' },
          { kind: 'group', groupId },
          { kind: 'item', type: 'attack', instanceId: 'itm-meta-7' },
          { kind: 'group', groupId: 'grp-meta-2' },
        ],
      },
      [otherPhase]: { techniques: [assignment('attack', 'T1583', 10)], capecs: [], cwes: [], customItems: [], groups: [], layout: [] },
    },
    customLibrary: {
      [identityId]: { id: identityId, stixType: 'identity', name: 'Group identity', identity_class: 'organization' },
      [malwareId]: { id: malwareId, stixType: 'malware', name: 'Group malware', is_family: false },
    },
  };
}

async function openApp(page: Page) {
  await page.route('**/*', route => {
    const url = new URL(route.request().url());
    return url.origin === new URL(baseURL).origin ? route.continue() : route.abort();
  });
  await page.goto('/index.html');
  await expect(page.locator('#loading')).toHaveClass(/hidden/, { timeout: 60_000 });
}

async function importBytes(page: Page, buffer: Buffer) {
  await page.locator('#toast').evaluate(el => { el.textContent = ''; });
  await page.locator('#import-killchain-input').setInputFiles({ name: 'group-metadata.json', mimeType: 'application/json', buffer });
  await expect(page.locator('#toast')).toHaveText('Imported kill chain');
}

async function snapshot(page: Page) {
  return page.evaluate(() => {
    const app = eval('state');
    return { assignments: app.assignments, customLibrary: app.library.custom };
  });
}

const group = (page: Page) => page.locator(`.phase-group[data-group-id="${groupId}"]`);

async function deleteGroup(page: Page, accept = true) {
  page.once('dialog', dialog => accept ? dialog.accept() : dialog.dismiss());
  await group(page).locator('.delete').click();
}

test.beforeEach(async ({ page }) => {
  await openApp(page);
  await importBytes(page, Buffer.from(JSON.stringify(fixture())));
});

test('mixed group deletion preserves metadata through a full JSON round trip', async ({ page, browser, baseURL }) => {
  const before = await snapshot(page);
  const source = before.assignments[phaseKey];
  const moved = source.groups[0].items;
  await deleteGroup(page);
  const after = await snapshot(page);
  const phase = after.assignments[phaseKey];

  // assert custom placement first so the baseline fails at the original defect.
  expect(phase.customItems).toEqual([...source.customItems, ...moved.filter(item => item.type === 'custom')]);
  for (const [type, key] of Object.entries(destinations)) {
    expect(phase[key]).toEqual([...source[key], ...moved.filter(item => item.type === type)]);
  }
  expect(phase.groups).toEqual(source.groups.slice(1));
  expect(phase.layout).toEqual([
    ...source.layout.filter(entry => entry.groupId !== groupId),
    ...moved.map(item => ({ kind: 'item', type: item.type, instanceId: item.instanceId })),
  ]);
  expect(after.customLibrary).toEqual(before.customLibrary);
  expect(after.assignments).toEqual({ ...before.assignments, [phaseKey]: phase });
  await expect(group(page)).toHaveCount(0);

  const phaseElement = page.locator(`[data-phase="${phaseKey}"]`);
  for (const item of moved) {
    const card = phaseElement.locator('[draggable="true"][data-source-group-id=""]')
      .filter({ has: page.locator(`.edit[onclick*="'${item.instanceId}'"]`) });
    await expect(card).toHaveCount(1);
    await expect(card).toBeVisible();
    expect(phase.layout.filter(entry => entry.instanceId === item.instanceId)).toHaveLength(1);
    if (item.type !== 'custom') {
      await card.hover();
      await card.locator('.edit').click();
      await expect(page.locator('#meta-comments')).toHaveValue(item.metadata.comments);
      await expect(page.locator('#meta-confidence')).toHaveValue(String(item.metadata.confidence));
      await expect(page.locator('#score-selector .selected')).toHaveAttribute('data-value', item.metadata.score);
      const cveInputs = page.locator('#cve-list input');
      await expect(cveInputs.nth(0)).toHaveValue(item.metadata.cveEntries[0].id);
      await expect(cveInputs.nth(1)).toHaveValue('9.8');
      await expect(cveInputs.nth(2)).toHaveValue(vector);
      await expect(page.locator('#hyperlink-list input').nth(0)).toHaveValue(item.metadata.hyperlinks[0].label);
      await expect(page.locator('#hyperlink-list input').nth(1)).toHaveValue(item.metadata.hyperlinks[0].url);
      await expect(page.locator('#observable-list input')).toHaveValue(item.metadata.observables[0].value);
      await page.locator('.metadata-editor-close').click();
    }
  }
  await expect(page.locator('[data-group-injected]')).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).groupInjected)).toBeUndefined();

  // Reuses the shared export helper, which clicks the real export control.
  const { buffer: bytes, json: exported } = await exportNative(page);
  expect(exported.assignments).toEqual(after.assignments);
  expect(exported.customLibrary).toEqual(after.customLibrary);
  const context = await browser.newContext({ baseURL });
  try {
    const freshPage = await context.newPage();
    await openApp(freshPage);
    await importBytes(freshPage, bytes);
    const restored = await snapshot(freshPage);
    // ungrouped imports omit the redundant type property; array placement carries its type.
    const expected = JSON.parse(JSON.stringify(after));
    for (const phase of Object.values(expected.assignments) as any[]) {
      for (const key of Object.values(destinations)) {
        for (const item of phase[key]) delete item.type;
      }
    }
    expect(restored).toEqual(expected);
    await expect(freshPage.locator(`[data-phase="${phaseKey}"] .custom-tag`)).toHaveCount(4);
  } finally {
    await context.close();
  }
});

test('cancelling group deletion leaves all assignments and library data unchanged', async ({ page }) => {
  const before = await snapshot(page);
  await deleteGroup(page, false);
  expect(await snapshot(page)).toEqual(before);
  await expect(group(page)).toHaveCount(1);
});

for (const missingItems of [false, true]) {
  test(`deletes an empty group with ${missingItems ? 'missing' : 'empty'} items`, async ({ page }) => {
    const data = fixture();
    data.assignments[phaseKey].groups[0].items = [];
    await importBytes(page, Buffer.from(JSON.stringify(data)));
    if (missingItems) {
      await page.evaluate(key => { delete eval('state').assignments[key].groups[0].items; }, phaseKey);
    }
    const before = await snapshot(page);
    await deleteGroup(page);
    const expected = JSON.parse(JSON.stringify(before));
    expected.assignments[phaseKey].groups.shift();
    expected.assignments[phaseKey].layout = expected.assignments[phaseKey].layout.filter(entry => entry.groupId !== groupId);
    expect(await snapshot(page)).toEqual(expected);
    await expect(group(page)).toHaveCount(0);
  });
}

for (const invalid of ['unknown', 'constructor', 'toString', '__proto__', 'inherited-type', 'number-type', 'null-item', 'array-item', 'null-items', 'object-items', 'undefined-items', 'destination', 'layout']) {
  test(`rejects ${invalid} before moving any group items`, async ({ page }) => {
    await page.evaluate(({ phaseKey, invalid }) => {
      const phase = eval('state').assignments[phaseKey];
      const group = phase.groups[0];
      const badItem = group.items[1];
      switch (invalid) {
        case 'inherited-type':
          delete badItem.type;
          Object.setPrototypeOf(badItem, { type: 'custom' });
          break;
        case 'number-type': badItem.type = 42; break;
        case 'null-item': group.items[1] = null; break;
        case 'array-item': group.items[1] = []; break;
        case 'null-items': group.items = null; break;
        case 'object-items': group.items = {}; break;
        case 'undefined-items': group.items = undefined; break;
        case 'destination': phase.customItems = {}; break;
        case 'layout': phase.layout = {}; break;
        default: badItem.type = invalid;
      }
    }, { phaseKey, invalid });
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    const before = await snapshot(page);
    await deleteGroup(page);
    await expect(page.locator('#toast')).toHaveText('Cannot delete group: invalid item or layout data.');
    expect(await snapshot(page)).toEqual(before);
    expect(errors).toEqual([]);
    await expect(group(page)).toHaveCount(1);
  });
}
