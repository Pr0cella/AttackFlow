import fs from 'node:fs';
import { expect, test, type Page } from '@playwright/test';

const phaseKey = 'IN:reconnaissance';
const targetKey = 'IN:resource-development';
const hostileIds = [
  'grp-demo-1" onclick="window.af01Executed=true',
  "grp-demo-1');window.af01Executed=true;//",
  'grp-demo-1&#39;);window.af01Executed=true;//',
];

function payload(ids: unknown[]) {
  return {
    schema: 'killchain-export-lite',
    assignments: {
      [phaseKey]: {
        techniques: [], capecs: [], cwes: [],
        groups: ids.map((groupId, index) => ({
          groupId, label: `Group ${index}`, collapsed: false,
          items: [{ type: 'attack', id: 'T1595', instanceId: `itm-test-${index}` }],
        })),
        layout: ids.map(groupId => ({ kind: 'group', groupId })),
      },
    },
  };
}

async function importPayload(page: Page, data: unknown) {
  await page.locator('#toast').evaluate(el => { el.textContent = ''; });
  await page.locator('#import-killchain-input').setInputFiles({
    name: 'af-01.json', mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(data)),
  });
  await expect(page.locator('#toast')).toHaveText('Imported kill chain');
}

async function phaseState(page: Page, key = phaseKey) {
  return page.evaluate(key => eval('state').assignments[key], key);
}

test.beforeEach(async ({ page }) => {
  await page.route('**/*', route => {
    const url = new URL(route.request().url());
    return url.hostname === '127.0.0.1' ? route.continue() : route.abort();
  });
  await page.goto('/index.html');
  await expect(page.locator('#loading')).toHaveClass(/hidden/, { timeout: 60_000 });
});

test('regenerates invalid and duplicate IDs per phase without changing the input', async ({ page }) => {
  const valid = 'grp-test-abc12';
  const ids = [valid, valid, ...hostileIds, '', null, 42, 'grp-test-abcdef', 'grp-test-abc12\n', 'grp-TEST-abc12'];
  const input = payload(ids);
  input.assignments[targetKey] = payload([valid]).assignments[phaseKey];
  const result = await page.evaluate(data => {
    const before = JSON.stringify(data);
    const sanitized = (window as any).sanitizeImportedData(data);
    (window as any).ensureAssignmentShape(sanitized.assignments);
    return { sanitized, unchanged: before === JSON.stringify(data) };
  }, input);
  expect(result.unchanged).toBe(true);
  const phase = result.sanitized.assignments[phaseKey];
  const actualIds = phase.groups.map((group: any) => group.groupId);
  expect(new Set(actualIds).size).toBe(ids.length);
  actualIds.forEach((id: string) => expect(id).toMatch(/^grp-[a-z0-9]+-[a-z0-9]{1,5}$/));
  expect(actualIds[0]).toBe(valid);
  expect(actualIds[1]).not.toBe(valid);
  expect(result.sanitized.assignments[targetKey].groups[0].groupId).toBe(valid);
  expect(phase.layout[0].groupId).toBe(valid);
  expect(new Set(phase.layout.map((entry: any) => entry.groupId))).toEqual(new Set(actualIds));
  expect(phase.layout).toHaveLength(ids.length);
  expect(phase.groups.every((group: any) => group.items[0].id === 'T1595')).toBe(true);
  hostileIds.forEach(id => expect(JSON.stringify(result.sanitized)).not.toContain(id));
});

test('remaps the hostile import fixture and retains grouping demo layout and contents', async ({ page }) => {
  await importPayload(page, JSON.parse(fs.readFileSync('tests/import-validation/bypass-group-id-xss.json', 'utf8')));
  let phase = await phaseState(page);
  expect(phase.groups[0].groupId).toMatch(/^grp-[a-z0-9]+-[a-z0-9]{1,5}$/);
  expect(phase.layout[0].groupId).toBe(phase.groups[0].groupId);
  await expect(page.locator('.phase-group')).toHaveCount(1);
  const demo = JSON.parse(fs.readFileSync('examples/grouping-demo.json', 'utf8'));
  await importPayload(page, demo);
  for (const [key, original] of Object.entries(demo.assignments) as [string, any][]) {
    phase = await phaseState(page, key);
    expect(phase.groups.map((g: any) => [g.label, g.items.map((item: any) => item.id)]))
      .toEqual((original.groups || []).map((g: any) => [g.label, g.items.map((item: any) => item.id)]));
    expect(phase.layout.filter((entry: any) => entry.kind === 'group').map((entry: any) => entry.groupId))
      .toEqual(phase.groups.map((g: any) => g.groupId));
  }
});

test('preserves collapse, rename Escape/Enter/blur and delete behavior', async ({ page }) => {
  await importPayload(page, payload([hostileIds[1]]));
  const group = page.locator('.phase-group');
  await group.locator('.phase-group-header').click();
  await expect(group).toHaveClass(/collapsed/);
  await group.locator('.phase-group-header').click();
  await expect(group).not.toHaveClass(/collapsed/);
  await group.locator('.rename').click();
  const input = group.locator('input.metadata-input');
  await input.fill('Cancelled');
  const oldInput = await input.elementHandle();
  await input.press('Escape');
  await oldInput!.dispatchEvent('blur');
  await expect(group.locator('.phase-group-title')).toHaveText('Group 0');
  await group.locator('.rename').click();
  await input.fill('Saved on Enter');
  await input.press('Enter');
  await expect(group.locator('.phase-group-title')).toHaveText('Saved on Enter');
  await group.locator('.rename').click();
  await input.fill('Saved on blur');
  await input.press('Tab');
  await expect(group.locator('.phase-group-title')).toHaveText('Saved on blur');
  page.once('dialog', dialog => dialog.dismiss());
  await group.locator('.delete').click();
  await expect(group).toHaveCount(1);
  page.once('dialog', dialog => dialog.accept());
  await group.locator('.delete').click();
  await expect(group).toHaveCount(0);
  const phase = await phaseState(page);
  expect(phase.techniques[0].id).toBe('T1595');
  expect(phase.layout).toEqual([{ kind: 'item', type: 'attack', instanceId: 'itm-test-0' }]);
});

test('moves a group and drags assignments out of and into it', async ({ page }) => {
  await importPayload(page, payload(['grp-test-abc12']));
  const transfer = await page.evaluateHandle(() => new DataTransfer());
  const group = page.locator('.phase-group');
  await group.locator('.phase-group-header').dispatchEvent('dragstart', { dataTransfer: transfer });
  await page.locator(`[data-phase="${targetKey}"]`).dispatchEvent('drop', { dataTransfer: transfer });
  expect((await phaseState(page)).groups).toHaveLength(0);
  expect((await phaseState(page, targetKey)).groups[0].groupId).toBe('grp-test-abc12');
  await group.locator('[data-source-group-id]').dispatchEvent('dragstart', { dataTransfer: transfer });
  await page.locator(`[data-phase="${phaseKey}"]`).dispatchEvent('drop', { dataTransfer: transfer });
  expect((await phaseState(page)).techniques[0].id).toBe('T1595');
  expect((await phaseState(page, targetKey)).groups[0].items).toHaveLength(0);
  await page.locator(`[data-phase="${phaseKey}"] [data-source-group-id]`).dispatchEvent('dragstart', { dataTransfer: transfer });
  await group.dispatchEvent('dragover', { dataTransfer: transfer });
  await group.dispatchEvent('dragleave', { dataTransfer: transfer });
  await group.dispatchEvent('drop', { dataTransfer: transfer });
  expect((await phaseState(page)).techniques).toHaveLength(0);
  expect((await phaseState(page, targetKey)).groups[0].items[0].id).toBe('T1595');
  await group.locator('.phase-group-header').dispatchEvent('dragend', { dataTransfer: transfer });
});

for (const [index, hostileId] of hostileIds.entries()) {
  test(`encodes raw group IDs as data at render sinks (${index + 1})`, async ({ page }) => {
    await importPayload(page, payload(['grp-test-abc12']));
    await page.evaluate(({ phaseKey, hostileId }) => {
      const phase = eval('state').assignments[phaseKey];
      phase.groups[0].groupId = hostileId;
      phase.groups[0].label = 'Label " onfocus="window.af01Executed=true';
      phase.layout[0].groupId = hostileId;
      (window as any).renderKillChain();
    }, { phaseKey, hostileId });
    const group = page.locator('.phase-group');
    await expect(group).toHaveAttribute('data-group-id', hostileId);
    const assertHandlers = async () => {
      const handlers = await group.evaluate(root => [root, ...root.querySelectorAll('*')]
        .flatMap(el => Array.from(el.attributes).filter(attr => attr.name.startsWith('on')).map(attr => attr.value)));
      for (const handler of handlers) {
        expect(handler).not.toContain(hostileId);
        expect(handler).not.toContain('af01Executed');
      }
    };
    await assertHandlers();
    await group.locator('.phase-group-header').click();
    await expect(group).toHaveClass(/collapsed/);
    await group.locator('.rename').click();
    await expect(group.locator('input')).toHaveValue('Label " onfocus="window.af01Executed=true');
    await expect(group.locator('input')).not.toHaveAttribute('onfocus');
    await assertHandlers();
    await group.locator('input').press('Escape');
    expect(await page.evaluate(() => (window as any).af01Executed)).toBeUndefined();
    page.once('dialog', dialog => dialog.accept());
    await group.locator('.delete').click();
    await expect(group).toHaveCount(0);
  });
}
