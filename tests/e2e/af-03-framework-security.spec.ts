import fs from 'node:fs';
import { expect, test, type Page } from '@playwright/test';

const frameworks = [
  { type: 'attack', bucket: 'attack', library: 'techniques', file: 'attack-techniques.json', wrapper: null, id: 'T1595', other: 'T1059' },
  { type: 'capec', bucket: 'capecPatterns', library: 'capecs', file: 'capec-full.json', wrapper: 'patterns', id: 'CAPEC-1', other: 'CAPEC-2' },
  { type: 'cwe', bucket: 'cweWeaknesses', library: 'cwes', file: 'cwe-full.json', wrapper: 'weaknesses', id: 'CWE-79', other: 'CWE-89' },
];
const phaseKey = 'IN:reconnaissance';

function dataset() {
  return {
    attack: { T1595: { id: 'T1595', name: 'Test technique' } },
    capecPatterns: { 'CAPEC-1': { id: 'CAPEC-1', name: 'Test pattern' } },
    cweWeaknesses: { 'CWE-79': { id: 'CWE-79', name: 'Test weakness' } },
    techniqueToCapec: {}, capecToTechnique: {}, cweToCapec: {},
  };
}

async function openApp(page: Page) {
  await page.goto('/index.html');
  await expect(page.locator('#loading')).toHaveClass(/hidden/, { timeout: 60_000 });
}

test.beforeEach(async ({ page }) => {
  await page.route('**/*', route => {
    return new URL(route.request().url()).hostname === '127.0.0.1' ? route.continue() : route.abort();
  });
});

test('accepts every bundled framework record and preserves immutable snapshots', async ({ page }) => {
  await openApp(page);
  const bundled: any = dataset();
  for (const framework of frameworks) {
    const raw = JSON.parse(fs.readFileSync(`resources/${framework.file}`, 'utf8'));
    bundled[framework.bucket] = framework.wrapper ? raw[framework.wrapper] : raw;
  }
  const result = await page.evaluate(data => {
    const app = window as any;
    const snapshot = app.buildImmutableSharedDataPayload(data);
    return {
      valid: app.validateSharedDatasetShape(data),
      equal: JSON.stringify(snapshot) === JSON.stringify(data),
      frozen: Object.isFrozen(snapshot) && Object.isFrozen(snapshot.attack) && Object.isFrozen(snapshot.attack.T1595),
      separate: snapshot !== data && snapshot.attack.T1595 !== data.attack.T1595,
    };
  }, bundled);
  expect(result).toEqual({ valid: true, equal: true, frozen: true, separate: true });
});

test('rejects malformed, missing, mismatched and inherited record IDs at validation and handoff', async ({ page }) => {
  await openApp(page);
  const results = await page.evaluate(({ data, frameworks }) => {
    const app = window as any;
    const results = [];
    for (const framework of frameworks) {
      const invalidRecords = [null, [], {}, { id: null }, { id: 123 }, { id: false },
        { id: [framework.id] }, { id: framework.other }, { id: framework.id.toLowerCase() },
        { id: framework.id + '\n' }, { id: framework.id + "');alert(1)//" },
        Object.create({ id: framework.id }),
      ];
      for (const record of invalidRecords) {
        const candidate = { ...data, [framework.bucket]: { [framework.id]: record } };
        results.push([app.validateSharedDatasetShape(candidate), app.buildImmutableSharedDataPayload(candidate)]);
      }
      for (const id of [framework.id + '\n', framework.id + '" onclick="alert(1)', framework.id.toLowerCase(), '__proto__', 'T1', 'T1595.1', 'CAPEC-x', 'CWE-x']) {
        const candidate = { ...data, [framework.bucket]: { [id]: { id } } };
        results.push([app.validateSharedDatasetShape(candidate), app.buildImmutableSharedDataPayload(candidate)]);
      }
    }
    return results;
  }, { data: dataset(), frameworks });
  expect(results.every(result => result[0] === false && result[1] === null)).toBe(true);
});

for (const framework of frameworks) {
  test(`${framework.type}: rejects poisoned resource data before cache write`, async ({ page }) => {
    const records = { [framework.id]: { id: framework.id + "');window.af03Executed=true;//", name: 'Poisoned' } };
    await page.route(`**/resources/${framework.file}`, route => route.fulfill({
      json: framework.wrapper ? { [framework.wrapper]: records } : records,
    }));
    await page.goto('/index.html');
    await expect(page.locator('#loading .loading-text')).toContainText('Shared dataset validation failed');
    expect(await page.evaluate(() => (window as any).getSharedDataCache().data)).toBeNull();
    const handoff = await page.evaluate(async () => {
      try { await (window as any).getAttackFlowSharedData(); return 'accepted'; }
      catch (error) { return (error as Error).message; }
    });
    expect(handoff).toBe('Shared dataset validation failed');
  });

  test(`${framework.type}: selection and dragging use the original valid ID`, async ({ page }) => {
    await openApp(page);
    await page.evaluate(type => (window as any).switchTab(type), framework.type);
    const item = page.locator(`#list-${framework.type} .entity-item`).first();
    const id = await item.getAttribute('data-entity-id');
    expect(id).toBeTruthy();
    await item.click();
    expect(await page.evaluate(() => eval('state').selection)).toEqual({ type: framework.type, id });
    const transfer = await page.evaluateHandle(() => new DataTransfer());
    await item.dispatchEvent('dragstart', { dataTransfer: transfer });
    expect(await page.evaluate(() => eval('dragData').id)).toBe(id);
    await page.locator(`[data-phase="${phaseKey}"]`).dispatchEvent('drop', { dataTransfer: transfer });
    expect(await page.evaluate(({ library, phaseKey }) => eval('state').assignments[phaseKey][library][0].id,
      { library: framework.library, phaseKey })).toBe(id);
    await item.dispatchEvent('dragend', { dataTransfer: transfer });
    expect(await page.evaluate(() => eval('dragData').kind)).toBeNull();
  });

  test(`${framework.type}: list and global search treat hostile IDs as data`, async ({ page }) => {
    await openApp(page);
    const id = framework.id + "');window.af03Executed=true;//\" onmouseover=\"window.af03Executed=true";
    const result = await page.evaluate(({ framework, id }) => {
      const app = window as any;
      const appState = eval('state');
      appState.library.techniques = {};
      appState.library.capecs = {};
      appState.library.cwes = {};
      appState.library[framework.library] = { [id]: { id, name: 'Poison Probe', domain: 'enterprise', abstraction: 'Base' } };
      appState.globalSearch = '';
      appState.filters[framework.type] = 'all';
      app.filterEntities(framework.type);
      appState.globalSearch = 'poison probe';
      app.renderGlobalSearchResults();
      const calls: unknown[] = [];
      const oldSelect = app.selectEntity;
      const oldOpen = app.openGlobalSearchResult;
      app.selectEntity = (type: string, value: string) => calls.push([type, value]);
      app.openGlobalSearchResult = (type: string, value: string) => calls.push([type, value]);
      try {
        const elements = [document.querySelector(`#list-${framework.type} .entity-item`), document.querySelector('#global-search-results .global-search-item')] as HTMLElement[];
        const results = elements.map(element => {
          element.click();
          element.dispatchEvent(new DragEvent('dragstart', { bubbles: true, dataTransfer: new DataTransfer() }));
          const dragged = eval('dragData').id;
          element.dispatchEvent(new DragEvent('dragend', { bubbles: true }));
          element.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
          return {
            id: element.dataset.entityId, dragged,
            handlers: Array.from(element.attributes).filter(attr => attr.name.startsWith('on')).map(attr => attr.value),
          };
        });
        return { results, calls, executed: app.af03Executed === true };
      } finally {
        app.selectEntity = oldSelect;
        app.openGlobalSearchResult = oldOpen;
      }
    }, { framework, id });
    expect(result.calls).toEqual([[framework.type, id], [framework.type, id]]);
    expect(result.executed).toBe(false);
    for (const rendered of result.results) {
      expect(rendered.id).toBe(id);
      expect(rendered.dragged).toBe(id);
      for (const handler of rendered.handlers) expect(handler).not.toContain('af03Executed');
    }
  });
}

test('rejects a mutated cache and preserves the previous cache on invalid reload', async ({ page }) => {
  await openApp(page);
  await page.route('**/resources/attack-techniques.json', route => route.fulfill({ json: { T1595: { id: 'T1059' } } }));
  const reload = await page.evaluate(async () => {
    const app = window as any;
    const cache = app.getSharedDataCache();
    const previous = cache.data;
    const loadedAt = cache.loadedAt;
    let error = '';
    try { await app.loadSharedLibraryData(true); } catch (e) { error = (e as Error).message; }
    return { error, same: cache.data === previous, timestamp: cache.loadedAt === loadedAt, cleared: cache.promise === null };
  });
  expect(reload).toEqual({ error: 'Shared dataset validation failed', same: true, timestamp: true, cleared: true });
  const reuse = await page.evaluate(async () => {
    const app = window as any;
    const data = app.getSharedDataCache().data;
    data.attack.T1595.id = 'T1059';
    const errors = [];
    for (const read of [() => app.loadSharedLibraryData(), () => app.getAttackFlowSharedData()]) {
      try { await read(); errors.push('accepted'); } catch (e) { errors.push((e as Error).message); }
    }
    return { errors, payload: app.buildImmutableSharedDataPayload(data) };
  });
  expect(reuse).toEqual({ errors: ['Shared dataset validation failed', 'Shared dataset validation failed'], payload: null });
});
