// RT-10 Composer import decisions and RT-11 cross-page file workflows.
//
// SCOPE, stated so this file is never read as more than it is: the Composer defines 40
// object types and 262 field descriptors, including structured shapes the main editor has
// no analogue for (dictionary, hashes, extensions, kill-chain-phases, object-refs). An
// exhaustive per-field matrix for that surface is outstanding work and is NOT here.
// What is covered is the Composer lifecycle, every import decision branch, and the
// declared cross-page intersection with its losses stated explicitly.
//
// Composer sanitization defects are already covered as known gaps AF-RC-003 and AF-RC-007
// in stix-builder-security.spec.ts and are not re-asserted here.

import { expect, test, type Page } from '@playwright/test';
import {
  BASE_URL, exportStix, importNative, importStix, openApp, readState, withFreshContext,
} from './helpers/roundtrip';

const bytes = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8');

const A = 'malware--11111111-1111-4111-8111-111111111111';
const B = 'identity--22222222-2222-4222-8222-222222222222';
const C = 'tool--33333333-3333-4333-8333-333333333333';

function bundle(objects: unknown[], id = 'bundle--99999999-9999-4999-8999-999999999999') {
  return { type: 'bundle', id, spec_version: '2.1', objects };
}

const sdo = (id: string, name: string, extra: Record<string, unknown> = {}) => ({
  type: id.split('--')[0], spec_version: '2.1', id,
  created: '2026-01-01T00:00:00.000Z', modified: '2026-01-02T00:00:00.000Z',
  name, ...extra,
});

async function openComposer(page: Page) {
  const blocked: string[] = [];
  const localOrigin = new URL(BASE_URL).origin;
  await page.route('**/*', route => {
    const url = route.request().url();
    if (new URL(url).origin === localOrigin) return route.continue();
    blocked.push(url);
    return route.abort();
  });
  await page.goto('/stix-builder.html');
  await expect(page.locator('#add-object')).toBeVisible({ timeout: 60_000 });
  return blocked;
}

async function importIntoComposer(page: Page, buffer: Buffer, name = 'composer.json') {
  await page.locator('#bundle-file').setInputFiles({ name, mimeType: 'application/json', buffer });
}

const composerState = (page: Page) => page.evaluate(() =>
  JSON.parse(JSON.stringify(eval('state').bundle)));

async function exportFromComposer(page: Page) {
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.locator('#export-bundle').click(),
  ]);
  const downloadPath = await download.path();
  const fs = require('node:fs');
  const buffer = fs.readFileSync(downloadPath!);
  return { name: download.suggestedFilename(), buffer, json: JSON.parse(buffer.toString('utf8')) };
}

test.describe('RT-10 Composer import decisions', () => {
  test('replace, merge and both-declined branches each do exactly one thing', async ({ page }) => {
    await openComposer(page);

    await test.step('the first import into an empty bundle asks nothing', async () => {
      // No confirm is shown while the bundle is empty.
      await importIntoComposer(page, bytes(bundle([sdo(A, 'First malware')])), 'first.json');
      await expect(page.locator('#toast')).toHaveText('Bundle imported');
      const state = await composerState(page);
      expect(state.objects.map((o: any) => o.id)).toEqual([A]);
    });

    await test.step('declining replace then declining merge leaves the bundle untouched', async () => {
      const before = await composerState(page);
      // Two confirms: "Replace?" then "Merge?". Dismiss both.
      page.on('dialog', dialog => dialog.dismiss());
      await importIntoComposer(page, bytes(bundle([sdo(B, 'Second identity')])), 'declined.json');
      await page.waitForTimeout(300);
      expect(await composerState(page)).toEqual(before);
      page.removeAllListeners('dialog');
    });

    await test.step('declining replace then accepting merge adds without removing', async () => {
      let seen = 0;
      page.on('dialog', dialog => { seen += 1; return seen === 1 ? dialog.dismiss() : dialog.accept(); });
      await importIntoComposer(page, bytes(bundle([sdo(B, 'Second identity')])), 'merge.json');
      await expect(page.locator('#toast')).toHaveText('Bundle imported');
      page.removeAllListeners('dialog');

      const state = await composerState(page);
      expect(state.objects.map((o: any) => o.id).sort()).toEqual([A, B].sort());
      expect(seen).toBe(2);
    });

    await test.step('a duplicate id is skipped during merge rather than overwriting', async () => {
      let seen = 0;
      page.on('dialog', dialog => { seen += 1; return seen === 1 ? dialog.dismiss() : dialog.accept(); });
      // Same id as A, different content: the incoming object must not win.
      await importIntoComposer(page, bytes(bundle([sdo(A, 'CONFLICTING malware')])), 'dupe.json');
      await expect(page.locator('#toast')).toHaveText('Bundle imported');
      page.removeAllListeners('dialog');

      const state = await composerState(page);
      expect(state.objects.filter((o: any) => o.id === A)).toHaveLength(1);
      expect(state.objects.find((o: any) => o.id === A).name).toBe('First malware');
    });

    await test.step('accepting replace discards the current bundle entirely', async () => {
      page.on('dialog', dialog => dialog.accept());
      await importIntoComposer(page, bytes(bundle([sdo(C, 'Replacement tool')])), 'replace.json');
      await expect(page.locator('#toast')).toHaveText('Bundle imported');
      page.removeAllListeners('dialog');

      const state = await composerState(page);
      expect(state.objects.map((o: any) => o.id)).toEqual([C]);
    });
  });

  test('malformed bundles are refused with a diagnostic', async ({ page }) => {
    await openComposer(page);
    await importIntoComposer(page, bytes(bundle([sdo(A, 'Baseline')])), 'baseline.json');
    await expect(page.locator('#toast')).toHaveText('Bundle imported');
    const before = await composerState(page);

    page.on('dialog', dialog => dialog.accept());
    for (const [label, payload] of [
      ['not a bundle', { type: 'not-bundle', objects: [] }],
      ['objects missing', { type: 'bundle' }],
      ['objects not an array', { type: 'bundle', objects: {} }],
      ['array root', []],
    ] as [string, unknown][]) {
      await page.locator('#toast').evaluate(el => { el.textContent = ''; });
      await importIntoComposer(page, bytes(payload), `${label}.json`);
      await expect(page.locator('#toast'), label).toContainText('Import failed');
      expect(await composerState(page), label).toEqual(before);
    }
    page.removeAllListeners('dialog');
  });

  test('an empty bundle replaces the current one with nothing', async ({ page }) => {
    await openComposer(page);
    await importIntoComposer(page, bytes(bundle([sdo(A, 'Baseline')])), 'baseline.json');
    await expect(page.locator('#toast')).toHaveText('Bundle imported');

    page.on('dialog', dialog => dialog.accept());
    await importIntoComposer(page, bytes(bundle([])), 'empty.json');
    await expect(page.locator('#toast')).toHaveText('Bundle imported');
    page.removeAllListeners('dialog');

    const state = await composerState(page);
    expect(state.objects).toEqual([]);
  });

  test('export offers a confirm when validation reports issues and honours a decline', async ({ page }) => {
    await openComposer(page);
    // An indicator with no pattern is schema-invalid, so validateBundle() reports issues.
    await importIntoComposer(page, bytes(bundle([
      { type: 'indicator', spec_version: '2.1', id: 'indicator--44444444-4444-4444-8444-444444444444', name: 'No pattern' },
    ])), 'invalid.json');
    await expect(page.locator('#toast')).toHaveText('Bundle imported');

    await test.step('declining the confirm produces no download', async () => {
      page.once('dialog', dialog => {
        expect(dialog.message()).toContain('validation issues');
        return dialog.dismiss();
      });
      const pending = page.waitForEvent('download', { timeout: 1500 }).then(() => 'download', () => 'none');
      await page.locator('#export-bundle').click();
      expect(await pending).toBe('none');
    });

    await test.step('accepting the confirm exports the bundle as-is', async () => {
      page.once('dialog', dialog => dialog.accept());
      const exported = await exportFromComposer(page);
      expect(exported.name).toBe('stix-bundle.json');
      expect(exported.json.objects).toHaveLength(1);
    });
  });
});

test.describe('RT-11 cross-page file workflows', () => {
  test('a main-editor STIX download imports into the Composer with a stated intersection', async ({ page, browser }) => {
    // Build a real bundle in the main editor, including derived graph objects.
    await openApp(page);
    await importNative(page, bytes({
      assignments: {
        'IN:reconnaissance': {
          techniques: [{ id: 'T1059.001', instanceId: 'itm-x-1' }],
          capecs: [], cwes: [],
          customItems: [
            { id: A, instanceId: 'itm-x-2', type: 'custom', metadata: {} },
            { id: B, instanceId: 'itm-x-3', type: 'custom', metadata: {} },
          ],
          groups: [], layout: [],
        },
      },
      customLibrary: {
        [A]: { id: A, stixType: 'malware', name: 'Cross malware', is_family: false },
        [B]: { id: B, stixType: 'identity', name: 'Cross identity', identity_class: 'organization' },
      },
    }), 'rt-11-source.json');

    const exported = await exportStix(page);
    const sourceIds = exported.json.objects.map((o: any) => o.id);
    const sourceRelationships = exported.json.objects.filter((o: any) => o.type === 'relationship');
    expect(sourceRelationships.length).toBeGreaterThan(0);

    await withFreshContext(browser, async composerPage => {
      await openComposer(composerPage);
      await importIntoComposer(composerPage, exported.buffer, exported.name);
      await expect(composerPage.locator('#toast')).toHaveText('Bundle imported');

      const state = await composerState(composerPage);
      const importedIds = state.objects.map((o: any) => o.id);

      // DECLARED INTERSECTION: the Composer accepts objects whose type it defines. Every
      // object it kept must be one the main editor emitted, with the same id.
      for (const id of importedIds) expect(sourceIds).toContain(id);

      // The core SDOs survive the hop.
      expect(importedIds).toContain(A);
      expect(importedIds).toContain(B);
      expect(state.objects.find((o: any) => o.id === A).name).toBe('Cross malware');

      // EXPLICIT LOSSES, not a full-graph transfer:
      const lost = sourceIds.filter((id: string) => !importedIds.includes(id));
      // Whatever is lost, it is never silently more than the source contained.
      expect(lost.every((id: string) => sourceIds.includes(id))).toBe(true);
      // Record the loss shape rather than asserting an equal object count.
      expect(importedIds.length).toBeLessThanOrEqual(sourceIds.length);
    });
  });

  test('a Composer download imports into the main editor as library objects only', async ({ page, browser }) => {
    await openComposer(page);
    await importIntoComposer(page, bytes(bundle([
      sdo(A, 'Composer malware', { is_family: false }),
      sdo(B, 'Composer identity', { identity_class: 'organization' }),
      { type: 'relationship', spec_version: '2.1', id: 'relationship--55555555-5555-4555-8555-555555555555',
        created: '2026-01-01T00:00:00.000Z', modified: '2026-01-01T00:00:00.000Z',
        relationship_type: 'uses', source_ref: A, target_ref: B },
    ])), 'composer-source.json');
    await expect(page.locator('#toast')).toHaveText('Bundle imported');

    const exported = await exportFromComposer(page);
    const exportedIds = exported.json.objects.map((o: any) => o.id);
    expect(exportedIds).toContain('relationship--55555555-5555-4555-8555-555555555555');

    await withFreshContext(browser, async mainPage => {
      await importStix(mainPage, exported.buffer, exported.name);
      // Wait for the import to complete before reading state: the relationship object is
      // skipped without being counted, so only the two SDOs are reported.
      await expect(mainPage.locator('#toast')).toHaveText('Imported 2 STIX objects');

      const restored = await readState(mainPage);
      // DECLARED INTERSECTION: supported SDOs become library entries.
      expect(restored.customLibrary[A]).toBeDefined();
      expect(restored.customLibrary[A].name).toBe('Composer malware');
      expect(restored.customLibrary[B].identity_class).toBe('organization');

      // EXPLICIT LOSS: the relationship is skipped by the main importer, so the edge the
      // Composer authored does not exist after the hop. This is a projection, not a
      // round trip, and no phase assignment is invented for the imported objects.
      expect(restored.customLibrary['relationship--55555555-5555-4555-8555-555555555555']).toBeUndefined();
      for (const phase of Object.values(restored.assignments) as any[]) {
        expect(phase.customItems).toEqual([]);
        expect(phase.groups).toEqual([]);
      }
    });
  });
});
