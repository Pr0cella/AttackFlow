// RT-10 Composer import decisions and RT-11 cross-page file workflows.
//
// SCOPE, stated so this file is never read as more than it is: the Composer defines 40
// object types and 262 field descriptors, including structured shapes the main editor has
// no analogue for (dictionary, hashes, extensions, kill-chain-phases, object-refs). An
// exhaustive per-field matrix for that surface is outstanding work and is NOT here.
// What is covered is the Composer lifecycle, every import decision branch, and the
// declared cross-page intersection with its losses stated explicitly.
//
// The Composer's own sanitization defects -- imported strings losing the bracket and quote
// characters a STIX pattern needs, and numeric editor values reaching HTML attributes
// unencoded -- are held open in stix-builder-security.spec.ts and are not re-asserted here.

import { expect, test, type Page } from '@playwright/test';
import {
  exportStix, expectNoDownload, expectNoExternalRequests, importNative, importStix,
  installRequestGuard, openApp, readState, withFreshContext,
} from './helpers/roundtrip';

const bytes = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8');

test.use({ serviceWorkers: 'block' });
test.afterEach(async ({ page }) => expectNoExternalRequests(page));

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

/**
 * The exact objects the RT-09 lifecycle must carry, hand-authored from the fixture plus
 * the one edit the test performs. Asserted on every artifact in the flow so a field lost
 * or overwritten between stages fails where an id/count check cannot see it.
 */
const LIFECYCLE_OBJECTS = [
  {
    type: 'malware', spec_version: '2.1', id: A,
    created: '2026-01-01T00:00:00.000Z', modified: '2026-01-02T00:00:00.000Z',
    name: 'Edited lifecycle malware', is_family: false, description: 'Initial description',
  },
  {
    type: 'identity', spec_version: '2.1', id: B,
    created: '2026-01-01T00:00:00.000Z', modified: '2026-01-02T00:00:00.000Z',
    name: 'Lifecycle identity', identity_class: 'organization',
  },
];

function expectLifecycleBundle(json: any, label: string) {
  expect(json.type, `${label} envelope type`).toBe('bundle');
  expect(json.spec_version, `${label} spec version`).toBe('2.1');
  expect(json.id, `${label} bundle id`).toMatch(/^bundle--[0-9a-f-]{36}$/);
  const byId = (objects: any[]) => [...objects].sort((x, y) => x.id.localeCompare(y.id));
  expect(byId(json.objects), `${label} objects`)
    .toEqual(byId(LIFECYCLE_OBJECTS));
}

async function openComposer(page: Page) {
  const blocked = await installRequestGuard(page.context());
  await page.goto('/stix-builder.html');
  await expect(page.locator('#add-object')).toBeVisible({ timeout: 60_000 });
  return blocked;
}

/**
 * Uploads a bundle and waits for the import to actually finish.
 *
 * `decisions` answers the confirm sequence in order: importBundle() asks "Replace?" and,
 * if that is declined, "Merge?". Each dialog is awaited explicitly rather than slept
 * through, and the returned promise resolves only once the operation has COMPLETED, not
 * merely once the declared decisions were answered.
 *
 * Why that distinction matters: `setInputFiles` returns before FileReader.onload runs. A
 * helper that resolved as soon as its declared decisions were answered removed its dialog
 * listener immediately when no decisions were declared, so a prompt that should never have
 * appeared was auto-dismissed by Playwright, unseen, and `expect(asked).toEqual([])`
 * passed vacuously. The listener now stays installed until the operation finishes, and any
 * undeclared prompt is reported.
 *
 * Completion signal, never a sleep: importBundle() calls showToast() on every path except
 * one -- declining both Replace and Merge hits `return` with no trace. That single case
 * declares `completesWithToast: false`, where answering the last declared decision IS
 * completion because only `return` follows it.
 */
type ComposerImportOptions = { completesWithToast?: boolean };

async function importIntoComposer(
  page: Page, buffer: Buffer, name = 'composer.json', decisions: ('accept' | 'dismiss')[] = [],
  options: ComposerImportOptions = {},
) {
  await page.locator('#toast').evaluate(element => { element.textContent = ''; });

  const seen: string[] = [];
  const answered = decisions.map(() => {
    let resolve!: () => void;
    const promise = new Promise<void>(r => { resolve = r; });
    return { promise, resolve };
  });
  const undeclared: string[] = [];
  const handler = async (dialog: any) => {
    const index = seen.length;
    seen.push(dialog.message());
    const decision = decisions[index];
    if (decision === undefined) undeclared.push(dialog.message());
    // An undeclared prompt is dismissed rather than left pending, so the run reports it
    // instead of hanging on a modal nobody answers.
    if (decision === 'accept') await dialog.accept();
    else await dialog.dismiss();
    answered[index]?.resolve();
  };
  page.on('dialog', handler);
  try {
    await page.locator('#bundle-file').setInputFiles({ name, mimeType: 'application/json', buffer });
    // Every declared decision must actually have been asked and answered.
    await Promise.all(answered.map(a => a.promise));
    if (options.completesWithToast ?? true) {
      try {
        await expect(page.locator('#toast')).not.toBeEmpty();
      } catch (error) {
        // An undeclared prompt can suppress the toast entirely (the both-declined path).
        // Report that cause below rather than a misleading toast timeout.
        if (undeclared.length === 0) throw error;
      }
    }
  } finally {
    page.off('dialog', handler);
  }
  expect(undeclared, 'the Composer asked a confirm this test did not declare').toEqual([]);
  expect(seen, 'every declared decision must have been asked').toHaveLength(decisions.length);
  return seen;
}

/** Completion signal: importBundle() sets a toast on every outcome, success or failure. */
async function settleComposerImport(page: Page) {
  await expect(page.locator('#toast')).not.toBeEmpty();
  return (await page.locator('#toast').textContent()) || '';
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
      // No confirm is shown while the bundle is empty, so no decisions are supplied.
      const asked = await importIntoComposer(page, bytes(bundle([sdo(A, 'First malware')])), 'first.json');
      expect(asked, 'an empty bundle must not prompt').toEqual([]);
      expect(await settleComposerImport(page)).toBe('Bundle imported');
      expect((await composerState(page)).objects.map((o: any) => o.id)).toEqual([A]);
    });

    await test.step('declining replace then declining merge leaves the bundle untouched', async () => {
      const before = await composerState(page);
      // The only path that sets no toast: `if (!confirm('Merge ...')) return;`. Answering
      // the second decline IS completion here, since only `return` follows it.
      const asked = await importIntoComposer(page,
        bytes(bundle([sdo(B, 'Second identity')])), 'declined.json', ['dismiss', 'dismiss'],
        { completesWithToast: false });

      // Both questions were actually asked, in order, and both were answered before the
      // state below is read. The previous version slept 300ms and hoped.
      expect(asked).toHaveLength(2);
      expect(asked[0]).toContain('Replace');
      expect(asked[1]).toContain('Merge');
      expect(await composerState(page)).toEqual(before);
    });

    await test.step('declining replace then accepting merge adds without removing', async () => {
      const asked = await importIntoComposer(page,
        bytes(bundle([sdo(B, 'Second identity')])), 'merge.json', ['dismiss', 'accept']);
      expect(asked).toHaveLength(2);
      expect(await settleComposerImport(page)).toBe('Bundle imported');

      const state = await composerState(page);
      expect(state.objects.map((o: any) => o.id).sort()).toEqual([A, B].sort());
      expect(state.objects).toHaveLength(2);
    });

    await test.step('a duplicate id is skipped during merge rather than overwriting', async () => {
      // Same id as A, different content: the incoming object must not win.
      await importIntoComposer(page,
        bytes(bundle([sdo(A, 'CONFLICTING malware')])), 'dupe.json', ['dismiss', 'accept']);
      expect(await settleComposerImport(page)).toBe('Bundle imported');

      // Asserted AFTER completion, and on both content and count, so an unchanged object
      // that merely predates the FileReader cannot satisfy this.
      const state = await composerState(page);
      expect(state.objects).toHaveLength(2);
      expect(state.objects.filter((o: any) => o.id === A)).toHaveLength(1);
      expect(state.objects.find((o: any) => o.id === A).name).toBe('First malware');
    });

    await test.step('accepting replace discards the current bundle entirely', async () => {
      const asked = await importIntoComposer(page,
        bytes(bundle([sdo(C, 'Replacement tool')])), 'replace.json', ['accept']);
      expect(asked, 'accepting replace must not also ask about merge').toHaveLength(1);
      expect(asked[0]).toContain('Replace');
      expect(await settleComposerImport(page)).toBe('Bundle imported');
      expect((await composerState(page)).objects.map((o: any) => o.id)).toEqual([C]);
    });
  });

  test('malformed bundles are refused with a diagnostic', async ({ page }) => {
    await openComposer(page);
    await importIntoComposer(page, bytes(bundle([sdo(A, 'Baseline')])), 'baseline.json');
    await expect(page.locator('#toast')).toHaveText('Bundle imported');
    const before = await composerState(page);

    // No dialog listener here on purpose: a malformed bundle throws before importBundle()
    // reaches any confirm(), and the helper now FAILS on an undeclared prompt, which
    // proves that rather than quietly accepting one.
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
  });

  test('an empty bundle replaces the current one with nothing', async ({ page }) => {
    await openComposer(page);
    await importIntoComposer(page, bytes(bundle([sdo(A, 'Baseline')])), 'baseline.json');
    await expect(page.locator('#toast')).toHaveText('Bundle imported');

    // The decision is DECLARED through the helper rather than answered by a second
    // listener. Two handlers race for the same dialog -- one of them then fails with
    // "already handled" -- and neither test can say which prompts were actually asked.
    const asked = await importIntoComposer(page, bytes(bundle([])), 'empty.json', ['accept']);
    expect(asked, 'replacing a non-empty bundle asks exactly once').toHaveLength(1);
    expect(asked[0]).toContain('Replace');
    await expect(page.locator('#toast')).toHaveText('Bundle imported');

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
      await expectNoDownload(page, () => page.locator('#export-bundle').click());
    });

    await test.step('accepting the confirm exports the bundle as-is', async () => {
      page.once('dialog', dialog => dialog.accept());
      const exported = await exportFromComposer(page);
      expect(exported.name).toBe('stix-bundle.json');
      expect(exported.json.objects).toHaveLength(1);
    });
  });
});

test.describe('RT-09 Composer lifecycle (representative, not the full field matrix)', () => {
  test('create, edit, download, reimport in a fresh Composer and download again', async ({ page, browser }) => {
    await openComposer(page);

    // PLAIN EVIDENCE ONLY, deliberately. The Composer strips [ ] { } ; " ' ` from every
    // imported string today -- the separate sanitization case in
    // stix-builder-security.spec.ts holds that open -- so punctuation-rich evidence cannot
    // survive this flow yet. Marking the whole lifecycle as an expected failure would
    // demonstrate no lifecycle at all, so this proves the stages are wired end to end and
    // punctuation is added to this same flow once the sanitizer is fixed.
    await importIntoComposer(page, bytes(bundle([
      sdo(A, 'Lifecycle malware', { is_family: false, description: 'Initial description' }),
      sdo(B, 'Lifecycle identity', { identity_class: 'organization' }),
    ])), 'lifecycle-source.json');
    expect(await settleComposerImport(page)).toBe('Bundle imported');

    // Ordinary edit through the real editor field, not a state poke.
    await page.evaluate(id => {
      (eval('state') as any).ui.activeObjectId = id;
      (window as any).renderEditor();
    }, A);
    const nameField = page.locator('[data-field="name"]');
    await expect(nameField).toBeVisible();
    await nameField.fill('Edited lifecycle malware');
    await nameField.blur();

    const edited = await composerState(page);
    expect(edited.objects.find((o: any) => o.id === A).name).toBe('Edited lifecycle malware');

    const first = await exportFromComposer(page);
    expect(first.json.objects).toHaveLength(2);

    await withFreshContext(browser, async freshPage => {
      await openComposer(freshPage);
      expect((await composerState(freshPage)).objects, 'fresh Composer starts empty').toEqual([]);

      await importIntoComposer(freshPage, first.buffer, first.name);
      expect(await settleComposerImport(freshPage)).toBe('Bundle imported');

      const restored = await composerState(freshPage);
      expect(restored.objects.map((o: any) => o.id).sort()).toEqual([A, B].sort());
      expect(restored.objects.find((o: any) => o.id === A).name).toBe('Edited lifecycle malware');
      expect(restored.objects.find((o: any) => o.id === A).description).toBe('Initial description');
      expect(restored.objects.find((o: any) => o.id === B).identity_class).toBe('organization');

      const second = await exportFromComposer(freshPage);
      // BOTH downloads are compared against the hand-authored record, not against each
      // other and not by identity alone. Counting objects and ids in the final artifact
      // let an exporter that replaced every name and description still pass, because
      // neither the count nor the ids changed.
      expectLifecycleBundle(first.json, 'first download');
      expectLifecycleBundle(second.json, 'final download');
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
      const importedIds = state.objects.map((o: any) => o.id).sort();

      // The population is HAND-AUTHORED from the fixture, not copied from the export.
      // `EXPECTED_KEPT = [...sourceIds]` made the transfer its own oracle: it proved the
      // two sides agreed, which they would even if both were wrong, and it said nothing
      // about what should have been there. Counts are pinned on BOTH sides instead.
      //
      // Derived from the fixture: one technique projects to one attack-pattern and its
      // five reviewed mitigations, each with a mitigates edge; the two custom SDOs share
      // a phase, producing exactly one co-location edge. Nothing else may cross.
      const EXPECTED_POPULATION: Record<string, number> = {
        'malware': 1, 'identity': 1, 'attack-pattern': 1, 'course-of-action': 5,
        'relationship': 6,
      };
      const countByType = (objects: any[]) => objects.reduce((counts: any, o: any) => {
        counts[o.type] = (counts[o.type] || 0) + 1;
        return counts;
      }, {});
      expect(countByType(exported.json.objects), 'exported population').toEqual(EXPECTED_POPULATION);
      expect(countByType(state.objects), 'population after the hop').toEqual(EXPECTED_POPULATION);
      expect(importedIds, 'no object may be lost or duplicated by the hop')
        .toEqual([...sourceIds].sort());
      expect(new Set(importedIds).size).toBe(importedIds.length);

      // COMPLETE edge records across the hop, not merely resolvable endpoints. Endpoint
      // resolution alone accepted a Composer that rewrote every target_ref to equal its
      // source_ref: the edges still pointed at objects that existed.
      const importedEdges = state.objects.filter((o: any) => o.type === 'relationship');
      const edgeRecord = (o: any) => JSON.stringify(o, Object.keys(o).sort());
      const tally = (edges: any[]) => edges.map(edgeRecord).sort();
      expect(tally(importedEdges), 'relationship records must survive the hop unchanged')
        .toEqual(tally(sourceRelationships));

      // Hand-authored topology for this fixture, independent of both artifacts.
      const patternId = state.objects.find((o: any) => o.type === 'attack-pattern').id;
      const mitigates = importedEdges.filter((e: any) => e.relationship_type === 'mitigates');
      expect(mitigates, 'one mitigates edge per derived mitigation').toHaveLength(5);
      for (const edge of mitigates) expect(edge.target_ref).toBe(patternId);

      const coLocation = importedEdges.filter((e: any) => e.relationship_type !== 'mitigates');
      expect(coLocation, 'exactly one co-location edge').toHaveLength(1);
      expect(coLocation[0].source_ref).toBe(A);
      expect(coLocation[0].target_ref).toBe(B);
      expect(coLocation[0].description).toBe('Co-located in phase IN:reconnaissance');
      // CURRENT BEHAVIOR, pinned not endorsed: every co-location edge is `related-to`
      // whatever the endpoint types, because addRelationship() reads the FLAT
      // STIX_RELATIONSHIP_MAP two levels deep (`[sourceType]?.[targetType]`), which
      // indexes into a string and is always undefined, so the configured defaults --
      // malware `uses`, indicator `indicates` -- can never apply. Already recorded as
      // confirmed current behavior in the coverage audit; whether the map should be
      // nested or the lookup flattened is an open product decision, so this asserts
      // today's output rather than marking a guessed contract as an expected failure.
      expect(coLocation[0].relationship_type).toBe('related-to');

      const presentIds = new Set(importedIds);
      for (const edge of importedEdges) {
        expect(presentIds.has(edge.source_ref), `dangling source_ref ${edge.source_ref}`).toBe(true);
        expect(presentIds.has(edge.target_ref), `dangling target_ref ${edge.target_ref}`).toBe(true);
      }

      // Exact supported-field expectations in this direction.
      const malware = state.objects.find((o: any) => o.id === A);
      expect(malware.name).toBe('Cross malware');
      expect(malware.type).toBe('malware');
      const identity = state.objects.find((o: any) => o.id === B);
      expect(identity.name).toBe('Cross identity');
      expect(identity.identity_class).toBe('organization');
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
      // DECLARED INTERSECTION: supported SDOs become library entries, and EXACTLY those.
      // Naming the complete key set matters as much as naming what is kept: without it an
      // importer that invented an extra library entry would pass unnoticed.
      expect(Object.keys(restored.customLibrary).sort(), 'exact restored library population')
        .toEqual([A, B].sort());
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
