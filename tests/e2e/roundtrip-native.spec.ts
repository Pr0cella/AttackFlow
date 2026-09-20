// RT-01..RT-05 and RT-15: native kill-chain document preservation across
// import -> UI edit -> real download -> fresh-context import -> second download.
//
// Every expectation comes from tests/fixtures/roundtrip/native.ts, which is authored by
// hand from the documented contract. Production sanitizers are never used to build an
// oracle, and a first-cycle loss is never allowed to become the second-cycle baseline.

import fs from 'node:fs';
import path from 'node:path';
import { expect, test, type Page } from '@playwright/test';
import {
  ALL_PHASES, ASSIGNMENT_KEYS, NATIVE_EXPORT_KEYS, dispatchDragAndDrop, exportNative, expectInertRender,
  expectIsoTimestampWithin, expectNativeExportsEquivalent, expectNoExternalRequests,
  importNative, openApp, readState, withFreshContext,
} from './helpers/roundtrip';
import {
  ALL_OBSERVABLE_TYPES, DESCRIPTION_STORED, EVIDENCE_LINES, EVIDENCE_STORED, FULL_PHASES,
  GROUPS, IDS, TITLE, URL_BRACKETS_REJECTED, VECTOR_31, expectedFullAssignments,
  expectedFullLibrary, expectedLegacyRecon, nativeFull, nativeLegacy, nativeMinimal,
} from '../fixtures/roundtrip/native';

const REPO_ROOT = path.resolve(__dirname, '../..');
const bytes = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8');

test.use({ serviceWorkers: 'block' });
test.afterEach(async ({ page }) => expectNoExternalRequests(page));

/** Strips generated instance ids after validating their syntax and uniqueness. */
function stripInstanceIds(phase: any) {
  const seen = new Set<string>();
  const copy = JSON.parse(JSON.stringify(phase));
  const visit = (items: any[]) => {
    for (const entry of items || []) {
      expect(entry.instanceId, 'generated instance id').toMatch(/^itm-[a-z0-9]+-\d+$/);
      expect(seen.has(entry.instanceId), `duplicate instance id ${entry.instanceId}`).toBe(false);
      seen.add(entry.instanceId);
      delete entry.instanceId;
    }
  };
  for (const key of ASSIGNMENT_KEYS) visit(copy[key]);
  for (const group of copy.groups || []) visit(group.items);

  // Layout entries reference the generated ids that were just stripped, so they cannot be
  // compared against a hand-authored expectation. Rather than delete them and claim a
  // comprehensive preservation check, assert that every entry still resolves to something
  // present, then drop the ids. This case is a METADATA test, not a layout-order test.
  for (const entry of copy.layout || []) {
    if (entry.kind === 'group') {
      expect((copy.groups || []).some((g: any) => g.groupId === entry.groupId),
        `layout group ${entry.groupId} must exist`).toBe(true);
    } else {
      expect(seen.has(entry.instanceId), `layout item ${entry.instanceId} must exist`).toBe(true);
    }
  }
  delete copy.layout;
  return copy;
}

test.describe('RT-01 minimal native document', () => {
  test('exports, reimports in a fresh context, and converges', async ({ page, browser }) => {
    const startedAt = Date.now();
    const blocked = await openApp(page);

    // The phase roster is verified independently so a silently removed phase is detected.
    const runtimePhases = await page.evaluate(() => eval('ALL_PHASES'));
    expect(runtimePhases).toEqual([...ALL_PHASES]);

    await importNative(page, bytes(nativeMinimal()), 'rt-01-minimal.json');

    const imported = await readState(page);
    expect(Object.keys(imported.assignments).sort()).toEqual([...ALL_PHASES].sort());
    for (const phase of ALL_PHASES) {
      expect(imported.assignments[phase], `empty phase ${phase}`).toEqual({
        techniques: [], capecs: [], cwes: [], customItems: [], groups: [], layout: [],
      });
    }
    expect(imported.customLibrary).toEqual({});
    expect(imported.title).toBe('');
    expect(imported.description).toBe('');
    expect(imported.view).toBe('killchain');
    expect(imported.activeTab).toBe('attack');
    expect(imported.layers).toEqual({ attack: true, capec: true, cwe: true, custom: true });
    expect(imported.hideEmpty).toBe(false);

    const first = await exportNative(page);
    expect(first.name).toBe('attack-chain-export.json');
    // An empty custom library must not produce an embedded bundle.
    expect(Object.keys(first.json).sort()).toEqual([...NATIVE_EXPORT_KEYS].sort());
    expect(first.json).not.toHaveProperty('stixBundle');
    expect(typeof first.json.version).toBe('string');
    expect(first.json.version.length).toBeGreaterThan(0);
    expect(first.json.schema).toBe('killchain-export-lite');
    expectIsoTimestampWithin(first.json.exportedAt, startedAt);

    await withFreshContext(browser, async freshPage => {
      expect((await readState(freshPage)).customLibrary).toEqual({});
      await importNative(freshPage, first.buffer, first.name);
      expect(await readState(freshPage)).toEqual(imported);

      const second = await exportNative(freshPage);
      expectIsoTimestampWithin(second.json.exportedAt, startedAt);
      expectNativeExportsEquivalent(first.json, second.json, startedAt);
    });

    expect(blocked, 'no external request may be attempted').toEqual([]);
  });
});

test.describe('RT-02/RT-03 complete native document', () => {
  test('preserves fields, instance identity, groups and layout across two cycles', async ({ page, browser }) => {
    test.setTimeout(120_000);
    const startedAt = Date.now();
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await openApp(page);
    await importNative(page, bytes(nativeFull()), 'rt-02-full.json');

    const expectedAssignments = expectedFullAssignments();
    const expectedLibrary = expectedFullLibrary();
    let imported = await readState(page);

    await test.step('imported state matches the independent oracle', async () => {
      expect(imported.assignments).toEqual(expectedAssignments);
      expect(imported.customLibrary).toEqual(expectedLibrary);
      expect(imported.title).toBe(TITLE);
      expect(imported.description).toBe(DESCRIPTION_STORED);
      expect(imported.activeTab).toBe('capec');
      expect(imported.layers).toEqual({ attack: true, capec: false, cwe: true, custom: true });
      expect(imported.hideEmpty).toBe(false);
    });

    await test.step('repeated entities keep distinct instances and metadata', async () => {
      const recon = imported.assignments[FULL_PHASES.recon];
      const exploitation = imported.assignments[FULL_PHASES.exploitation];
      const lateral = imported.assignments[FULL_PHASES.lateral];

      // T1595 appears three times across two phases without collapsing.
      const t1595 = [
        ...recon.techniques.filter(a => a.id === 'T1595'),
        ...exploitation.techniques.filter(a => a.id === 'T1595'),
      ];
      expect(t1595.map(a => a.instanceId)).toEqual(['itm-rt-001', 'itm-rt-010', 'itm-rt-011']);
      expect(new Set(t1595.map(a => a.metadata.score)).size).toBe(3);

      // The same custom identity is ungrouped in one phase and grouped in another.
      expect(recon.customItems[0].id).toBe(IDS.identity);
      expect(lateral.groups[0].items[0].id).toBe(IDS.identity);
      expect(recon.customItems[0].instanceId).not.toBe(lateral.groups[0].items[0].instanceId);

      // A library entry with no assignment anywhere survives.
      const assignedIds = new Set(Object.values(imported.assignments).flatMap((phase: any) => [
        ...phase.customItems.map((a: any) => a.id),
        ...phase.groups.flatMap((g: any) => g.items.filter((i: any) => i.type === 'custom').map((i: any) => i.id)),
      ]));
      expect(assignedIds.has(IDS.tool)).toBe(false);
      expect(imported.customLibrary[IDS.tool]).toBeDefined();
    });

    await test.step('documented trust-boundary normalizations stay exactly as specified', async () => {
      const meta = imported.assignments[FULL_PHASES.recon].techniques[0].metadata;

      // Newlines are removed with no replacement separator, at both trust boundaries.
      // Every printable line survives verbatim; only the separators are gone.
      expect(meta.comments).toBe(EVIDENCE_STORED);
      expect(meta.comments).not.toContain('\n');
      for (const line of EVIDENCE_LINES) expect(meta.comments).toContain(line);

      // A URL containing raw brackets fails the http(s) allowlist and its entry is
      // dropped whole rather than being silently rewritten into a different URL.
      expect(meta.hyperlinks.map((h: any) => h.url)).not.toContain(URL_BRACKETS_REJECTED);
      expect(meta.hyperlinks.some((h: any) => h.label === 'Rejected brackets')).toBe(false);
      expect(meta.hyperlinks).toHaveLength(2);
    });

    await test.step('every observable type and score enum survives', async () => {
      const meta = imported.assignments[FULL_PHASES.recon].techniques[0].metadata;
      expect(meta.observables.map((o: any) => o.type)).toEqual([...ALL_OBSERVABLE_TYPES]);
      const scores = new Set(Object.values(imported.assignments).flatMap((phase: any) => [
        ...ASSIGNMENT_KEYS.flatMap(key => phase[key].map((a: any) => a.metadata.score)),
        ...phase.groups.flatMap((g: any) => g.items.map((i: any) => i.metadata.score)),
      ]));
      expect([...scores].sort()).toEqual(['critical', 'high', 'low', 'medium', 'unclassified']);
    });

    const first = await exportNative(page);

    await test.step('first download reflects state and does not mutate it', async () => {
      // Slug contract: runs of characters outside [A-Za-z0-9_-] collapse to one hyphen,
      // literal hyphens in the title are kept, and trailing hyphens are trimmed.
      expect(first.name).toBe('RT-02-Full-Native-doc-title---chain.json');
      expect(Object.keys(first.json).sort()).toEqual([...NATIVE_EXPORT_KEYS, 'stixBundle'].sort());
      expect(first.json.assignments).toEqual(expectedAssignments);
      expect(first.json.customLibrary).toEqual(expectedLibrary);
      expect(first.json.title).toBe(TITLE);
      expectIsoTimestampWithin(first.json.exportedAt, startedAt);
      expect(await readState(page)).toEqual(imported);
    });

    await expectInertRender(page, errors);

    await test.step('fresh-context reimport and second download converge', async () => {
      await withFreshContext(browser, async freshPage => {
        const freshErrors: string[] = [];
        freshPage.on('pageerror', error => freshErrors.push(error.message));
        await importNative(freshPage, first.buffer, first.name);

        const restored = await readState(freshPage);
        expect(restored.assignments).toEqual(expectedAssignments);
        expect(restored.customLibrary).toEqual(expectedLibrary);
        expect(restored).toEqual(imported);

        // Restored evidence renders as inert text, not as markup.
        await expect(freshPage.locator(`[data-phase="${FULL_PHASES.recon}"]`)).toBeVisible();
        await expectInertRender(freshPage, freshErrors);

        const second = await exportNative(freshPage);
        expectNativeExportsEquivalent(first.json, second.json, startedAt);

        // Third cycle: evidence-rich documents must not accumulate encoding or duplicates.
        await importNative(freshPage, second.buffer, second.name);
        expect(await readState(freshPage)).toEqual(imported);
        const third = await exportNative(freshPage);
        expectNativeExportsEquivalent(first.json, third.json, startedAt);
      });
    });

    imported = await readState(page);
    expect(imported.assignments).toEqual(expectedAssignments);
  });
});

// Expected-failure convention, applied across this suite:
//   - the marker sits INSIDE the test, immediately before the behavior that is known to
//     be broken, so setup, upload, export and prerequisite assertions above it still
//     count as unexpected failures rather than earning known-gap credit;
//   - independent contracts get independent tests, so the first failure cannot hide a
//     second one.

test.describe('RT-02 native persistence gaps', () => {
  // AF-RT-003 covers two separable contracts. They are asserted apart so that restoring
  // one without the other is visible rather than masked by the first failure.
  for (const field of ['filters', 'selection'] as const) {
    test(`restores exported ${field}`, async ({ page, browser }) => {
      const expected = {
        filters: { attack: 'enterprise', capec: 'all', cwe: 'all', custom: 'all' },
        selection: { type: 'attack', id: 'T1595' },
      }[field];

      await openApp(page);
      await importNative(page, bytes(nativeFull()), `rt-af-rt-003-${field}.json`);
      await page.evaluate(({ key, value }) => { (eval('state') as any)[key] = value; },
        { key: field, value: expected });

      // Prerequisite: the exporter really does write the field. If this breaks, the
      // finding has changed shape and the failure must NOT be credited to AF-RT-003.
      const exported = await exportNative(page);
      expect(exported.json[field]).toEqual(expected);

      await withFreshContext(browser, async freshPage => {
        await importNative(freshPage, exported.buffer, exported.name);
        const restored = await readState(freshPage);

        test.fail(true, `Known gap AF-RT-003: ${field} is exported but never restored`);
        // Desired behavior: a value the exporter writes is a value the importer restores.
        expect(restored[field]).toEqual(expected);
      });
    });
  }
});

test.describe('RT-02 view restoration', () => {
  test('restores the relationship view through a native round trip', async ({ page, browser }) => {
    await openApp(page);
    await importNative(page, bytes(nativeFull()), 'rt-af-rt-001.json');
    await page.evaluate(() => (window as any).setView('relationship'));

    // Prerequisites: the app holds the view and the exporter writes it. Both work today,
    // so a failure here is a real regression, not the known import-allowlist gap.
    expect((await readState(page)).view).toBe('relationship');
    const exported = await exportNative(page);
    expect(exported.json.view).toBe('relationship');

    await withFreshContext(browser, async freshPage => {
      await importNative(freshPage, exported.buffer, exported.name);

      test.fail(true, "Known gap AF-RT-001: import allowlists 'relations' but the app and export use 'relationship'");
      expect((await readState(freshPage)).view).toBe('relationship');
    });
  });
});

test.describe('RT-15 legacy metadata keys', () => {
  test('imports metadata.cves the way the rest of the app reads it', async ({ page }) => {
    await openApp(page);
    const legacy = {
      assignments: {
        'IN:exploitation': {
          techniques: [{
            id: 'T1190', instanceId: 'itm-rt-cves',
            metadata: { cves: [{ id: 'CVE-2024-3400', score: '10.0', vector: VECTOR_31 }] },
          }],
        },
      },
    };
    await importNative(page, bytes(legacy), 'rt-af-rt-002.json');

    // Prerequisite: the document imported at all and the assignment survived. Only the
    // CVE projection below is the known gap.
    const assignment = (await readState(page)).assignments['IN:exploitation'].techniques[0];
    expect(assignment.id).toBe('T1190');

    test.fail(true, 'Known gap AF-RT-002: sanitizeAssignmentMetadata ignores the legacy cves key that getCveEntries accepts');
    // getCveEntries() reads `cves`; the import sanitizer is the only reader that does not.
    expect(assignment.metadata.cveEntries).toEqual([{ id: 'CVE-2024-3400', score: 10, vector: VECTOR_31 }]);
  });
});

test.describe('RT-15 shipped example documents', () => {
  for (const name of ['demo.json', 'grouping-demo.json', 'stix-demo.json']) {
    test(`${name} imports, exports and converges in a fresh context`, async ({ page, browser }) => {
      const startedAt = Date.now();
      const source = fs.readFileSync(path.join(REPO_ROOT, 'examples', name));
      await openApp(page);
      await importNative(page, source, name);

      const imported = await readState(page);

      // FIRST-IMPORT ORACLE, read from the shipped file itself rather than from the
      // already-imported state. Comparing cycle two to cycle one proves convergence but
      // is blind to a loss that happens on the FIRST import, which is how this suite
      // previously let `stix-demo.json` drop its legacy CVE unnoticed.
      const sourceDoc = JSON.parse(source.toString('utf8'));
      for (const [phaseKey, sourcePhase] of Object.entries(sourceDoc.assignments) as [string, any][]) {
        const restored = imported.assignments[phaseKey];
        expect(restored, `phase ${phaseKey} must exist after import`).toBeDefined();
        for (const key of ASSIGNMENT_KEYS) {
          const expectedIds = (sourcePhase[key] || []).map((a: any) => a.id ?? a);
          expect(restored[key].map((a: any) => a.id), `${phaseKey}.${key} ids and order`)
            .toEqual(expectedIds);
        }
        const sourceGroups = sourcePhase.groups || [];
        expect(restored.groups.length, `${phaseKey} group count`).toBe(sourceGroups.length);
        for (const [index, sourceGroup] of sourceGroups.entries()) {
          expect(restored.groups[index].label, `${phaseKey} group ${index} label`)
            .toBe(sourceGroup.label);
          expect(restored.groups[index].items.map((i: any) => i.id), `${phaseKey} group ${index} items`)
            .toEqual((sourceGroup.items || []).map((i: any) => i.id));
        }
        // Evidence the runtime preserves verbatim today: score and comments.
        for (const key of ASSIGNMENT_KEYS) {
          for (const [index, sourceItem] of (sourcePhase[key] || []).entries()) {
            const sourceMeta = sourceItem.metadata || {};
            if (typeof sourceMeta.score === 'string') {
              expect(restored[key][index].metadata.score, `${phaseKey}.${key}[${index}] score`)
                .toBe(sourceMeta.score);
            }
            if (typeof sourceMeta.comments === 'string') {
              expect(restored[key][index].metadata.comments, `${phaseKey}.${key}[${index}] comments`)
                .toBe(sourceMeta.comments.replace(/[\u0000-\u001F\u007F]/g, '').trim().slice(0, 2000));
            }
          }
        }
      }
      // The whole shipped library survives; entry-level field fidelity is RP-02/RP-03.
      expect(Object.keys(imported.customLibrary).sort())
        .toEqual(Object.keys(sourceDoc.customLibrary || {}).sort());

      // Every assignment carries a full metadata object and a unique instance id.
      const instanceIds = new Set<string>();
      for (const [phaseKey, phase] of Object.entries(imported.assignments)) {
        for (const key of ASSIGNMENT_KEYS) {
          for (const entry of (phase as any)[key]) {
            expect(entry.metadata, `${phaseKey}.${key} metadata`).toMatchObject({
              score: expect.any(String), comments: expect.any(String),
              cveEntries: expect.any(Array), hyperlinks: expect.any(Array), observables: expect.any(Array),
            });
            expect(instanceIds.has(entry.instanceId), `duplicate ${entry.instanceId}`).toBe(false);
            instanceIds.add(entry.instanceId);
            expect(entry).not.toHaveProperty('type');
          }
        }
        for (const group of (phase as any).groups) {
          for (const entry of group.items) {
            expect(entry.type, 'grouped item keeps its type').toMatch(/^(attack|capec|cwe|custom)$/);
            expect(instanceIds.has(entry.instanceId), `duplicate ${entry.instanceId}`).toBe(false);
            instanceIds.add(entry.instanceId);
          }
        }
        // Every layout entry resolves to something that still exists.
        for (const entry of (phase as any).layout) {
          if (entry.kind === 'group') {
            expect((phase as any).groups.some((g: any) => g.groupId === entry.groupId)).toBe(true);
          } else {
            expect(instanceIds.has(entry.instanceId)).toBe(true);
          }
        }
      }

      const first = await exportNative(page);
      await withFreshContext(browser, async freshPage => {
        await importNative(freshPage, first.buffer, first.name);
        expect(await readState(freshPage)).toEqual(imported);
        const second = await exportNative(freshPage);
        expectNativeExportsEquivalent(first.json, second.json, startedAt);
      });
    });
  }

  test('legacy flat metadata and legacy CVE keys normalize as documented', async ({ page }) => {
    await openApp(page);
    await importNative(page, bytes(nativeLegacy()), 'rt-15-legacy.json');

    const recon = (await readState(page)).assignments['IN:reconnaissance'];
    expect(stripInstanceIds(recon)).toEqual(expectedLegacyRecon());
  });
});

// ---------------------------------------------------------------------------
// RT-04 group lifecycle
//
// Group deletion (accept, cancel, empty, malformed) is already covered end to end by
// group-metadata.spec.ts; this suite covers the rest of the lifecycle and the native
// round trip that follows it, rather than duplicating those assertions.
// ---------------------------------------------------------------------------

const cardFor = (instanceId: string) => `[draggable="true"]:has(.tag-action-btn.edit[onclick*="'${instanceId}'"])`;

test.describe('RT-04 group lifecycle', () => {
  test('create, rename, collapse, move and cancelled delete survive a native round trip', async ({ page, browser }) => {
    test.setTimeout(120_000);
    const startedAt = Date.now();
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await openApp(page);
    await importNative(page, bytes(nativeFull()), 'rt-04-groups.json');

    const recon = `[data-phase="${FULL_PHASES.recon}"]`;
    const exploitation = `[data-phase="${FULL_PHASES.exploitation}"]`;

    await test.step('create a group through the real control and rename it', async () => {
      await page.locator(`${recon} .phase-group-btn`).first().click();
      const created = await page.evaluate(key => {
        const groups = eval('state').assignments[key].groups;
        return groups[groups.length - 1].groupId;
      }, FULL_PHASES.recon);
      expect(created).toMatch(/^grp-[a-z0-9]+-[a-z0-9]{1,5}$/);

      // createGroup() opens the rename input immediately; commit with Enter.
      const input = page.locator(`#group-rename-${created}`);
      await expect(input).toBeVisible();
      await expect(input).toHaveValue('New Group');
      await input.fill('Renamed "group" <x> & --y');
      await input.press('Enter');

      const group = await page.evaluate(({ key, id }) => {
        return eval('state').assignments[key].groups.find((g: any) => g.groupId === id);
      }, { key: FULL_PHASES.recon, id: created });
      expect(group.label).toBe('Renamed "group" <x> & --y');
      // Rename leaves a transient UI flag in state; it must not reach the restored document.
      expect(group.editing).toBe(false);
      await expect(page.locator(`${recon} .phase-group[data-group-id="${created}"] .phase-group-title`))
        .toHaveText('Renamed "group" <x> & --y');
    });

    await test.step('collapse and expand through the real header control', async () => {
      const group = page.locator(`${recon} .phase-group[data-group-id="${GROUPS.mixed}"]`);
      const collapsed = () => page.evaluate(({ key, id }) =>
        eval('state').assignments[key].groups.find((g: any) => g.groupId === id).collapsed,
        { key: FULL_PHASES.recon, id: GROUPS.mixed });

      expect(await collapsed()).toBe(true);
      await group.locator('.phase-group-header').click();
      expect(await collapsed()).toBe(false);
      await expect(group).not.toHaveClass(/collapsed/);
      await group.locator('.phase-group-header').click();
      expect(await collapsed()).toBe(true);
      await expect(group).toHaveClass(/collapsed/);
    });

    await test.step('move an item out of a group and a group across phases', async () => {
      // Expand first so the grouped card is interactive.
      await page.locator(`${recon} .phase-group[data-group-id="${GROUPS.mixed}"] .phase-group-header`).click();

      // itm-rt-006 (CWE-79) leaves the mixed group for the exploitation phase.
      await dispatchDragAndDrop(page, cardFor('itm-rt-006'), exploitation);
      const afterItemMove = await readState(page);
      expect(afterItemMove.assignments[FULL_PHASES.recon].groups[0].items.map((i: any) => i.instanceId))
        .toEqual(['itm-rt-004', 'itm-rt-005']);
      const moved = afterItemMove.assignments[FULL_PHASES.exploitation].cwes;
      expect(moved).toHaveLength(1);
      expect(moved[0].instanceId).toBe('itm-rt-006');
      // Metadata travels with the instance.
      expect(moved[0].metadata.confidence).toBe(50);

      // The whole repeat group moves from lateral movement to exploitation.
      await dispatchDragAndDrop(page,
        `[data-phase="${FULL_PHASES.lateral}"] .phase-group[data-group-id="${GROUPS.dup}"] .phase-group-header`,
        exploitation);
      const afterGroupMove = await readState(page);
      expect(afterGroupMove.assignments[FULL_PHASES.lateral].groups).toEqual([]);
      const target = afterGroupMove.assignments[FULL_PHASES.exploitation].groups;
      expect(target).toHaveLength(1);
      expect(target[0].groupId).toBe(GROUPS.dup);
      expect(target[0].items[0].instanceId).toBe('itm-rt-021');
      // The source layout no longer references the departed group.
      expect(afterGroupMove.assignments[FULL_PHASES.lateral].layout
        .some((e: any) => e.kind === 'group' && e.groupId === GROUPS.dup)).toBe(false);
      expect(afterGroupMove.assignments[FULL_PHASES.exploitation].layout
        .filter((e: any) => e.kind === 'group' && e.groupId === GROUPS.dup)).toHaveLength(1);
    });

    await test.step('a cancelled delete changes nothing', async () => {
      const before = await readState(page);
      page.once('dialog', dialog => dialog.dismiss());
      await page.locator(`${recon} .phase-group[data-group-id="${GROUPS.mixed}"] .delete`).click();
      expect(await readState(page)).toEqual(before);
      await expect(page.locator(`${recon} .phase-group[data-group-id="${GROUPS.mixed}"]`)).toHaveCount(1);
    });

    const edited = await readState(page);
    const first = await exportNative(page);
    await expectInertRender(page, errors);

    await test.step('AF-RT-004: the transient rename flag leaks into the export but not back in', async () => {
      // commitRenameGroup() sets editing=false instead of deleting the key, and
      // exportJSON() serializes state.assignments verbatim, so a UI-only flag with no
      // place in the document schema reaches the downloaded file.
      const exportedGroups = first.json.assignments[FULL_PHASES.recon].groups;
      const renamed = exportedGroups.find((g: any) => g.label === 'Renamed "group" <x> & --y');
      expect(renamed, 'the renamed group is in the export').toBeDefined();
      expect(Object.prototype.hasOwnProperty.call(renamed, 'editing')).toBe(true);
      expect(renamed.editing).toBe(false);
      // Groups that were never renamed in this session carry no such flag.
      const untouched = exportedGroups.find((g: any) => g.groupId === GROUPS.empty);
      expect(Object.prototype.hasOwnProperty.call(untouched, 'editing')).toBe(false);
    });

    await test.step('the edited document restores with usable group controls', async () => {
      await withFreshContext(browser, async freshPage => {
        await importNative(freshPage, first.buffer, first.name);
        const restored = await readState(freshPage);

        // The transient rename flag is dropped by the importer; nothing else changes,
        // so the document converges to a clean shape on the second cycle.
        const expected = JSON.parse(JSON.stringify(edited));
        for (const phase of Object.values(expected.assignments) as any[]) {
          for (const group of phase.groups) delete group.editing;
        }
        expect(restored.assignments).toEqual(expected.assignments);
        for (const phase of Object.values(restored.assignments) as any[]) {
          for (const group of phase.groups) {
            expect(Object.prototype.hasOwnProperty.call(group, 'editing')).toBe(false);
          }
        }
        expect(restored.customLibrary).toEqual(edited.customLibrary);

        // Convergence is measured on the untouched restored document, before the
        // usability probe below mutates it.
        const second = await exportNative(freshPage);
        expectNativeExportsEquivalent(first.json, second.json, startedAt);

        // Restored controls still work: rename and collapse are both live.
        const group = freshPage.locator(`[data-phase="${FULL_PHASES.recon}"] .phase-group[data-group-id="${GROUPS.mixed}"]`);
        await expect(group).toHaveCount(1);
        await group.locator('.rename').click();
        await expect(freshPage.locator(`#group-rename-${GROUPS.mixed}`)).toBeVisible();
        await freshPage.locator(`#group-rename-${GROUPS.mixed}`).press('Escape');
        // Escape cancels the rename and re-renders; wait for the input to go before clicking.
        await expect(freshPage.locator(`#group-rename-${GROUPS.mixed}`)).toHaveCount(0);

        const collapsedIn = (target: typeof freshPage) => target.evaluate(({ key, id }) =>
          eval('state').assignments[key].groups.find((g: any) => g.groupId === id).collapsed,
          { key: FULL_PHASES.recon, id: GROUPS.mixed });
        const before = await collapsedIn(freshPage);
        await group.locator('.phase-group-header').click();
        expect(await collapsedIn(freshPage), 'restored collapse control still toggles').toBe(!before);
      });
    });
  });
});

// ---------------------------------------------------------------------------
// RT-05 editing lifecycle
// ---------------------------------------------------------------------------

test.describe('RT-05 editing lifecycle', () => {
  test('library fields and per-instance metadata edit independently and deletions stay deleted', async ({ page, browser }) => {
    test.setTimeout(120_000);
    const startedAt = Date.now();
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await openApp(page);
    await importNative(page, bytes(nativeFull()), 'rt-05-editing.json');

    let createdId = '';
    await test.step('create a custom object through the real modal', async () => {
      // The fixture restores the CAPEC tab, so reach the STIX panel the way a user does.
      await page.locator('.sidebar-tab.custom').click();
      await page.locator('button[onclick="openCreateCustomModal()"]').click();
      await expect(page.locator('#create-custom-modal')).toHaveClass(/visible/);
      await page.locator('#custom-stix-type').selectOption('threat-actor');
      await page.locator('#custom-name').fill('RT Created "actor" <x>');
      await page.locator('#custom-description').fill('Created through the modal & kept');
      await page.locator('#custom-labels').fill('rt-created, second--label');
      await page.locator('button[onclick="createCustomItem()"]').click();
      await expect(page.locator('#create-custom-modal')).not.toHaveClass(/visible/);

      const library = (await readState(page)).customLibrary;
      const entry = Object.values(library).find((e: any) => e.name === 'RT Created "actor" <x>') as any;
      expect(entry, 'created object is in the library').toBeDefined();
      createdId = entry.id;
      expect(createdId).toMatch(/^threat-actor--[0-9a-f-]{36}$/);
      expect(entry.description).toBe('Created through the modal & kept');
      expect(entry.labels).toEqual(['rt-created', 'second--label']);
    });

    await test.step('per-instance metadata edits do not touch the shared library entry', async () => {
      const libraryBefore = (await readState(page)).customLibrary;

      // Two instances of the same entity: editing one must not change the other.
      const card = page.locator(cardFor('itm-rt-010'));
      await card.hover();
      await card.locator('.tag-action-btn.edit').click();
      await expect(page.locator('#meta-comments')).toHaveValue('First exploitation instance');
      await page.locator('#meta-comments').fill('Edited first instance only');
      await page.locator('#meta-confidence').fill('88');
      await page.locator('button[onclick="saveMetadata()"]').click();

      const after = await readState(page);
      const instances = after.assignments[FULL_PHASES.exploitation].techniques;
      expect(instances[0].metadata.comments).toBe('Edited first instance only');
      expect(instances[0].metadata.confidence).toBe(88);
      // The sibling instance of the same technique is untouched.
      expect(instances[1].metadata.comments).toBe('Second exploitation instance');
      expect(instances[1].metadata.confidence).toBeNull();
      expect(after.customLibrary).toEqual(libraryBefore);
    });

    await test.step('library edits do not touch per-instance metadata', async () => {
      const assignmentsBefore = (await readState(page)).assignments;

      await page.evaluate(id => (window as any).openStixEditor(id), IDS.malware);
      await expect(page.locator('#edit-stix-modal')).toHaveClass(/visible/);
      await page.locator('#stix-edit-name').fill('Renamed RT Malware');
      await page.locator('.btn-stix-save').click();
      await expect(page.locator('#edit-stix-modal')).not.toHaveClass(/visible/);

      const after = await readState(page);
      expect(after.customLibrary[IDS.malware].name).toBe('Renamed RT Malware');
      // is_family false survives an unrelated edit rather than being dropped as falsy.
      expect(after.customLibrary[IDS.malware].is_family).toBe(false);
      expect(after.assignments).toEqual(assignmentsBefore);
    });

    await test.step('removing one assignment leaves the library entry and other instances', async () => {
      const card = page.locator(cardFor('itm-rt-011'));

      // A dismissed confirm must remove nothing at all.
      const before = await readState(page);
      page.once('dialog', dialog => dialog.dismiss());
      await card.hover();
      await card.locator('.tag-action-btn.remove').click();
      expect(await readState(page)).toEqual(before);

      page.once('dialog', dialog => dialog.accept());
      await card.hover();
      await card.locator('.tag-action-btn.remove').click();

      const after = await readState(page);
      const instances = after.assignments[FULL_PHASES.exploitation].techniques;
      expect(instances.map((a: any) => a.instanceId)).toEqual(['itm-rt-010']);
      expect(after.assignments[FULL_PHASES.exploitation].layout
        .some((e: any) => e.instanceId === 'itm-rt-011')).toBe(false);
      // Removing an assignment must not remove the entity from any other phase.
      expect(after.assignments[FULL_PHASES.recon].techniques[0].instanceId).toBe('itm-rt-001');
    });

    await test.step('deleting a library object removes every assignment of it', async () => {
      page.once('dialog', dialog => dialog.accept());
      await page.evaluate(id => (window as any).deleteCustomItem(id), IDS.identity);

      const after = await readState(page);
      expect(after.customLibrary[IDS.identity]).toBeUndefined();
      for (const phase of Object.values(after.assignments) as any[]) {
        expect(phase.customItems.some((a: any) => a.id === IDS.identity)).toBe(false);
        for (const group of phase.groups) {
          expect(group.items.some((i: any) => i.id === IDS.identity)).toBe(false);
        }
        for (const entry of phase.layout) {
          if (entry.kind === 'item') {
            const present = ASSIGNMENT_KEYS.some(key =>
              phase[key].some((a: any) => a.instanceId === entry.instanceId));
            expect(present, `stale layout entry ${entry.instanceId}`).toBe(true);
          }
        }
      }
    });

    const edited = await readState(page);
    const first = await exportNative(page);
    await expectInertRender(page, errors);

    await test.step('deleted data stays absent through export and fresh reimport', async () => {
      expect(first.text).not.toContain(IDS.identity);
      expect(first.text).not.toContain('itm-rt-011');
      expect(first.text).not.toContain('Second exploitation instance');
      expect(first.json.customLibrary[createdId]).toBeDefined();

      await withFreshContext(browser, async freshPage => {
        await importNative(freshPage, first.buffer, first.name);
        const restored = await readState(freshPage);
        expect(restored.assignments).toEqual(edited.assignments);
        expect(restored.customLibrary).toEqual(edited.customLibrary);
        expect(restored.customLibrary[IDS.identity]).toBeUndefined();
        expect(restored.customLibrary[createdId].name).toBe('RT Created "actor" <x>');

        const second = await exportNative(freshPage);
        expectNativeExportsEquivalent(first.json, second.json, startedAt);
      });
    });
  });
});
