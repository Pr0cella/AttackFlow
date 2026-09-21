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
  GROUPS, IDS, NAME_LIMIT_ID, TITLE, URL_BRACKETS_REJECTED, VECTOR_31, expectedFullAssignments,
  expectedFullLibrary, expectedLegacyRecon, nameOfLength, nativeFull, nativeLegacy,
  nativeMinimal, nativeWithCustomEntry,
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
  // The exporter writes `filters` and `selection` into every document, and no import path
  // ever reads them back, so both are written and silently discarded.
  //
  // They are two separable contracts, asserted apart, so that restoring one without the
  // other is visible rather than masked by whichever fails first.
  for (const field of ['filters', 'selection'] as const) {
    test(`restores exported ${field}`, async ({ page, browser }) => {
      const expected = {
        filters: { attack: 'enterprise', capec: 'all', cwe: 'all', custom: 'all' },
        selection: { type: 'attack', id: 'T1595' },
      }[field];

      await openApp(page);
      await importNative(page, bytes(nativeFull()), `rt-persistence-${field}.json`);
      await page.evaluate(({ key, value }) => { (eval('state') as any)[key] = value; },
        { key: field, value: expected });

      // Prerequisite: the exporter really does write the field. If this breaks, the gap has
      // changed shape and the failure must NOT be credited to the known restore gap.
      const exported = await exportNative(page);
      expect(exported.json[field]).toEqual(expected);

      await withFreshContext(browser, async freshPage => {
        await importNative(freshPage, exported.buffer, exported.name);
        const restored = await readState(freshPage);

        test.fail(true, `Known gap: ${field} is written into the export and never read back on import`);
        // Desired behavior: a value the exporter writes is a value the importer restores.
        expect(restored[field]).toEqual(expected);
      });
    });
  }
});

// The view is exported but never restored: the importer only accepts 'killchain' and
// 'relations', and 'relations' is a name the app itself never writes. So a document saved
// in the relationship view reopens in the kill chain view. Only the preference is lost --
// the document comes back intact -- and that is accepted, so this case asserts what the
// app actually does rather than marking a desired behavior as a known failure. If the
// importer is ever changed to accept 'relationship', the last assertion fails on purpose.
test.describe('RT-02 view restoration', () => {
  test('exports the relationship view and reopens in the kill chain view', async ({ page, browser }) => {
    await openApp(page);
    await importNative(page, bytes(nativeFull()), 'rt-view-preference.json');

    // The preference is set through the real view control, the way an analyst sets it.
    await page.locator('#view-relationship').click();
    await expect(page.locator('#relationship-container')).toHaveClass(/visible/);
    expect((await readState(page)).view).toBe('relationship');

    // The exporter writes the live view, so the preference does reach the file.
    const exported = await exportNative(page);
    expect(exported.json.view).toBe('relationship');

    await withFreshContext(browser, async freshPage => {
      await importNative(freshPage, exported.buffer, exported.name);
      const restored = await readState(freshPage);

      // The importer drops that value: the kill chain view is what comes back.
      expect(restored.view).toBe('killchain');
      await expect(freshPage.locator('#view-killchain')).toHaveClass(/active/);
      await expect(freshPage.locator('#relationship-container')).not.toHaveClass(/visible/);

      // Only the preference is lost -- the document itself is restored.
      expect(restored.title).toBe(TITLE);
      await expect(freshPage.locator('#kill-chain-title')).toHaveValue(TITLE);
    });
  });
});

test.describe('RT-15 legacy metadata keys', () => {
  test('normalizes cves arrays for nested, flat, grouped and mixed metadata', async ({ page }) => {
    await openApp(page);
    const changedScopeVector = VECTOR_31.replace('/S:U/', '/S:C/');
    const legacy = {
      assignments: {
        'IN:exploitation': {
          techniques: [
            {
              id: 'T1190', instanceId: 'itm-rt-cves-nested',
              metadata: {
                cves: [
                  { id: ' cve-2024-3400 ', score: '10.0', vector: VECTOR_31 },
                  { id: 'not-a-cve', score: 9, vector: VECTOR_31 },
                  null,
                ],
              },
            },
            {
              id: 'T1595', instanceId: 'itm-rt-cves-flat',
              cves: [{ id: 'CVE-2024-3401', score: 4, cvssVector: changedScopeVector }],
            },
            {
              id: 'T1041', instanceId: 'itm-rt-cves-current',
              metadata: {
                cveEntries: [{ id: 'CVE-2024-3402', score: 8.75, vector: VECTOR_31 }],
              },
            },
            {
              id: 'T1566', instanceId: 'itm-rt-cves-mixed',
              metadata: {
                cveEntries: [{ id: 'CVE-2024-3403', score: 9.8, vector: VECTOR_31 }],
                cves: [
                  { id: 'CVE-2024-3403', score: 7.1, vector: changedScopeVector },
                  { id: 'CVE-2024-3404', score: 11, vector: 'invalid' },
                  { id: 'CVE-2024-3404', score: 11, vector: 'invalid' },
                ],
              },
            },
            { id: 'T1021', instanceId: 'itm-rt-cves-empty', metadata: { cves: [] } },
          ],
          groups: [{
            groupId: 'grp-rt-cves', label: 'Legacy CVE group', collapsed: false,
            items: [{
              id: 'T1059', type: 'attack', instanceId: 'itm-rt-cves-grouped',
              metadata: { cves: [{ id: 'CVE-2024-3405', score: '6.4', vector: VECTOR_31 }] },
            }],
          }],
        },
      },
    };
    await importNative(page, bytes(legacy), 'rt-af-rt-002.json');

    const phase = (await readState(page)).assignments['IN:exploitation'];
    const byInstance = Object.fromEntries(phase.techniques.map((item: any) => [item.instanceId, item]));
    expect(byInstance['itm-rt-cves-nested'].metadata.cveEntries)
      .toEqual([{ id: 'CVE-2024-3400', score: 10, vector: VECTOR_31 }]);
    expect(byInstance['itm-rt-cves-flat'].metadata.cveEntries)
      .toEqual([{ id: 'CVE-2024-3401', score: 4, vector: changedScopeVector }]);
    expect(byInstance['itm-rt-cves-current'].metadata.cveEntries)
      .toEqual([{ id: 'CVE-2024-3402', score: 8.8, vector: VECTOR_31 }]);
    expect(byInstance['itm-rt-cves-mixed'].metadata.cveEntries).toEqual([
      { id: 'CVE-2024-3403', score: 9.8, vector: VECTOR_31 },
      { id: 'CVE-2024-3403', score: 7.1, vector: changedScopeVector },
      { id: 'CVE-2024-3404', score: null, vector: '' },
      { id: 'CVE-2024-3404', score: null, vector: '' },
    ]);
    expect(byInstance['itm-rt-cves-empty'].metadata.cveEntries).toEqual([]);
    expect(phase.groups[0].items[0].metadata.cveEntries)
      .toEqual([{ id: 'CVE-2024-3405', score: 6.4, vector: VECTOR_31 }]);
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

      const expectedDemoCve = [{
        id: 'CVE-2024-3400', score: 10,
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      }];
      if (name === 'stix-demo.json') {
        const restored = imported.assignments['IN:exploitation'].techniques
          .find((item: any) => item.id === 'T1190');
        expect(restored.metadata.cveEntries).toEqual(expectedDemoCve);
      }

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
      // Scope: this asserts that the whole shipped library SURVIVES, and that each entry
      // keeps its NAME. Other field-level fidelity inside an entry is still not claimed.
      // The name is asserted because the shipped stix-demo.json carries names of 53 and 54
      // characters, so an importer bounded by the 50-character label limit loses analyst
      // data from a file this project ships -- silently, and on the FIRST import.
      const sourceLibrary = (sourceDoc.customLibrary || {}) as Record<string, any>;
      expect(Object.keys(imported.customLibrary).sort()).toEqual(Object.keys(sourceLibrary).sort());
      for (const [id, sourceEntry] of Object.entries(sourceLibrary)) {
        if (typeof sourceEntry.name !== 'string') continue;
        expect(imported.customLibrary[id].name, `${id} name`)
          .toBe(sourceEntry.name.replace(/[\u0000-\u001F\u007F]/g, '').trim().slice(0, 200));
      }

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
      if (name === 'stix-demo.json') {
        const downloaded = first.json.assignments['IN:exploitation'].techniques
          .find((item: any) => item.id === 'T1190');
        expect(downloaded.metadata.cveEntries).toEqual(expectedDemoCve);
      }
      await withFreshContext(browser, async freshPage => {
        await importNative(freshPage, first.buffer, first.name);
        const reimported = await readState(freshPage);
        expect(reimported).toEqual(imported);
        if (name === 'stix-demo.json') {
          const restored = reimported.assignments['IN:exploitation'].techniques
            .find((item: any) => item.id === 'T1190');
          expect(restored.metadata.cveEntries).toEqual(expectedDemoCve);
        }
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
    // The one group this test renames, and so the ONLY group permitted to carry the
    // transient `editing` flag. Captured here because the id is generated at runtime.
    let renamedGroupId = '';

    await test.step('create a group through the real control and rename it', async () => {
      await page.locator(`${recon} .phase-group-btn`).first().click();
      const created = await page.evaluate(key => {
        const groups = eval('state').assignments[key].groups;
        return groups[groups.length - 1].groupId;
      }, FULL_PHASES.recon);
      expect(created).toMatch(/^grp-[a-z0-9]+-[a-z0-9]{1,5}$/);
      renamedGroupId = created;

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

    await test.step('the transient rename flag leaks into the export but not back in', async () => {
      // commitRenameGroup() sets editing=false instead of deleting the key, and
      // exportJSON() serializes state.assignments verbatim, so a UI-only flag with no
      // place in the document schema reaches the downloaded file.
      const exportedGroups = first.json.assignments[FULL_PHASES.recon].groups;
      const renamed = exportedGroups.find((g: any) => g.groupId === renamedGroupId);
      expect(renamed, 'the renamed group is in the export').toBeDefined();
      expect(renamed.label).toBe('Renamed "group" <x> & --y');
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
        // The expectation drops the flag at the ONE asserted path, not wherever it is
        // found: a leak at any other group must fail rather than be normalized away.
        const expected = JSON.parse(JSON.stringify(edited));
        for (const [phaseKey, phase] of Object.entries(expected.assignments) as [string, any][]) {
          for (const group of phase.groups) {
            const leaks = Object.prototype.hasOwnProperty.call(group, 'editing');
            if (phaseKey === FULL_PHASES.recon && group.groupId === renamedGroupId) {
              expect(leaks, 'the renamed group carries the flag').toBe(true);
              expect(group.editing).toBe(false);
              delete group.editing;
            } else {
              expect(leaks, `unexpected 'editing' flag at ${phaseKey}/${group.groupId}`).toBe(false);
            }
          }
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
        // The first export carries the transient flag at exactly one declared path; the
        // second must not, and no other group may carry it in either artifact.
        expectNativeExportsEquivalent(first.json, second.json, startedAt, {
          editingLeakPaths: [`${FULL_PHASES.recon}/${renamedGroupId}`],
        });

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

// ---------------------------------------------------------------------------
// RT-05 custom object name limits
//
// A custom object's name is written under a 200-code-unit limit everywhere the app
// writes one: the create modal's maxlength attribute, createCustomItem(),
// saveStixEditor(), the editor field builder, and the STIX bundle importer's own
// maxNameLength. The native importer is the single path that bounds the same field by
// the LABEL limit instead, which is a different field's policy, so a name an analyst
// was allowed to type is silently shortened when their own export is loaded back.
//
// The label and description limits are asserted alongside it, because the cheap way to
// make the name cases pass is to raise every string limit at once, and that would be a
// different, much larger change.
// ---------------------------------------------------------------------------

const customNameText = (page: Page) =>
  page.locator('.entity-item.custom .entity-name').first().evaluate(el => el.textContent);

test.describe('RT-05 custom object name limits', () => {
  test('a 123-code-unit name created in the modal survives export and fresh reimport', async ({ page, browser }) => {
    const NAME = nameOfLength(123);
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await openApp(page);

    let createdId = '';
    await test.step('the create modal accepts and stores the whole name', async () => {
      await page.locator('.sidebar-tab.custom').click();
      await page.locator('button[onclick="openCreateCustomModal()"]').click();
      await expect(page.locator('#create-custom-modal')).toHaveClass(/visible/);
      await page.locator('#custom-stix-type').selectOption('threat-actor');
      // The input's own maxlength is 200, so a 123-unit name is enterable by design.
      await page.locator('#custom-name').fill(NAME);
      expect(await page.locator('#custom-name').inputValue()).toBe(NAME);
      await page.locator('button[onclick="createCustomItem()"]').click();
      await expect(page.locator('#create-custom-modal')).not.toHaveClass(/visible/);

      const library = (await readState(page)).customLibrary;
      const entries = Object.values(library) as any[];
      expect(entries, 'exactly one created object').toHaveLength(1);
      expect(entries[0].name).toBe(NAME);
      createdId = entries[0].id;
      // The sidebar renders the stored name in full; shortening is CSS, not data.
      expect(await customNameText(page)).toBe(NAME);
    });

    const first = await exportNative(page);

    await test.step('the download carries the name in both the document and the bundle', async () => {
      expect(first.json.customLibrary[createdId].name).toBe(NAME);
      const sdo = first.json.stixBundle.objects.find((o: any) => o.id === createdId);
      expect(sdo, 'the created object is projected into the embedded bundle').toBeDefined();
      expect(sdo.name).toBe(NAME);
    });

    await withFreshContext(browser, async freshPage => {
      const freshErrors: string[] = [];
      freshPage.on('pageerror', error => freshErrors.push(error.message));
      await importNative(freshPage, first.buffer, first.name);

      // The reimported name must be the name that was exported. Before the fix the
      // importer cut it to the 50-unit label limit here.
      const restored = await readState(freshPage);
      expect(restored.customLibrary[createdId].name).toBe(NAME);

      await freshPage.locator('.sidebar-tab.custom').click();
      expect(await customNameText(freshPage)).toBe(NAME);

      const second = await exportNative(freshPage);
      expect(second.json.customLibrary[createdId].name).toBe(NAME);
      await expectInertRender(freshPage, freshErrors);
    });

    await expectInertRender(page, errors);
  });

  // One case per length so the first failure cannot hide the others. Scope: these probe
  // the IMPORT trust boundary, which is where the loss is; the full create/export/reimport
  // cycle is covered once above rather than five more times.
  for (const length of [49, 50, 51, 199, 200]) {
    test(`an imported ${length}-code-unit name is preserved exactly`, async ({ page }) => {
      const NAME = nameOfLength(length);
      await openApp(page);
      await importNative(page, bytes(nativeWithCustomEntry({ name: NAME })), `rt-05-name-${length}.json`);

      const entry = (await readState(page)).customLibrary[NAME_LIMIT_ID];
      expect(entry, 'the library entry survives import').toBeDefined();
      expect(entry.name).toBe(NAME);
      expect(entry.name.length).toBe(length);
    });
  }

  test('an imported name above the 200-code-unit policy is truncated to 200', async ({ page }) => {
    const NAME = nameOfLength(260);
    await openApp(page);
    await importNative(page, bytes(nativeWithCustomEntry({ name: NAME })), 'rt-05-name-over.json');

    const entry = (await readState(page)).customLibrary[NAME_LIMIT_ID];
    // The policy is unchanged by this fix: the native importer now applies the SAME
    // 200-unit name limit the rest of the app already applied, not a larger one.
    expect(entry.name).toBe(NAME.slice(0, 200));
    expect(entry.name.length).toBe(200);
  });

  test('a punctuation-rich name survives the round trip and renders inert', async ({ page, browser }) => {
    // Printable evidence is preserved as data; the render sink encodes it. Both are
    // asserted, never traded against each other.
    const NAME = 'RT03 "quoted" & <tag>; [b] {c} \\back -- Ελληνικά 日本語 Straße '
      + '</div><img data-rt-injected src=x onerror="window.__rtExecuted=true">';
    expect(NAME.length, 'stays inside the 200-unit policy').toBeLessThanOrEqual(200);

    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await openApp(page);
    await importNative(page, bytes(nativeWithCustomEntry({ name: NAME })), 'rt-05-name-punctuation.json');

    expect((await readState(page)).customLibrary[NAME_LIMIT_ID].name).toBe(NAME);
    await page.locator('.sidebar-tab.custom').click();
    expect(await customNameText(page)).toBe(NAME);
    await expectInertRender(page, errors);

    const first = await exportNative(page);
    expect(first.json.customLibrary[NAME_LIMIT_ID].name).toBe(NAME);

    await withFreshContext(browser, async freshPage => {
      const freshErrors: string[] = [];
      freshPage.on('pageerror', error => freshErrors.push(error.message));
      await importNative(freshPage, first.buffer, first.name);
      expect((await readState(freshPage)).customLibrary[NAME_LIMIT_ID].name).toBe(NAME);
      await freshPage.locator('.sidebar-tab.custom').click();
      expect(await customNameText(freshPage)).toBe(NAME);
      await expectInertRender(freshPage, freshErrors);
    });
  });

  test('the label and description limits are unchanged by the name limit', async ({ page }) => {
    const label50 = nameOfLength(50);
    const label51 = nameOfLength(51);
    const description = 'd'.repeat(2100);
    await openApp(page);
    await importNative(page, bytes(nativeWithCustomEntry({
      name: nameOfLength(120), labels: [label50, label51], description,
    })), 'rt-05-sibling-limits.json');

    const entry = (await readState(page)).customLibrary[NAME_LIMIT_ID];
    // Labels keep their own 50-unit limit: a broad "raise every string limit" change
    // would let the 51st unit through here.
    expect(entry.labels).toEqual([label50, label51.slice(0, 50)]);
    expect(entry.description).toBe(description.slice(0, 2000));
    expect(entry.name).toBe(nameOfLength(120));
  });
});

test.describe('RT-05 custom type name limit', () => {
  // A SEPARATE field, kept here so a broad "raise every limit" change is visible.
  //
  // MEASURED, because reading one line of the importer gives the wrong answer: the
  // library loop writes `customTypeName` through the 50-unit label limit, and then the
  // spec-field loop below it writes the SAME key again from the raw input at 2000, because
  // STIX_OBJECTS['x-custom'] declares customTypeName as an optional field and the loop
  // excludes only name, description and labels. The second write wins, so a 70-unit type
  // name survives and the label cap on that key is dead for x-custom objects.
  //
  // `name` is in that exclusion set, so nothing overwrites it -- which is exactly why the
  // name limit is the one that is felt.
  test('a 70-code-unit custom type name survives a native round trip', async ({ page, browser }) => {
    const TYPE_NAME = nameOfLength(70);
    await openApp(page);
    await page.locator('.sidebar-tab.custom').click();
    await page.locator('button[onclick="openCreateCustomModal()"]').click();
    await expect(page.locator('#create-custom-modal')).toHaveClass(/visible/);
    await page.locator('#custom-stix-type').selectOption('x-custom');
    await expect(page.locator('#custom-typename')).toBeVisible();
    await page.locator('#custom-typename').fill(TYPE_NAME);
    await page.locator('#custom-name').fill('RT Custom Type Probe');
    await page.locator('button[onclick="createCustomItem()"]').click();
    await expect(page.locator('#create-custom-modal')).not.toHaveClass(/visible/);

    const created = Object.values((await readState(page)).customLibrary)[0] as any;
    expect(created.customTypeName, 'the 80-unit creation limit keeps all 70').toBe(TYPE_NAME);

    const first = await exportNative(page);
    expect(first.json.customLibrary[created.id].customTypeName).toBe(TYPE_NAME);

    await withFreshContext(browser, async freshPage => {
      await importNative(freshPage, first.buffer, first.name);
      const restored = (await readState(freshPage)).customLibrary[created.id];
      // Observed behavior: the spec-field write restores the whole 70 units. This is the
      // field the name fix does NOT touch, so it must read the same before and after it.
      expect(restored.customTypeName).toBe(TYPE_NAME);
      // The name on the same object is bounded by the name policy, not the label one.
      expect(restored.name).toBe('RT Custom Type Probe');
    });
  });
});
