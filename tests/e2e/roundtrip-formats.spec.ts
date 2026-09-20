// RT-12 CSV report projection, RT-13 technique-ID text import, RT-14 Navigator import.
//
// These routes are intentionally asymmetric and the suite does not pretend otherwise:
// there is no importer for the exported CSV report and no Navigator exporter. RT-12
// validates a one-way report projection; RT-13 and RT-14 continue through native JSON to
// prove the assignments those imports create are preserved.

import fs from 'node:fs';
import path from 'node:path';
import { expect, test } from '@playwright/test';
import {
  ALL_PHASES, exportCsv, exportNative, expectNativeExportsEquivalent, expectNoExternalRequests,
  dispatchDragAndDrop, importNative, importNavigatorLayer, installRequestGuard, openApp,
  readState, withFreshContext,
} from './helpers/roundtrip';
import { parseCsvStrict, readCsv } from './helpers/csv-reader';

const REPO_ROOT = path.resolve(__dirname, '../..');
const bytes = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8');

test.use({ serviceWorkers: 'block' });
test.afterEach(async ({ page }) => expectNoExternalRequests(page));

const CSV_HEADER_PREFIX = ['Type', 'ID', 'Name', 'Score', 'Confidence', 'CVE(s)', 'Comments'];

function csvFixture() {
  const stixId = 'malware--eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
  const meta = (overrides: Record<string, unknown> = {}) => ({ score: 'high', ...overrides });
  return {
    title: 'CSV "Report" Title',
    assignments: {
      'IN:reconnaissance': {
        // The same technique is assigned in two phases: one consolidated row, two markers.
        techniques: [{ id: 'T1595', instanceId: 'itm-c-1', metadata: meta({ confidence: 80, comments: 'First instance comment' }) }],
        capecs: [{ id: 'CAPEC-169', instanceId: 'itm-c-2', metadata: meta({ score: 'low' }) }],
        cwes: [],
        customItems: [{ id: stixId, instanceId: 'itm-c-3', type: 'custom', metadata: meta({ score: 'critical' }) }],
        groups: [], layout: [],
      },
      'OUT:exfiltration': {
        techniques: [
          { id: 'T1595', instanceId: 'itm-c-4', metadata: meta({ score: 'low', comments: 'Second instance comment' }) },
          // Formula-shaped and separator-bearing evidence.
          { id: 'T1041', instanceId: 'itm-c-5', metadata: meta({ comments: '=SUM(A1:A2), "quoted", semi;colon' }) },
        ],
        capecs: [], cwes: [],
        customItems: [], groups: [
          { groupId: 'grp-csv-1', label: 'Grouped', items: [{ id: 'CWE-79', instanceId: 'itm-c-6', type: 'cwe', metadata: meta({ score: 'medium' }) }] },
        ],
        layout: [],
      },
    },
    customLibrary: { [stixId]: { id: stixId, stixType: 'malware', name: 'CSV Malware "M"', is_family: false } },
  };
}

test.describe('RT-12 CSV report projection', () => {
  test('serializes real bytes an RFC 4180 reader can parse, with documented projections', async ({ page }) => {
    await openApp(page);
    await importNative(page, bytes(csvFixture()), 'rt-12-csv.json');

    const csv = await exportCsv(page);
    expect(csv.name).toBe('CSV-Report-Title.csv');

    const rows = parseCsvStrict(csv.buffer);
    const [titleRow, headerRow, ...dataRows] = rows;

    await test.step('title and header rows have their documented shapes', async () => {
      // The title row is deliberately narrower than every other row.
      expect(titleRow).toEqual(['Title', 'CSV "Report" Title']);
      expect(headerRow).toEqual([...CSV_HEADER_PREFIX, ...ALL_PHASES.map(p =>
        p.split(':')[1].split('-').map(w => w[0].toUpperCase() + w.slice(1)).join(' '))]);
      expect(headerRow).toHaveLength(CSV_HEADER_PREFIX.length + ALL_PHASES.length);
      for (const row of dataRows) expect(row).toHaveLength(headerRow.length);
    });

    await test.step('every entity type produces a row and phases become markers', async () => {
      // Derived mitigation rows are asserted separately; these are the assigned entities.
      const entityRows = dataRows.filter(r => r[0] !== 'Mitigation');
      const byId = new Map(entityRows.map(r => [r[1], r]));
      expect([...byId.keys()].sort()).toEqual([
        'CAPEC-169', 'CWE-79', 'T1041', 'T1595',
        'malware--eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
      ].sort());

      expect(byId.get('T1595')![0]).toBe('ATT&CK');
      expect(byId.get('CAPEC-169')![0]).toBe('CAPEC');
      expect(byId.get('CWE-79')![0]).toBe('CWE');
      expect(byId.get('malware--eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee')![0]).toBe('STIX: malware');
      expect(byId.get('malware--eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee')![2]).toBe('CSV Malware "M"');

      // A grouped item is reported exactly like an ungrouped one.
      const cwe = byId.get('CWE-79')!;
      expect(cwe[CSV_HEADER_PREFIX.length + ALL_PHASES.indexOf('OUT:exfiltration')]).toBe('X');

      // Two instances of T1595 in two phases consolidate into one row with two markers.
      const t1595 = byId.get('T1595')!;
      const markers = t1595.slice(CSV_HEADER_PREFIX.length);
      expect(markers.filter(cell => cell === 'X')).toHaveLength(2);
      expect(markers[ALL_PHASES.indexOf('IN:reconnaissance')]).toBe('X');
      expect(markers[ALL_PHASES.indexOf('OUT:exfiltration')]).toBe('X');
      // Documented loss: consolidated metadata follows the FIRST encountered instance.
      expect(t1595[6]).toBe('First instance comment');
      expect(csv.text).not.toContain('Second instance comment');
    });

    await test.step('derived mitigation rows reference the techniques they mitigate', async () => {
      const mitigations = dataRows.filter(r => r[0] === 'Mitigation');
      expect(mitigations.length).toBeGreaterThan(0);
      for (const row of mitigations) {
        expect(row[1]).toMatch(/^M\d{4}$/);
        expect(row[6]).toMatch(/^Mitigates: /);
        // Score, confidence and CVE columns are empty for derived rows.
        expect([row[3], row[4], row[5]]).toEqual(['', '', '']);
      }
    });

    await test.step('separators and quotes inside evidence decode to exact cell values', async () => {
      // Exact equality, not substring containment. A substring check passes even when the
      // exporter wraps the evidence in extra literal quote characters, which is the very
      // defect AF-RC-008 describes.
      const ordinary = dataRows.find(r => r[1] === 'T1595')!;
      expect(ordinary[6]).toBe('First instance comment');

      const capec = dataRows.find(r => r[1] === 'CAPEC-169')!;
      expect(capec[3]).toBe('low');
      expect(capec[6]).toBe('');

      // Row multiplicity: one row per entity id, no duplicates.
      const ids = dataRows.filter(r => r[0] !== 'Mitigation').map(r => r[1]);
      expect(new Set(ids).size, 'entity rows must not duplicate').toBe(ids.length);
    });
  });

});

// Separate describes: test.fail() applies to every test in its block, so a known gap must
// never share a block with tests that are expected to pass. Row endings and cell quoting
// are also separate CONTRACTS, split so that fixing one does not mask the other.

test.describe('RT-12 CSV row-ending gap', () => {
  test('ends records with CRLF as RFC 4180 requires', async ({ page }) => {
    await openApp(page);
    await importNative(page, bytes(csvFixture()), 'rt-12-crlf.json');
    const csv = await exportCsv(page);

    // Asserted on the RAW BYTES. A reader that accepts both endings cannot tell you which
    // one was written, so this can never be delegated to the decoding oracle.
    expect(csv.buffer.length, 'export produced no bytes').toBeGreaterThan(0);

    test.fail(true, 'Known gap AF-RC-008: rows are joined with LF, not CRLF');
    expect(csv.text).toContain('\r\n');
  });
});

test.describe('RT-12 CSV guarded-cell gap', () => {
  test('guards a formula-leading cell with exactly one layer of quoting', async ({ page }) => {
    await openApp(page);
    await importNative(page, bytes(csvFixture()), 'rt-12-guard.json');
    const csv = await exportCsv(page);

    // Prerequisite: the bytes decode at all, and the guarded row is present. If this
    // breaks, the failure is NOT the known quoting defect.
    const rows = parseCsvStrict(csv.buffer);
    const row = rows.find(r => r[1] === 'T1041');
    expect(row, 'the guarded technique row must exist').toBeDefined();

    test.fail(true, 'Known gap AF-RC-008: the guard pre-quotes, then the cell is quoted again');
    // Desired: the guard adds one leading tab inside a single layer of quoting, so a
    // standard reader recovers exactly tab + the original text, with no stray quotes.
    expect(row![6]).toBe('\t=SUM(A1:A2), "quoted", semi;colon');
  });
});

test.describe('RT-12 CSV reader oracle', () => {
  // Narrow validation of the REPLACEMENT oracle itself, not a new parser feature. The
  // previous hand-written reader accepted the first two and lost the third.
  test('the Python reader rejects malformed quoting and keeps an empty quoted field', async ({ page }) => {
    // This case needs no browser, but the file-level afterEach asserts the egress guard,
    // and that assertion is meant to fail for an unguarded page. Install it rather than
    // weaken the check: a test that never navigates should still declare its intent.
    await installRequestGuard(page.context());

    for (const malformed of ['"x"y', 'a,"unterminated']) {
      const result = readCsv(Buffer.from(malformed, 'utf8'));
      expect(result.ok, `strict reader must reject ${JSON.stringify(malformed)}`).toBe(false);
    }
    expect(parseCsvStrict(Buffer.from('""', 'utf8'))).toEqual([['']]);
    expect(parseCsvStrict(Buffer.from('a,"",b', 'utf8'))).toEqual([['a', '', 'b']]);
    expect(parseCsvStrict(Buffer.from('"a""b"', 'utf8'))).toEqual([['a"b']]);
    expect(parseCsvStrict(Buffer.from('a,b\r\nc,d\r\n', 'utf8'))).toEqual([['a', 'b'], ['c', 'd']]);
  });
});

test.describe('RT-13 technique-ID text import', () => {
  test('normalizes tokens, replaces the library, and the resulting assignments round trip', async ({ page, browser }) => {
    const startedAt = Date.now();
    await openApp(page);

    await test.step('empty and fully invalid input is refused without changing the library', async () => {
      const before = (await readState(page)).techniqueIds.length;
      await page.evaluate(() => (window as any).openCsvImportModal());
      await page.locator('#csv-import-textarea').fill('   ');
      await page.locator('button[onclick="submitCsvImport()"]').click();
      await expect(page.locator('#csv-import-error')).toHaveText('No valid technique IDs found.');
      expect((await readState(page)).techniqueIds.length).toBe(before);

      await page.locator('#csv-import-textarea').fill('NOT-AN-ID, 12345');
      await page.locator('button[onclick="submitCsvImport()"]').click();
      await expect(page.locator('#csv-import-error')).toHaveText('No valid technique IDs found.');
      expect((await readState(page)).techniqueIds.length).toBe(before);
    });

    await test.step('mixed separators, case and duplicates normalize as documented', async () => {
      // Lowercase, repeated, comma / space / newline separated, with one invalid token
      // and one well-formed ID that is absent from the pinned base library.
      await page.locator('#csv-import-textarea').fill('t1595, T1595\nt1059.001  BAD-TOKEN\nT9999');
      await page.locator('button[onclick="submitCsvImport()"]').click();
      await expect(page.locator('#csv-import-modal')).not.toHaveClass(/visible/);

      // 3 valid unique IDs, 1 invalid token skipped, 1 valid ID missing from the library.
      await expect(page.locator('#toast'))
        .toHaveText('Loaded 3 techniques (library replaced), 1 invalid skipped, 1 missing in base library');

      const state = await readState(page);
      expect(state.techniqueIds.sort()).toEqual(['T1059.001', 'T1595', 'T9999']);
    });

    await test.step('CONTRACT: tab is not a separator because it is stripped, not split on', async () => {
      // normalizeUserInput(raw, 20000, true) keeps LF and CR but removes every other
      // control character, TAB included. A tab-separated paste therefore fuses its
      // neighbours into one token that then fails validation, rather than importing
      // two IDs or reporting two invalid tokens. Asserted as current behavior.
      await page.evaluate(() => (window as any).openCsvImportModal());
      await page.locator('#csv-import-textarea').fill('T1595\tT1078');
      await page.locator('button[onclick="submitCsvImport()"]').click();
      await expect(page.locator('#csv-import-error')).toHaveText('No valid technique IDs found.');
      // Newline in the same position does separate correctly.
      await page.locator('#csv-import-textarea').fill('T1595\nT1078');
      await page.locator('button[onclick="submitCsvImport()"]').click();
      await expect(page.locator('#toast')).toHaveText('Loaded 2 techniques (library replaced)');
    });

    await test.step('assignments created from imported IDs survive a native round trip', async () => {
      // Assign through the REAL sidebar drag source. A second native import would call
      // initAssignments(), which restores the full base technique library and so destroys
      // the replaced library this route exists to produce. Dispatched handler coverage,
      // not physical gesture coverage.
      // Re-import so this step does not depend on what the tab-contract step above left
      // behind. The library replacement is the precondition being exercised here.
      await page.evaluate(() => (window as any).openCsvImportModal());
      await page.locator('#csv-import-textarea').fill('T1595, T1059.001, T9999');
      await page.locator('button[onclick="submitCsvImport()"]').click();
      await expect(page.locator('#csv-import-modal')).not.toHaveClass(/visible/);

      const libraryBefore = (await readState(page)).techniqueIds.sort();
      expect(libraryBefore).toEqual(['T1059.001', 'T1595', 'T9999']);

      for (const [id, phase] of [['T1595', 'IN:reconnaissance'], ['T9999', 'IN:exploitation']] as const) {
        await dispatchDragAndDrop(page,
          `.entity-item.attack[data-entity-id="${id}"]`, `[data-phase="${phase}"]`);
      }

      const assigned = await readState(page);
      // The imported library is NOT reset by assigning from it.
      expect(assigned.techniqueIds.sort()).toEqual(libraryBefore);
      expect(assigned.assignments['IN:reconnaissance'].techniques.map((a: any) => a.id)).toEqual(['T1595']);
      expect(assigned.assignments['IN:exploitation'].techniques.map((a: any) => a.id)).toEqual(['T9999']);
      // A real assignment gets a generated instance id and default metadata.
      const instance = assigned.assignments['IN:reconnaissance'].techniques[0];
      expect(instance.instanceId).toMatch(/^itm-[a-z0-9]+-\d+$/);
      expect(instance.metadata.score).toBe('unclassified');

      const first = await exportNative(page);
      await withFreshContext(browser, async freshPage => {
        await importNative(freshPage, first.buffer, first.name);
        const restored = await readState(freshPage);
        expect(restored.assignments['IN:reconnaissance'].techniques.map((a: any) => a.id)).toEqual(['T1595']);
        expect(restored.assignments['IN:exploitation'].techniques.map((a: any) => a.id)).toEqual(['T9999']);
        expect(restored.assignments).toEqual(assigned.assignments);
        const second = await exportNative(freshPage);
        expectNativeExportsEquivalent(first.json, second.json, startedAt);
      });
    });
  });
});

test.describe('RT-14 Navigator import', () => {
  const layer = (techniques: unknown[]) => ({ name: 'RT layer', domain: 'enterprise-attack', techniques });

  test('honours enabled flags, subtechniques, duplicates and invalid IDs', async ({ page }) => {
    await openApp(page);
    await importNavigatorLayer(page, bytes(layer([
      { techniqueID: 'T1595', enabled: true },
      { techniqueID: 'T1059.001' },                 // enabled omitted: treated as enabled
      { techniqueID: 'T1078', enabled: false },     // explicitly disabled: skipped silently
      { techniqueID: 'T1595' },                     // duplicate: collapses onto one entry
      { techniqueID: 'not-an-id' },                 // invalid: counted as skipped
      { techniqueID: '' },                          // empty: counted as skipped
      { techniqueID: 'T0800' },                     // ICS-range id: domain is derived
    ])), 'rt-14-layer.json');

    // Disabled entries are skipped before validation, so they are not counted.
    await expect(page.locator('#toast'))
      .toHaveText('Loaded 4 techniques (library replaced), 2 skipped (invalid ID)');

    const state = await readState(page);
    expect(state.techniqueIds.sort()).toEqual(['T0800', 'T1059.001', 'T1595']);
    expect(state.techniqueIds).not.toContain('T1078');
  });

  test('rejects malformed layers without replacing the current library', async ({ page }) => {
    await openApp(page);
    await importNavigatorLayer(page, bytes(layer([{ techniqueID: 'T1595' }])), 'rt-14-good.json');
    const before = await readState(page);
    expect(before.techniqueIds).toEqual(['T1595']);

    for (const [name, payload] of [
      ['array root', [] as unknown],
      ['missing techniques', { name: 'x' }],
      ['techniques not an array', { techniques: {} }],
    ] as [string, unknown][]) {
      await importNavigatorLayer(page, bytes(payload), `rt-14-${name}.json`);
      await expect(page.locator('#toast')).toContainText('Invalid');
      // A rejected layer must leave the previously loaded library untouched.
      expect((await readState(page)).techniqueIds, name).toEqual(['T1595']);
    }
  });

  test('assignments created from a Navigator layer survive a native round trip', async ({ page, browser }) => {
    const startedAt = Date.now();
    await openApp(page);
    await importNavigatorLayer(page, bytes(layer([
      { techniqueID: 'T1595' }, { techniqueID: 'T1059.001' },
    ])), 'rt-14-source.json');

    // The layer really did replace the library before anything is assigned from it.
    const libraryAfterImport = (await readState(page)).techniqueIds.sort();
    expect(libraryAfterImport).toEqual(['T1059.001', 'T1595']);

    // Assign from that library through the real control, without resetting it.
    await dispatchDragAndDrop(page,
      '.entity-item.attack[data-entity-id="T1595"]', '[data-phase="IN:reconnaissance"]');
    await dispatchDragAndDrop(page,
      '.entity-item.attack[data-entity-id="T1059.001"]', '[data-phase="THROUGH:execution"]');

    const assigned = await readState(page);
    expect(assigned.techniqueIds.sort(), 'assigning must not reset the imported library')
      .toEqual(libraryAfterImport);
    expect(assigned.assignments['IN:reconnaissance'].techniques.map((a: any) => a.id)).toEqual(['T1595']);
    expect(assigned.assignments['THROUGH:execution'].techniques.map((a: any) => a.id)).toEqual(['T1059.001']);

    const first = await exportNative(page);
    await withFreshContext(browser, async freshPage => {
      await importNative(freshPage, first.buffer, first.name);
      const restored = await readState(freshPage);
      expect(restored.assignments['IN:reconnaissance'].techniques.map((a: any) => a.id)).toEqual(['T1595']);
      expect(restored.assignments['THROUGH:execution'].techniques.map((a: any) => a.id)).toEqual(['T1059.001']);
      expect(restored.assignments).toEqual(assigned.assignments);
      const second = await exportNative(freshPage);
      expectNativeExportsEquivalent(first.json, second.json, startedAt);
    });
  });

  test('the shipped Navigator layers import without error', async ({ page }) => {
    await openApp(page);
    for (const name of ['Nav_Layer_ENTERPRISE.json', 'Nav_Layer_ICS.json', 'Nav_Layer_MOBILE.json']) {
      const source = fs.readFileSync(path.join(REPO_ROOT, 'resources', name));
      await importNavigatorLayer(page, source, name);
      await expect(page.locator('#toast')).toContainText('techniques (library replaced)');
      const state = await readState(page);
      expect(state.techniqueIds.length, name).toBeGreaterThan(0);
      for (const id of state.techniqueIds) expect(id, `${name} id`).toMatch(/^T\d{4}(\.\d{3})?$/);
    }
  });
});
