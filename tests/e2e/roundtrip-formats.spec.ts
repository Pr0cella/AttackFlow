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
  ALL_PHASES, exportCsv, exportNative, expectNativeExportsEquivalent, importNative,
  importNavigatorLayer, openApp, readState, withFreshContext,
} from './helpers/roundtrip';

const REPO_ROOT = path.resolve(__dirname, '../..');
const bytes = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8');

/**
 * Independent RFC 4180 reader.
 *
 * This implements the STANDARD, not the app's serializer, so it is a true oracle: none
 * of exportCSV()'s quoting logic is reproduced here. It accepts CRLF or LF row
 * separators so that the row-ending policy can be asserted separately from parsing.
 */
function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  let i = 0;
  const endField = () => { row.push(field); field = ''; };
  const endRow = () => { endField(); rows.push(row); row = []; };

  while (i < text.length) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"') {
        if (text[i + 1] === '"') { field += '"'; i += 2; continue; }
        quoted = false; i += 1; continue;
      }
      field += ch; i += 1; continue;
    }
    if (ch === '"' && field === '') { quoted = true; i += 1; continue; }
    if (ch === ',') { endField(); i += 1; continue; }
    if (ch === '\r' && text[i + 1] === '\n') { endRow(); i += 2; continue; }
    if (ch === '\n' || ch === '\r') { endRow(); i += 1; continue; }
    field += ch; i += 1;
  }
  if (field !== '' || row.length > 0) endRow();
  return rows;
}

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

    const rows = parseCsv(csv.text);
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

    await test.step('separators and quotes inside evidence survive a standard reader', async () => {
      const row = dataRows.find(r => r[1] === 'T1041')!;
      // The comma, the embedded quotes and the semicolon all round-trip through parsing.
      expect(row[6]).toContain('"quoted"');
      expect(row[6]).toContain('semi;colon');
      expect(row[6]).toContain('A1:A2');
    });
  });

});

// Separate describe: test.fail() applies to every test in its block, so a known gap
// must never share a block with tests that are expected to pass.
test.describe('RT-12 CSV serialization gap', () => {
  test.fail(true, 'Known gap AF-RC-008: guarded cells are quoted twice and rows use LF');
  test('guards formula-leading cells with single RFC 4180 quoting and CRLF rows', async ({ page }) => {
    await openApp(page);
    await importNative(page, bytes(csvFixture()), 'rt-12-guard.json');
    const csv = await exportCsv(page);

    // Desired: rows end with CRLF as RFC 4180 requires.
    expect(csv.text).toContain('\r\n');

    // Desired: the guard adds one leading tab inside a single layer of quoting, so a
    // standard reader recovers exactly tab + original text.
    const row = parseCsv(csv.text).find(r => r[1] === 'T1041')!;
    expect(row[6]).toBe('\t=SUM(A1:A2), "quoted", semi;colon');
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
      // Assign the imported techniques the way the app does, then round trip them.
      await importNative(page, bytes({
        assignments: {
          'IN:reconnaissance': {
            techniques: [
              { id: 'T1595', instanceId: 'itm-r-1', metadata: { score: 'high' } },
              { id: 'T9999', instanceId: 'itm-r-2', metadata: { score: 'low' } },
            ],
          },
        },
      }), 'rt-13-assigned.json');

      const imported = await readState(page);
      const recon = imported.assignments['IN:reconnaissance'].techniques;
      expect(recon.map((a: any) => a.id)).toEqual(['T1595', 'T9999']);
      // An ID with no framework entry gets a synthesized fallback rather than vanishing.
      expect(imported.techniqueIds).toContain('T9999');

      const first = await exportNative(page);
      await withFreshContext(browser, async freshPage => {
        await importNative(freshPage, first.buffer, first.name);
        const restored = await readState(freshPage);
        expect(restored.assignments).toEqual(imported.assignments);
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

    await importNative(page, bytes({
      assignments: {
        'IN:reconnaissance': {
          techniques: [{ id: 'T1595', instanceId: 'itm-n-1', metadata: { score: 'medium', comments: 'From navigator' } }],
        },
        'THROUGH:execution': {
          techniques: [{ id: 'T1059.001', instanceId: 'itm-n-2', metadata: { score: 'critical' } }],
        },
      },
    }), 'rt-14-assigned.json');

    const imported = await readState(page);
    const first = await exportNative(page);
    await withFreshContext(browser, async freshPage => {
      await importNative(freshPage, first.buffer, first.name);
      const restored = await readState(freshPage);
      expect(restored.assignments).toEqual(imported.assignments);
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
