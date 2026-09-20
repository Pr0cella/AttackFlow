// RT-17 failure, security and transactional behavior; RT-18 session and configuration
// isolation.
//
// Threat model: an attacker controls imported bytes and filenames, including nested
// structures and strings later rendered in cards, editors, tooltips and diagnostics.
// These tests must also detect loss of TRUSTED session data caused by a failed import.
//
// Every case snapshots valid state first, then asserts the expected unchanged state, the
// visible diagnostic, and the absence of a download where one would be wrong.

import { expect, test, type Page } from '@playwright/test';
import {
  BASE_URL, clickExportControl, exportNative, expectInertRender, expectNoDownload,
  expectNoExternalRequests, importNative, importStix, installRequestGuard, openApp, readState,
} from './helpers/roundtrip';
import { IDS, nativeFull } from '../fixtures/roundtrip/native';

const bytes = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8');
const raw = (text: string) => Buffer.from(text, 'utf8');

test.use({ serviceWorkers: 'block' });
test.afterEach(async ({ page }) => expectNoExternalRequests(page));

/** Imports bytes expecting refusal, and asserts the session survived untouched. */
async function expectRefused(page: Page, buffer: Buffer, name: string, before: unknown) {
  await page.locator('#toast').evaluate(el => { el.textContent = ''; });
  await page.locator('#import-killchain-input').setInputFiles({
    name, mimeType: 'application/json', buffer,
  });
  await expect(page.locator('#toast'), name).toContainText('Import failed');
  expect(await readState(page), `${name} must not alter session state`).toEqual(before);
}

test.describe('RT-17 rejection is atomic and diagnostic', () => {
  test('malformed and hostile documents never replace a loaded session', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await openApp(page);
    await importNative(page, bytes(nativeFull()), 'rt-17-baseline.json');
    const before = await readState(page);

    const cases: [string, Buffer][] = [
      ['malformed json', raw('{ "assignments": ')],
      ['null root', raw('null')],
      ['array root', raw('[]')],
      ['string root', raw('"not an object"')],
      ['number root', raw('42')],
      ['assignments missing', bytes({ title: 'x' })],
      ['phase key without a colon', bytes({ assignments: { reconnaissance: { techniques: [] } } })],
      ['phase data not an object', bytes({ assignments: { 'IN:reconnaissance': 'x' } })],
      ['techniques not an array', bytes({ assignments: { 'IN:reconnaissance': { techniques: {} } } })],
      ['groups not an array', bytes({ assignments: { 'IN:reconnaissance': { groups: {} } } })],
      ['title not a string', bytes({ assignments: {}, title: 42 })],
      ['title too long', bytes({ assignments: {}, title: 'x'.repeat(201) })],
      ['bad schema version', bytes({ assignments: {}, schemaVersion: 'not-a-version' })],
    ];

    for (const [label, buffer] of cases) {
      await test.step(label, () => expectRefused(page, buffer, `${label}.json`, before));
    }

    // A rejected import must also leave the document renderable and inert.
    await expect(page.locator(`[data-phase="IN:reconnaissance"]`)).toBeVisible();
    await expectInertRender(page, errors);
  });

  test('an array-valued assignments field destroys the loaded document', async ({ page }) => {
    // This test asserts CURRENT behavior so the severity is recorded and cannot regress
    // unnoticed. The desired behavior is asserted separately below as AF-RT-005.
    await openApp(page);
    await importNative(page, bytes(nativeFull()), 'rt-17-wipe-baseline.json');
    const before = await readState(page);
    expect(Object.keys(before.customLibrary).length).toBeGreaterThan(0);

    await importNative(page, bytes({ assignments: [] }), 'array-assignments.json');

    // validateKillChainImport() tests `typeof assignments !== 'object'`, which an array
    // passes, so the file is accepted, initAssignments() clears every phase and nothing
    // is restored. The analyst sees a success toast for a total loss of assignments.
    const after = await readState(page);
    for (const phase of Object.values(after.assignments) as any[]) {
      expect(phase.techniques).toEqual([]);
      expect(phase.capecs).toEqual([]);
      expect(phase.cwes).toEqual([]);
      expect(phase.customItems).toEqual([]);
      expect(phase.groups).toEqual([]);
    }
    expect(after.assignments).not.toEqual(before.assignments);
  });

  test('over-budget imports are refused whole, at the boundary and above it', async ({ page }) => {
    await openApp(page);
    await importNative(page, bytes(nativeFull()), 'rt-17-budget-baseline.json');
    const before = await readState(page);

    // Discovered constant, not an invented one: KILLCHAIN_IMPORT_LIMITS.maxAssignmentsPerPhase.
    const limit = await page.evaluate(() => eval('KILLCHAIN_IMPORT_LIMITS').maxAssignmentsPerPhase);
    expect(limit).toBe(500);

    const list = (count: number) => Array.from({ length: count }, (_, i) => ({
      id: 'T1595', instanceId: `itm-b-${i}`, metadata: {},
    }));

    // Just below and exactly at the limit are accepted.
    for (const count of [limit - 1, limit]) {
      await importNative(page, bytes({ assignments: { 'IN:reconnaissance': { techniques: list(count) } } }), `at-${count}.json`);
      expect((await readState(page)).assignments['IN:reconnaissance'].techniques).toHaveLength(count);
    }

    // One over the limit is refused, and the accepted document stays loaded.
    const accepted = await readState(page);
    await expectRefused(page, bytes({ assignments: { 'IN:reconnaissance': { techniques: list(limit + 1) } } }),
      'over-limit.json', accepted);
    await expect(page.locator('#toast')).toContainText(`Too many techniques in IN:reconnaissance (max ${limit})`);

    expect(before.assignments).not.toEqual(accepted.assignments);  // the baseline really changed
  });

  test('poison keys and unsafe URLs never reach state or the prototype', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await openApp(page);

    // Built as RAW JSON TEXT, deliberately. An object literal `{ '__proto__': {...} }`
    // sets the prototype instead of creating an own property, so JSON.stringify emits
    // nothing and the hostile key never reaches the parser at all. The previous version of
    // this fixture did exactly that, and its `.replace(/"__proto__"/g, '"__proto__"')` was
    // a no-op that made the omission look intentional.
    const hyperlinks = JSON.stringify([
      { label: 'js', url: 'javascript:window.__rtExecuted=true' },
      { label: 'data', url: 'data:text/html,<script>window.__rtExecuted=true</script>' },
      { label: 'vb', url: 'vbscript:msgbox(1)' },
      { label: 'file', url: 'file:///etc/passwd' },
      { label: 'protocol relative', url: '//evil.test/x' },
      { label: 'ok', url: 'https://example.test/ok' },
    ]);
    const poison = `{
      "assignments": {
        "__proto__": { "techniques": [], "polluted": true },
        "constructor": { "techniques": [] },
        "IN:reconnaissance": {
          "techniques": [{
            "id": "T1595",
            "instanceId": "itm-p-1",
            "__proto__": { "polluted": true },
            "metadata": { "comments": "poison probe", "__proto__": { "polluted": true },
                          "hyperlinks": ${hyperlinks} }
          }],
          "groups": [{ "groupId": "__proto__", "label": "x", "items": [] }],
          "layout": []
        }
      },
      "customLibrary": { "__proto__": { "name": "x" }, "constructor": { "name": "y" } }
    }`;

    // The fixture is only meaningful if the dangerous keys survive serialization as OWN
    // properties at every depth it claims to probe. Assert that before uploading, so a
    // fixture that quietly stopped being hostile fails loudly instead of passing.
    const parsedFixture = JSON.parse(poison);
    const own = (object: any, key: string) => Object.prototype.hasOwnProperty.call(object, key);
    expect(own(parsedFixture.assignments, '__proto__'), 'top-level __proto__ key').toBe(true);
    expect(own(parsedFixture.assignments, 'constructor'), 'top-level constructor key').toBe(true);
    expect(own(parsedFixture.assignments['IN:reconnaissance'].techniques[0], '__proto__'),
      'nested __proto__ on an assignment').toBe(true);
    expect(own(parsedFixture.assignments['IN:reconnaissance'].techniques[0].metadata, '__proto__'),
      'nested __proto__ on metadata').toBe(true);
    expect(own(parsedFixture.customLibrary, '__proto__'), 'library __proto__ key').toBe(true);

    await importNative(page, raw(poison), 'rt-17-poison.json');

    const state = await readState(page);
    // Only the http(s) link survives; nothing else is kept as a usable URL.
    const links = state.assignments['IN:reconnaissance'].techniques[0].metadata.hyperlinks;
    expect(links).toEqual([{ label: 'ok', url: 'https://example.test/ok' }]);

    // Dangerous keys never become phases, groups or library entries.
    expect(Object.keys(state.assignments)).not.toContain('__proto__');
    expect(Object.keys(state.assignments)).not.toContain('constructor');
    expect(Object.keys(state.customLibrary)).toEqual([]);
    const hostileGroup = state.assignments['IN:reconnaissance'].groups[0];
    expect(hostileGroup.groupId).not.toBe('__proto__');
    expect(hostileGroup.groupId).toMatch(/^grp-[a-z0-9]+-[a-z0-9]{1,5}$/);

    // No prototype anywhere in the page realm gained the injected marker.
    expect(await page.evaluate(() => ({} as any).polluted), 'Object.prototype').toBeUndefined();
    expect(await page.evaluate(() => ([] as any).polluted), 'Array.prototype').toBeUndefined();
    expect(await page.evaluate(() => (Object.prototype as any).techniques)).toBeUndefined();
    await expectInertRender(page, errors);
  });

  test('a STIX bundle that is refused leaves the existing library intact', async ({ page }) => {
    await openApp(page);
    await importNative(page, bytes(nativeFull()), 'rt-17-stix-baseline.json');
    const before = await readState(page);

    for (const [label, payload] of [
      ['wrong top-level type', { type: 'not-bundle', objects: [] }],
      ['objects missing', { type: 'bundle' }],
      ['array root', []],
    ] as [string, unknown][]) {
      await page.locator('#toast').evaluate(el => { el.textContent = ''; });
      await importStix(page, bytes(payload), `${label}.json`);
      await expect(page.locator('#toast'), label).toContainText('Invalid STIX bundle');
      expect(await readState(page), label).toEqual(before);
    }
  });
});

test.describe('RT-17 import validation gap', () => {
  // AF-RT-005 has two separable contracts: the file must be REPORTED as refused, and the
  // loaded document must be left intact. A single test would hide the second behind the
  // first, and the second is the one that costs an analyst their work.
  for (const contract of ['reports the refusal', 'leaves the loaded document intact'] as const) {
    test(`an array-valued assignments field ${contract}`, async ({ page }) => {
      await openApp(page);
      await importNative(page, bytes(nativeFull()), 'rt-17-gap-baseline.json');

      // Prerequisite: a populated document really is loaded, so "unchanged" means
      // something. A failure here is setup breakage, not the known gap.
      const before = await readState(page);
      expect(Object.keys(before.customLibrary).length).toBeGreaterThan(0);

      await page.locator('#toast').evaluate(el => { el.textContent = ''; });
      await page.locator('#import-killchain-input').setInputFiles({
        name: 'array-assignments.json', mimeType: 'application/json', buffer: bytes({ assignments: [] }),
      });

      // Completion signal. setInputFiles returns as soon as the file is handed over, but
      // importKillChain() reads it through an async FileReader. Asserting state before
      // that resolves compares against a document that has not been touched YET, which
      // makes the wipe look like correct behavior. The import path sets a toast on every
      // outcome, so a non-empty toast is the point at which the result is decided.
      await expect(page.locator('#toast')).not.toBeEmpty();

      test.fail(true, 'Known gap AF-RT-005: an array assignments field passes validation and wipes the document');
      if (contract === 'reports the refusal') {
        await expect(page.locator('#toast')).toContainText('Import failed');
      } else {
        // Assignments AND the custom library must both survive; the probed defect clears
        // both under the default clearStixOnKillChainImport setting.
        expect(await readState(page)).toEqual(before);
      }
    });
  }
});

test.describe('RT-17 export failure paths', () => {
  test('an incompatible supported property aborts export without a download or mutation', async ({ page }) => {
    await openApp(page);
    await importNative(page, bytes(nativeFull()), 'rt-17-export.json');

    // Direct state injection, deliberately: a boolean-typed supported property holding a
    // string is an export-time error that no UI path can produce. Only the STATE is
    // injected. Both exports are still triggered through their real menu controls, so an
    // unwired control fails this test exactly as it fails a successful-export lifecycle.
    await page.evaluate(id => { eval('state').library.custom[id].is_family = 'not-a-boolean'; }, IDS.malware);
    const before = await readState(page);

    await expectNoDownload(page, () => clickExportControl(page, 'JSON'));
    await expect(page.locator('#toast')).toContainText('JSON export failed');
    expect(await readState(page)).toEqual(before);

    await expectNoDownload(page, () => clickExportControl(page, 'STIX Bundle'));
    await expect(page.locator('#toast')).toContainText('STIX export failed');
    expect(await readState(page)).toEqual(before);

    // Repairing the value restores a working export with no stale or partial artifact.
    await page.evaluate(id => { eval('state').library.custom[id].is_family = false; }, IDS.malware);
    const exported = await exportNative(page);
    expect(exported.json.customLibrary[IDS.malware].is_family).toBe(false);
  });

  test('an absent or whitespace title uses the documented fallback name', async ({ page }) => {
    await openApp(page);
    for (const [title, expected] of [
      ['', 'attack-chain-export.json'],
      ['   ', 'attack-chain-export.json'],   // trimmed to empty at import, so falsy
      ['ok name', 'ok-name.json'],
      ['Report: "Q1" / 2026', 'Report-Q1-2026.json'],
    ] as [string, string][]) {
      await importNative(page, bytes({ assignments: { 'IN:reconnaissance': { techniques: [] } }, title }), 'name.json');
      const exported = await exportNative(page);
      expect(exported.name, `title ${JSON.stringify(title)}`).toBe(expected);
    }
  });
});

test.describe('RT-17 export filename gap', () => {
  // One case per title: a loop would stop at the first title and leave the rest unproven,
  // and the Latin and non-Latin cases fail for the same reason but matter differently.
  // The fallback is chosen by `state.title ? slug : 'attack-chain-export'`, which tests
  // the RAW title, not the slug. A non-empty title whose every character is stripped
  // produces an empty slug and the download name '.json' -- a dotfile, hidden on POSIX
  // systems and renamed inconsistently by browsers.
  for (const title of ['***', '///...///', 'Ελληνικά', '日本語']) {
    test(`a title of only stripped characters (${title}) falls back to a safe filename`, async ({ page }) => {
      await openApp(page);
      await importNative(page, bytes({ assignments: { 'IN:reconnaissance': { techniques: [] } }, title }), 'name.json');

      // Prerequisite: the title really did survive import, so the slug is what is at
      // fault rather than the title being dropped earlier.
      expect((await readState(page)).title).toBe(title);

      const exported = await exportNative(page);
      test.fail(true, 'Known gap AF-RT-006: a title that slugs to empty yields a dotfile name, not the fallback');
      expect(exported.name).toBe('attack-chain-export.json');
    });
  }
});

test.describe('RT-17 repeated operations', () => {
  test('the same file imports again after the input is reset', async ({ page }) => {
    await openApp(page);
    const file = bytes(nativeFull());

    await importNative(page, file, 'same.json');
    const first = await readState(page);

    // importKillChain() clears input.value, so selecting the same file must fire again.
    expect(await page.locator('#import-killchain-input').inputValue()).toBe('');
    await importNative(page, file, 'same.json');
    expect(await readState(page)).toEqual(first);

    // Repeated exports are stable and never accumulate objects.
    const a = await exportNative(page);
    const b = await exportNative(page);
    expect(b.json.assignments).toEqual(a.json.assignments);
    expect(b.json.stixBundle.objects).toHaveLength(a.json.stixBundle.objects.length);
  });
});

test.describe('RT-18 session and configuration isolation', () => {
  test('a fresh context starts from defaults with no inherited document', async ({ page }) => {
    await openApp(page);
    const state = await readState(page);
    expect(state.customLibrary).toEqual({});
    expect(state.title).toBe('');
    expect(state.description).toBe('');
    expect(state.view).toBe('killchain');
    expect(state.activeTab).toBe('attack');
    expect(state.hideEmpty).toBe(false);
    expect(state.compactMode).toBe(false);
    for (const phase of Object.values(state.assignments) as any[]) {
      expect(phase.customItems).toEqual([]);
      expect(phase.groups).toEqual([]);
    }
  });

  /**
   * Opens the app with imports.* flags overridden in a test-local config response.
   * Production config.js is never modified. The override must be registered AFTER the
   * catch-all external-request block, because Playwright matches the most recently
   * added route first -- and before navigation, since config.js loads with the page.
   */
  async function openAppWithImportFlags(page: Page, flags: Record<string, boolean>) {
    await installRequestGuard(page.context());
    const configUrl = new URL('/config.js', BASE_URL).href;
    await page.context().route(configUrl, async route => {
      const response = await route.fetch();
      let body = await response.text();
      for (const [key, value] of Object.entries(flags)) {
        const pattern = new RegExp(`(${key}\\s*:\\s*)(true|false)`);
        expect(pattern.test(body), `config.js must define ${key}`).toBe(true);
        body = body.replace(pattern, `$1${value}`);
      }
      return route.fulfill({ status: 200, contentType: 'application/javascript', body });
    });
    await page.goto('/index.html');
    await expect(page.locator('#loading')).toHaveClass(/hidden/, { timeout: 60_000 });
    await page.evaluate(() => { (window as any).__rtExecuted = false; });
    expectNoExternalRequests(page);
  }

  for (const clearOnKillChain of [true, false]) {
    test(`clearStixOnKillChainImport=${clearOnKillChain} treats the existing library consistently`, async ({ page }) => {
      await openAppWithImportFlags(page, { clearStixOnKillChainImport: clearOnKillChain });
      expect(await page.evaluate(() => eval('CONFIG').imports.clearStixOnKillChainImport)).toBe(clearOnKillChain);

      // Load a document whose library holds an object the next import does not mention.
      await importNative(page, bytes(nativeFull()), 'first-doc.json');
      expect((await readState(page)).customLibrary[IDS.tool]).toBeDefined();

      const secondId = 'campaign--77777777-7777-4777-8777-777777777777';
      await importNative(page, bytes({
        assignments: { 'IN:reconnaissance': { techniques: [] } },
        customLibrary: { [secondId]: { id: secondId, stixType: 'campaign', name: 'Second doc campaign' } },
      }), 'second-doc.json');

      const library = (await readState(page)).customLibrary;
      expect(library[secondId], 'the incoming library entry always arrives').toBeDefined();
      // The flag decides only whether the PREVIOUS document's objects survive.
      expect(Object.prototype.hasOwnProperty.call(library, IDS.tool)).toBe(!clearOnKillChain);
      if (!clearOnKillChain) expect(library[IDS.identity]).toBeDefined();
    });
  }

  for (const clearOnBundle of [true, false]) {
    test(`clearStixOnBundleImport=${clearOnBundle} treats existing STIX assignments consistently`, async ({ page }) => {
      await openAppWithImportFlags(page, { clearStixOnBundleImport: clearOnBundle });
      expect(await page.evaluate(() => eval('CONFIG').imports.clearStixOnBundleImport)).toBe(clearOnBundle);

      await importNative(page, bytes(nativeFull()), 'bundle-flag-baseline.json');
      const assignedBefore = (await readState(page)).assignments['THROUGH:lateral-movement'].customItems.length;
      expect(assignedBefore).toBeGreaterThan(0);

      const incoming = 'campaign--88888888-8888-4888-8888-888888888888';
      await importStix(page, bytes({
        type: 'bundle', id: 'bundle--88888888-8888-4888-8888-888888888888', spec_version: '2.1',
        objects: [{ type: 'campaign', spec_version: '2.1', id: incoming, name: 'Incoming campaign' }],
      }), 'incoming.json');
      await expect(page.locator('#toast')).toContainText('Imported 1 STIX object');

      const state = await readState(page);
      expect(state.customLibrary[incoming]).toBeDefined();
      // Clearing wipes existing STIX assignments; not clearing leaves them in place.
      const after = state.assignments['THROUGH:lateral-movement'].customItems.length;
      expect(after).toBe(clearOnBundle ? 0 : assignedBefore);
      expect(Object.prototype.hasOwnProperty.call(state.customLibrary, IDS.identity)).toBe(!clearOnBundle);
    });
  }

  test('compact mode forces hide-empty and an import cannot undo it', async ({ page }) => {
    await openApp(page);
    await page.evaluate(() => (window as any).setCompactMode(true));
    expect(await page.evaluate(() => eval('state').hideEmpty)).toBe(true);

    // The document says hideEmpty:false, but compact mode wins at import time.
    await importNative(page, bytes({
      assignments: { 'IN:reconnaissance': { techniques: [] } }, hideEmpty: false,
    }), 'compact.json');
    const state = await readState(page);
    expect(state.compactMode).toBe(true);
    expect(state.hideEmpty).toBe(true);
  });
});
