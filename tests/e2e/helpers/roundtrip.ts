// Shared harness for the import/export round-trip suite.
//
// The suite proves what survives import, editing, export and fresh-session reimport across
// every exposed import/export entry point. Specs are keyed by RT-nn route ids that appear
// in their describe titles: RT-01..RT-05 native documents, RT-06 the STIX type matrix,
// RT-07/RT-08 STIX projection and generated graph, RT-09..RT-11 Composer and cross-page,
// RT-12..RT-14 CSV and the asymmetric import routes, RT-15 legacy inputs, RT-16 restored
// views, RT-17/RT-18 failure paths and configuration.
//
// Scope rule: this file holds only needs proven by more than one round-trip spec --
// isolated contexts, real download bytes, named state snapshots, and the one documented
// native-import normalization. It deliberately contains no expected values: oracles are
// hand-authored beside their fixtures so a serializer bug cannot rewrite its own expectation.
//
// One cross-file contract lives here: the egress guard records any nonlocal request attempt
// to HARNESS_VIOLATION_LOG, and zz-harness-audit.spec.ts fails the run on its contents. See
// the comment at that constant for why the check cannot live inside the offending test.

import fs from 'node:fs';
import path from 'node:path';
import {
  expect, test, type Browser, type BrowserContext, type Download, type Page,
} from '@playwright/test';

export const BASE_URL = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:4173';

const baseUrl = new URL(BASE_URL);
const loopbackHosts = new Set(['127.0.0.1', 'localhost', '[::1]']);
if (!['http:', 'https:'].includes(baseUrl.protocol) || !loopbackHosts.has(baseUrl.hostname) ||
    baseUrl.username || baseUrl.password) {
  throw new Error(`PLAYWRIGHT_BASE_URL must be an uncredentialed loopback HTTP(S) URL: ${BASE_URL}`);
}

const LOCAL_ORIGIN = baseUrl.origin;
const requestAttempts = new WeakMap<BrowserContext, string[]>();
const MAX_RECORDED_REQUEST_ATTEMPTS = 20;

// Harness violations are reported OUT OF BAND, in a file read by zz-harness-audit.spec.ts.
//
// A `test.fail` marker makes Playwright treat any failure of that test as the expected
// one. Measured, not assumed: that absorption covers an error thrown from the test body,
// AND an error thrown from an afterAll hook in the same file -- a probe that attempted
// egress inside a marked body and threw from both places still reported "1 passed" with
// exit code 0. So an egress violation inside a known-gap test cannot be surfaced from
// anywhere in that test's own lifecycle.
//
// The file is the escape hatch: a spec with no marker of its own reads it at the end of
// the run and fails on its contents, so a harness violation can never be credited to a
// runtime defect marker.
export const HARNESS_VIOLATION_LOG =
  path.resolve(__dirname, '../../../test-results/harness-violations.log');

function recordHarnessViolation(message: string) {
  try {
    fs.mkdirSync(path.dirname(HARNESS_VIOLATION_LOG), { recursive: true });
    fs.appendFileSync(HARNESS_VIOLATION_LOG, `${message}\n`, 'utf8');
  } catch {
    // Never mask the violation itself behind a logging failure; the in-test throw below
    // still reports it whenever the test carries no marker.
  }
}

/** Installs the suite's exact-origin egress guard once for a browser context. */
export async function installRequestGuard(context: BrowserContext): Promise<string[]> {
  const existing = requestAttempts.get(context);
  if (existing) return existing;

  const attempts: string[] = [];
  requestAttempts.set(context, attempts);
  const recordAttempt = (url: string) => {
    if (attempts.length < MAX_RECORDED_REQUEST_ATTEMPTS) attempts.push(url.slice(0, 2048));
    else if (attempts.length === MAX_RECORDED_REQUEST_ATTEMPTS) {
      attempts.push('[additional nonlocal request attempts omitted]');
    }
  };
  await context.route('**/*', route => {
    const url = route.request().url();
    let origin: string;
    try {
      origin = new URL(url).origin;
    } catch {
      recordAttempt(url);
      return route.abort('blockedbyclient');
    }
    if (origin === LOCAL_ORIGIN) return route.continue();
    recordAttempt(url);
    return route.abort('blockedbyclient');
  });
  return attempts;
}

/** Fails a flow if any request outside the one approved loopback origin was attempted. */
export function expectNoExternalRequests(page: Page) {
  const attempts = requestAttempts.get(page.context());
  expect(attempts, 'request guard must be installed before navigation').toBeDefined();
  expect(attempts, 'no nonlocal request may be attempted').toEqual([]);
}

// Hand-authored from index.html KILL_CHAIN. Specs assert the running app matches this
// roster, so a silently added or removed phase fails instead of being absorbed.
export const ALL_PHASES = [
  'IN:reconnaissance', 'IN:resource-development', 'IN:delivery', 'IN:social-engineering',
  'IN:exploitation', 'IN:persistence', 'IN:defense-evasion', 'IN:command-control',
  'THROUGH:pivoting', 'THROUGH:discovery', 'THROUGH:privilege-escalation', 'THROUGH:execution',
  'THROUGH:credential-access', 'THROUGH:lateral-movement',
  'OUT:collection', 'OUT:exfiltration', 'OUT:impact', 'OUT:objectives',
] as const;

// Hand-authored from index.html TYPE_KEYS.
export const TYPE_KEYS: Record<string, string> = {
  attack: 'techniques', capec: 'capecs', cwe: 'cwes', custom: 'customItems',
};

export const ASSIGNMENT_KEYS = ['techniques', 'capecs', 'cwes', 'customItems'] as const;

// Hand-authored from index.html exportJSON(). stixBundle is conditional on a non-empty
// custom library and is therefore not part of the unconditional key set.
export const NATIVE_EXPORT_KEYS = [
  'version', 'schema', 'exportedAt', 'title', 'description', 'view', 'activeTab',
  'layers', 'hideEmpty', 'assignments', 'customLibrary',
] as const;

export type PhaseData = {
  techniques: any[]; capecs: any[]; cwes: any[]; customItems: any[];
  groups: any[]; layout: any[];
};

export type NativeState = {
  title: string; description: string; view: string; activeTab: string;
  layers: Record<string, boolean>; hideEmpty: boolean; compactMode: boolean;
  filters: Record<string, string>; selection: { type: string | null; id: string | null };
  assignments: Record<string, PhaseData>;
  customLibrary: Record<string, any>;
  techniqueIds: string[];
};

/**
 * Opens the real app with every non-local request refused at the context level.
 * Returns the list of refused URLs so a spec can assert that nothing was attempted
 * rather than only that nothing succeeded.
 */
export async function openApp(page: Page): Promise<string[]> {
  const blocked = await installRequestGuard(page.context());
  await page.goto('/index.html');
  await expect(page.locator('#loading')).toHaveClass(/hidden/, { timeout: 60_000 });
  await page.evaluate(() => { (window as any).__rtExecuted = false; });
  return blocked;
}

/** Reads app state through a structured clone so later mutations cannot alter a snapshot. */
export async function readState(page: Page): Promise<NativeState> {
  return page.evaluate(() => {
    const app = eval('state');
    return JSON.parse(JSON.stringify({
      title: app.title, description: app.description, view: app.view, activeTab: app.activeTab,
      layers: app.layers, hideEmpty: app.hideEmpty, compactMode: app.compactMode,
      filters: app.filters, selection: app.selection,
      assignments: app.assignments, customLibrary: app.library.custom,
      techniqueIds: Object.keys(app.library.techniques),
    }));
  });
}

export async function importNative(page: Page, buffer: Buffer, name = 'roundtrip.json') {
  await clearToast(page);
  await page.locator('#import-killchain-input').setInputFiles({
    name, mimeType: 'application/json', buffer,
  });
  await expect(page.locator('#toast')).toHaveText('Imported kill chain');
}

/**
 * FileReader.onload is asynchronous, so reading state straight after setInputFiles races
 * the import. Both paths set a toast on every outcome, success or failure, so waiting for
 * a non-empty toast is a reliable completion signal. Callers still assert the exact text.
 */
async function importAndSettle(page: Page, selector: string, buffer: Buffer, name: string) {
  await clearToast(page);
  await page.locator(selector).setInputFiles({ name, mimeType: 'application/json', buffer });
  await expect(page.locator('#toast')).not.toBeEmpty();
}

export async function importStix(page: Page, buffer: Buffer, name = 'roundtrip-bundle.json') {
  await importAndSettle(page, 'input[onchange="importStixBundle(event)"]', buffer, name);
}

export async function importNavigatorLayer(page: Page, buffer: Buffer, name = 'roundtrip-layer.json') {
  await importAndSettle(page, 'input[onchange="importNavigator(event)"]', buffer, name);
}

export async function clearToast(page: Page) {
  await page.locator('#toast').evaluate(el => { el.textContent = ''; });
}

type Captured = { name: string; buffer: Buffer; text: string };

/** Registers the download listener before triggering export, then reads the real bytes. */
async function capture(page: Page, trigger: () => Promise<unknown>): Promise<Captured> {
  const [download] = await Promise.all([page.waitForEvent('download'), trigger()]) as [Download, unknown];
  const downloadPath = await download.path();
  expect(downloadPath, 'export produced no download file').not.toBeNull();
  const buffer = fs.readFileSync(downloadPath!);
  return { name: download.suggestedFilename(), buffer, text: buffer.toString('utf8') };
}

/**
 * Drives the real export menu: open the dropdown, click the named item.
 *
 * Exported so that cases which expect NO download share the same entry point as the
 * capturing helpers below. If an export control is ever unwired, every caller fails.
 */
export async function clickExportControl(page: Page, name: 'JSON' | 'CSV' | 'STIX Bundle') {
  const dropdown = page.locator('#export-dropdown');
  await dropdown.locator(':scope > button.btn').click();
  await dropdown.getByRole('button', { name, exact: true }).click();
}

export async function exportNative(page: Page) {
  const captured = await capture(page, () => clickExportControl(page, 'JSON'));
  return { ...captured, json: JSON.parse(captured.text) };
}

export async function exportStix(page: Page) {
  const captured = await capture(page, () => clickExportControl(page, 'STIX Bundle'));
  return { ...captured, json: JSON.parse(captured.text) };
}

export async function exportCsv(page: Page) {
  return capture(page, () => clickExportControl(page, 'CSV'));
}

/** Asserts an export control produced no download at all within the given window. */
export async function expectNoDownload(page: Page, trigger: () => Promise<unknown>, ms = 1500) {
  const pending = page.waitForEvent('download', { timeout: ms }).then(
    () => 'download' as const,
    error => {
      if (error instanceof Error && error.name === 'TimeoutError') return 'none' as const;
      throw error;
    },
  );
  await trigger();
  expect(await pending, 'export unexpectedly produced a download').toBe('none');
}

/**
 * Runs body in a brand-new context with no copied storage or state, so a restored
 * document can never be satisfied by data left behind by the exporting context.
 */
export async function withFreshContext<T>(
  browser: Browser,
  body: (page: Page, blocked: string[]) => Promise<T>,
): Promise<T> {
  const context = await browser.newContext({
    baseURL: BASE_URL, acceptDownloads: true, serviceWorkers: 'block',
  });
  try {
    const page = await context.newPage();
    const blocked = await openApp(page);
    // Recorded before any assertion so it survives whatever happens to this test.
    const recordEgress = () => {
      const attempts = requestAttempts.get(page.context());
      if (attempts && attempts.length > 0) {
        recordHarnessViolation(
          `${test.info().titlePath.slice(1).join(' > ')} attempted: ${attempts.join(', ')}`,
        );
      }
    };
    let result: T;
    try {
      result = await body(page, blocked);
    } catch (bodyError) {
      // The egress audit must also run when the body fails, including when it fails by
      // design under a `test.fail` marker. Otherwise a harness violation is silently
      // credited to a known runtime defect and never reported at all. Both diagnostics
      // are preserved: the egress violation names itself and carries the original.
      recordEgress();
      try {
        expectNoExternalRequests(page);
      } catch (egressError) {
        const original = bodyError instanceof Error
          ? (bodyError.stack || bodyError.message) : String(bodyError);
        throw new Error(
          `${(egressError as Error).message}\n\nThe body also failed:\n${original}`,
        );
      }
      throw bodyError;
    }
    recordEgress();
    expectNoExternalRequests(page);
    return result;
  } finally {
    await context.close();
  }
}

/**
 * The single documented native-import normalization: ungrouped assignments lose the
 * redundant `type` property because their array placement already carries it
 * (index.html sanitizeImportedAssignment). Grouped items keep `type`, and every
 * instanceId is retained. Applied to an expectation, never to observed state.
 */
export function dropUngroupedTypes<T>(value: T): T {
  const copy = JSON.parse(JSON.stringify(value));
  const phases = (copy && copy.assignments) ? copy.assignments : copy;
  for (const phase of Object.values(phases || {}) as any[]) {
    if (!phase) continue;
    for (const key of ASSIGNMENT_KEYS) {
      for (const item of phase[key] || []) delete item.type;
    }
  }
  return copy;
}

/**
 * Compares two native exports of the same unchanged document.
 *
 * Everything outside the embedded bundle must match exactly. Inside it, buildSTIXBundle()
 * regenerates derived relationship objects with a fresh UUID and timestamp on every call,
 * so those are matched through a bijection keyed by semantic endpoints. Multiplicity is
 * checked before matching so a duplicate edge cannot disappear into a set comparison, and
 * every regenerated id and timestamp is still validated for syntax.
 */
/** A real UUID shape, not "36 hex-or-hyphen characters in any arrangement". */
export const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';

/** Validates the parts of a native export that must hold before anything is excluded. */
function expectNativeEnvelope(doc: any, startedAt: number, label: string) {
  expect(typeof doc.version, `${label} version`).toBe('string');
  expect(doc.version.length, `${label} version`).toBeGreaterThan(0);
  expect(doc.schema, `${label} schema`).toBe('killchain-export-lite');
  // Validated, then excluded from equality. Never excluded without validating.
  expectIsoTimestampWithin(doc.exportedAt, startedAt);
  expect(Object.keys(doc).sort(), `${label} own-key surface`)
    .toEqual([...(doc.stixBundle ? [...NATIVE_EXPORT_KEYS, 'stixBundle'] : NATIVE_EXPORT_KEYS)].sort());
}

/** Validates an embedded or standalone bundle envelope and its id uniqueness. */
export function expectBundleEnvelope(bundle: any, label: string) {
  expect(bundle.type, `${label} type`).toBe('bundle');
  expect(bundle.spec_version, `${label} spec_version`).toBe('2.1');
  expect(bundle.id, `${label} id`).toMatch(new RegExp(`^bundle--${UUID}$`));
  expect(Array.isArray(bundle.objects), `${label} objects`).toBe(true);
  const ids = bundle.objects.map((o: any) => o.id);
  expect(new Set(ids).size, `${label} duplicate object ids`).toBe(ids.length);
  for (const object of bundle.objects) {
    expect(object.spec_version, `${label} ${object.id} spec_version`).toBe('2.1');
  }
  // Every reference resolves inside the same bundle.
  const present = new Set(ids);
  for (const edge of bundle.objects.filter((o: any) => o.type === 'relationship')) {
    expect(present.has(edge.source_ref), `${label} dangling source_ref ${edge.source_ref}`).toBe(true);
    expect(present.has(edge.target_ref), `${label} dangling target_ref ${edge.target_ref}`).toBe(true);
  }
}

/**
 * Compares two native exports of the same unchanged document.
 *
 * Volatile values are VALIDATED in both artifacts before being excluded, never excluded
 * on trust. Objects fall into three provenance classes with different rules:
 *
 *   preserved  an SDO from the custom library, carrying analyst-supplied timestamps.
 *              Compared whole, timestamps included.
 *   derived    regenerated from framework data (attack-pattern, course-of-action). Its id
 *              is deterministic; only created/modified may move.
 *   edge       a relationship, regenerated with a fresh id every export. Compared as a
 *              COMPLETE record minus id/created/modified, so a dropped description or a
 *              corrupted spec_version is caught. Multiplicity is checked before matching
 *              so a duplicated edge cannot disappear into a set.
 *
 * The comparison is STRICT about the transient group `editing` flag by default: any group
 * carrying that key fails unless the caller names its exact phase/group path, and the
 * value `true` is never tolerated at any path. Only the group-lifecycle test declares a
 * path, because only it performs a rename. Once the app stops writing the flag, that
 * declaration is removed and this stays as an ordinary regression.
 */
export type NativeCompareOptions = {
  /** Exact `phaseKey/groupId` paths permitted to carry the transient `editing: false`. */
  editingLeakPaths?: readonly string[];
};

export function expectNativeExportsEquivalent(
  first: any, second: any, startedAt: number, options: NativeCompareOptions = {},
) {
  expectNativeEnvelope(first, startedAt, 'first export');
  expectNativeEnvelope(second, startedAt, 'second export');

  // `editing` is a transient rename flag: commitRenameGroup() sets it to false instead of
  // deleting the key, and the exporter serializes the assignment tree verbatim, so a
  // UI-only flag with no place in the document schema reaches the downloaded file. The
  // importer drops it again, so it may appear in a
  // first export and never in later ones. Each occurrence is ASSERTED here -- allowed
  // path, and value exactly false -- before it is excluded, so an unexpected leak, a new
  // leaking group, or a flag left at `true` fails instead of being normalized away.
  const allowedEditingPaths = new Set(options.editingLeakPaths || []);
  const auditEditing = (doc: any, label: string) => {
    for (const [phaseKey, phase] of Object.entries(doc.assignments || {}) as [string, any][]) {
      for (const group of phase?.groups || []) {
        if (!Object.prototype.hasOwnProperty.call(group, 'editing')) continue;
        const path = `${phaseKey}/${group.groupId}`;
        expect(allowedEditingPaths.has(path),
          `${label}: undeclared transient 'editing' flag at ${path}`).toBe(true);
        expect(group.editing,
          `${label}: 'editing' must never be true at ${path}`).toBe(false);
      }
    }
  };
  auditEditing(first, 'first export');
  auditEditing(second, 'second export');

  const strip = (doc: any) => {
    const copy = JSON.parse(JSON.stringify(doc));
    delete copy.exportedAt;   // validated above
    delete copy.stixBundle;   // compared below
    // Only the paths asserted immediately above are excluded, never `editing` at large.
    for (const [phaseKey, phase] of Object.entries(copy.assignments || {}) as [string, any][]) {
      for (const group of phase?.groups || []) {
        if (allowedEditingPaths.has(`${phaseKey}/${group.groupId}`)) delete group.editing;
      }
    }
    return copy;
  };
  expect(strip(second)).toEqual(strip(first));

  if (!first.stixBundle && !second.stixBundle) return;
  expect(Boolean(second.stixBundle), 'embedded bundle presence must match').toBe(Boolean(first.stixBundle));

  expectBundleEnvelope(first.stixBundle, 'first embedded bundle');
  expectBundleEnvelope(second.stixBundle, 'second embedded bundle');

  const split = (bundle: any, doc: any) => {
    const libraryIds = new Set(Object.keys(doc.customLibrary || {}));
    return {
      preserved: bundle.objects.filter((o: any) => libraryIds.has(o.id)),
      derived: bundle.objects.filter((o: any) => !libraryIds.has(o.id) && o.type !== 'relationship'),
      edges: bundle.objects.filter((o: any) => o.type === 'relationship'),
    };
  };
  const a = split(first.stixBundle, first);
  const b = split(second.stixBundle, second);

  const byId = (objects: any[]) => [...objects].sort((x, y) => x.id.localeCompare(y.id));
  const withoutStamps = (objects: any[]) => byId(objects).map(o => {
    const copy = { ...o };
    delete copy.created;
    delete copy.modified;
    return copy;
  });

  // Analyst-owned SDOs must match exactly, supplied timestamps included.
  expect(byId(b.preserved)).toEqual(byId(a.preserved));

  // Derived objects: identical ids and content, only the export stamp may move. Both
  // artifacts are validated, not just the second.
  expect(b.derived.length, 'derived object count must not change').toBe(a.derived.length);
  expect(withoutStamps(b.derived)).toEqual(withoutStamps(a.derived));
  for (const [label, objects] of [['first', a.derived], ['second', b.derived]] as const) {
    for (const object of objects) {
      expectIsoTimestampWithin(object.created, startedAt);
      expectIsoTimestampWithin(object.modified, startedAt);
    }
  }

  // Edges: multiset of COMPLETE records, excluding only genuinely regenerated fields.
  const record = (o: any) => {
    const copy = { ...o };
    delete copy.id;
    delete copy.created;
    delete copy.modified;
    return stableStringify(copy);
  };
  const tally = (objects: any[]) => {
    const counts = new Map<string, number>();
    for (const o of objects) counts.set(record(o), (counts.get(record(o)) || 0) + 1);
    return [...counts.entries()].sort();
  };
  expect(b.edges.length, 'relationship count must not grow between exports').toBe(a.edges.length);
  expect(tally(b.edges), 'relationship records must match, descriptions included').toEqual(tally(a.edges));

  for (const [label, objects] of [['first', a.edges], ['second', b.edges]] as const) {
    for (const edge of objects) {
      expect(edge.id, `${label} edge id`).toMatch(new RegExp(`^relationship--${UUID}$`));
      expectIsoTimestampWithin(edge.created, startedAt);
      expectIsoTimestampWithin(edge.modified, startedAt);
    }
    expect(new Set(objects.map((o: any) => o.id)).size, `${label} edge ids must be unique`)
      .toBe(objects.length);
  }
}

/** Stable object-key ordering for diagnostics only; array order is never touched. */
export function stableStringify(value: unknown): string {
  return JSON.stringify(value, (_key, val) => {
    if (val && typeof val === 'object' && !Array.isArray(val)) {
      return Object.fromEntries(Object.keys(val).sort().map(k => [k, val[k]]));
    }
    return val;
  }, 2);
}

/** Verifies a volatile value before a spec excludes it from an equality comparison. */
export function expectIsoTimestampWithin(value: unknown, startedAt: number, skewMs = 120_000) {
  expect(typeof value, 'timestamp must be a string').toBe('string');
  const parsed = Date.parse(value as string);
  expect(Number.isFinite(parsed), `unparseable timestamp: ${value}`).toBe(true);
  expect(value).toBe(new Date(parsed).toISOString());
  expect(parsed).toBeGreaterThanOrEqual(startedAt - skewMs);
  expect(parsed).toBeLessThanOrEqual(Date.now() + skewMs);
}

/**
 * Dispatches the application's REAL dragstart and drop handlers.
 *
 * This is deterministic coverage of those handlers, NOT physical pointer-gesture
 * coverage; a real pointer drag is recorded as an unautomated manual check. It exists
 * because assignment has no non-drag entry point: seeding assignments with a second
 * native import instead would call initAssignments(), which restores the full base
 * technique library and therefore destroys the very filtered library under test.
 */
export async function dispatchDragAndDrop(page: Page, sourceSelector: string, targetSelector: string) {
  await page.evaluate(({ sourceSelector, targetSelector }) => {
    const source = document.querySelector(sourceSelector);
    const target = document.querySelector(targetSelector);
    if (!source) throw new Error(`drag source missing: ${sourceSelector}`);
    if (!target) throw new Error(`drop target missing: ${targetSelector}`);
    const transfer = new DataTransfer();
    source.dispatchEvent(new DragEvent('dragstart', { bubbles: true, cancelable: true, dataTransfer: transfer }));
    target.dispatchEvent(new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: transfer }));
    source.dispatchEvent(new DragEvent('dragend', { bubbles: true, cancelable: true, dataTransfer: transfer }));
  }, { sourceSelector, targetSelector });
}

/** Asserts no injected node, no executed canary, and no unexpected page error. */
export async function expectInertRender(page: Page, errors: string[] = []) {
  await expect(page.locator('[data-rt-injected]')).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).__rtExecuted)).toBe(false);
  expect(await page.evaluate(() => ({} as any).polluted), 'prototype was polluted').toBeUndefined();
  expect(errors, 'unexpected page errors').toEqual([]);
}
