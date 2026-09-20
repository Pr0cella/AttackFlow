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

import fs from 'node:fs';
import { expect, type Browser, type Download, type Page } from '@playwright/test';

export const BASE_URL = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:4173';

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
  'filters', 'layers', 'hideEmpty', 'assignments', 'selection', 'customLibrary',
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
  const blocked: string[] = [];
  const localOrigin = new URL(BASE_URL).origin;
  await page.route('**/*', route => {
    const url = route.request().url();
    if (new URL(url).origin === localOrigin) return route.continue();
    blocked.push(url);
    return route.abort();
  });
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

export async function exportNative(page: Page) {
  const captured = await capture(page, () => page.evaluate(() => (window as any).exportJSON()));
  return { ...captured, json: JSON.parse(captured.text) };
}

export async function exportStix(page: Page) {
  const captured = await capture(page, () => page.evaluate(() => (window as any).exportSTIXBundle()));
  return { ...captured, json: JSON.parse(captured.text) };
}

export async function exportCsv(page: Page) {
  return capture(page, () => page.evaluate(() => (window as any).exportCSV()));
}

/** Asserts an export control produced no download at all within the given window. */
export async function expectNoDownload(page: Page, trigger: () => Promise<unknown>, ms = 1500) {
  const pending = page.waitForEvent('download', { timeout: ms }).then(() => 'download', () => 'none');
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
  const context = await browser.newContext({ baseURL: BASE_URL, acceptDownloads: true });
  try {
    const page = await context.newPage();
    const blocked = await openApp(page);
    return await body(page, blocked);
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
export function expectNativeExportsEquivalent(first: any, second: any, startedAt: number) {
  const strip = (doc: any) => {
    const copy = JSON.parse(JSON.stringify(doc));
    delete copy.exportedAt;
    delete copy.stixBundle;
    // `editing` is a transient rename flag that commitRenameGroup() leaves behind and
    // exportJSON() serializes (AF-RT-004). The importer drops it, so it can appear in a
    // first export and never in later ones. Convergence is judged without it; the leak
    // itself is asserted directly in RT-04 so it stays visible.
    for (const phase of Object.values(copy.assignments || {}) as any[]) {
      for (const group of phase?.groups || []) delete group.editing;
    }
    return copy;
  };
  expect(strip(second)).toEqual(strip(first));

  if (!first.stixBundle && !second.stixBundle) return;
  expect(Boolean(second.stixBundle), 'embedded bundle presence must match').toBe(Boolean(first.stixBundle));

  // Three provenance classes, each with its own comparison rule:
  //  - preserved: an SDO from the custom library, carrying analyst-supplied timestamps
  //  - derived:   an object regenerated from framework data (attack-pattern, mitigation).
  //               Its id is deterministic but created/modified are stamped at export time.
  //  - edge:      a relationship, regenerated with a fresh random id every export.
  const split = (bundle: any, doc: any) => {
    expect(bundle.type).toBe('bundle');
    expect(bundle.id).toMatch(/^bundle--[0-9a-f-]{36}$/);
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

  // Derived objects: identical ids and content, only the export stamp may move.
  expect(withoutStamps(b.derived)).toEqual(withoutStamps(a.derived));
  for (const object of b.derived) {
    expectIsoTimestampWithin(object.created, startedAt);
    expectIsoTimestampWithin(object.modified, startedAt);
  }

  // Regenerated edges: equal multiset of semantic keys, and equal count.
  const key = (o: any) => [o.type, o.relationship_type, o.source_ref, o.target_ref].join('|');
  const tally = (objects: any[]) => {
    const counts = new Map<string, number>();
    for (const o of objects) counts.set(key(o), (counts.get(key(o)) || 0) + 1);
    return counts;
  };
  expect(b.edges.length, 'relationship count must not grow between exports').toBe(a.edges.length);
  expect([...tally(b.edges).entries()].sort()).toEqual([...tally(a.edges).entries()].sort());

  // No dangling reference: every endpoint resolves to an object in the same bundle.
  const presentIds = new Set(second.stixBundle.objects.map((o: any) => o.id));
  for (const edge of b.edges) {
    expect(edge.id).toMatch(/^relationship--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expectIsoTimestampWithin(edge.created, startedAt);
    expectIsoTimestampWithin(edge.modified, startedAt);
    expect(presentIds.has(edge.source_ref), `dangling source_ref ${edge.source_ref}`).toBe(true);
    expect(presentIds.has(edge.target_ref), `dangling target_ref ${edge.target_ref}`).toBe(true);
  }
  expect(new Set(b.edges.map((o: any) => o.id)).size, 'edge ids must be unique').toBe(b.edges.length);
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

/** Asserts no injected node, no executed canary, and no unexpected page error. */
export async function expectInertRender(page: Page, errors: string[] = []) {
  await expect(page.locator('[data-rt-injected]')).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).__rtExecuted)).toBe(false);
  expect(await page.evaluate(() => ({} as any).polluted), 'prototype was polluted').toBeUndefined();
  expect(errors, 'unexpected page errors').toEqual([]);
}
