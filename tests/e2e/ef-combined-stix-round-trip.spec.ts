import fs from 'node:fs';
import { expect, test, type Page } from '@playwright/test';
import {
  expectNoExternalRequests, installRequestGuard,
} from './helpers/roundtrip';

test.use({ serviceWorkers: 'block' });
test.afterEach(async ({ page }) => expectNoExternalRequests(page));

// Combined EF-01 + EF-02 lifecycle:
// STIX bundle import -> STIX editor modification -> STIX download -> re-import in a fresh browser context.
// Each independent suite covers only part of this path.

type Values = Record<string, unknown>;

const created = '2026-01-01T00:00:00.000Z';
const modified = '2026-01-02T00:00:00.000Z';

// List items stay comma-free because the editor represents lists as comma-separated text.
// Enum values must come from their vocabulary because the editor renders enums as <select>.
// Open-vocab custom values are rendered as extra <option> values, exercising attribute encoding.
const importedProperties: Record<string, Values> = {
  'attack-pattern': {
    aliases: ['Spear "Alias" [1]', 'APT--Pattern; <v2>'],
  },
  campaign: {
    aliases: ["Op {Night}; 'Fall'"],
    first_seen: '2025-01-01T00:00:00.000Z',
    last_seen: '2025-02-01T00:00:00.000Z',
    objective: 'Collect {records}; retain [brackets] "quotes" & <tags> -- \\\\share',
  },
  'course-of-action': {},
  grouping: {
    context: 'custom"><img data-rt-injected src=x onerror="window.__rtExecuted=true"> --',
    object_refs: ['indicator--11111111-1111-4111-8111-111111111111'],
  },
  identity: {
    roles: ['incident "responder" [IR]', '<lead> & --'],
    identity_class: 'organization',
    sectors: ['technology', 'custom--sector; "x"'],
    contact_information: 'soc@example.test; ext. "7" <desk> & [B] \\q --',
  },
  indicator: {
    pattern: "[file:name = 'a\\\\b' AND file:size > 10] OR [domain-name:value = 'a--b.example']",
    pattern_type: 'stix',
    valid_from: '2026-03-01T00:00:00.000Z',
    indicator_types: ['malicious-activity', 'custom "type" {x}'],
    valid_until: '2026-04-01T00:00:00.000Z',
    pattern_version: '2.1;"rc" <1>',
  },
  infrastructure: {
    infrastructure_types: ['command-and-control'],
    aliases: ['Relay--01 "edge"'],
    first_seen: '2025-03-01T00:00:00.000Z',
    last_seen: '2025-04-01T00:00:00.000Z',
  },
  'intrusion-set': {
    aliases: ['The "Dukes"', 'APT--29; <x>'],
    first_seen: '2024-01-01T00:00:00.000Z',
    last_seen: '2025-01-01T00:00:00.000Z',
    goals: ['Collect [research]', 'Maintain {access}; & more'],
    resource_level: 'government',
    primary_motivation: 'custom "motive" <x>',
    secondary_motivations: ['dominance', 'custom--motive; [y]'],
  },
  location: {
    latitude: '52.5200',
    longitude: '13.4050',
    precision: '10.5',
    region: 'western-europe',
    country: 'DE',
    administrative_area: 'Berlin "State" [BE]',
    city: 'Berlin; <Mitte> & --',
    street_address: 'Example Str. 1; Building "B" [2] {3}',
    postal_code: "10115 \\ 'x'",
  },
  malware: {
    is_family: false,
    malware_types: ['ransomware', 'custom "loader" [x]'],
    aliases: ['Sample--Family; <v1>'],
    first_seen: '2025-05-01T00:00:00.000Z',
    last_seen: '2025-06-01T00:00:00.000Z',
    operating_system_refs: ['software--22222222-2222-4222-8222-222222222222'],
    architecture_execution_envs: ['x86-64'],
    implementation_languages: ['c++', 'c#'],
    capabilities: ['anti-debugging'],
    sample_refs: ['file--33333333-3333-4333-8333-333333333333'],
  },
  'malware-analysis': {
    product: 'Sandbox--X "Pro" [9]',
    result: 'malicious',
    version: '1.2.3-rc; <b>',
    host_vm_ref: 'software--44444444-4444-4444-8444-444444444444',
    operating_system_ref: 'software--55555555-5555-4555-8555-555555555555',
    installed_software_refs: ['software--66666666-6666-4666-8666-666666666666'],
    configuration_version: "config{7}; 'x'",
    modules: ['static [pe]', 'dynamic; "net"'],
    analysis_engine_version: 'engine;4 <x>',
    analysis_definition_version: 'defs[9] & --',
    submitted: '2026-05-01T00:00:00.000Z',
    analysis_started: '2026-05-01T00:01:00.000Z',
    analysis_ended: '2026-05-01T00:02:00.000Z',
    result_name: 'Family "A" <b> & [c]',
    sample_ref: 'malware--77777777-7777-4777-8777-777777777777',
  },
  note: {
    content: 'Analyst note: preserve [brackets], {braces}; `ticks` & </textarea><img data-rt-injected src=x onerror="window.__rtExecuted=true"> -- \\end',
    abstract: 'Short -- "summary"',
    authors: ['Analyst "One"', '<Two> & [3]'],
    object_refs: ['indicator--88888888-8888-4888-8888-888888888888'],
  },
  'observed-data': {
    first_observed: '2026-06-01T00:00:00.000Z',
    last_observed: '2026-06-01T01:00:00.000Z',
    number_observed: 7,
    object_refs: ['ipv4-addr--99999999-9999-4999-8999-999999999999'],
  },
  opinion: {
    opinion: 'strongly-agree',
    explanation: 'Corroborated by source "A"; confidence [bounded] <x> & --',
    authors: ["Reviewer--2; 'b'"],
    object_refs: ['report--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'],
  },
  report: {
    published: '2026-07-01T00:00:00.000Z',
    report_types: ['threat-report', 'custom "brief" {x}'],
    object_refs: ['malware--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'],
  },
  'threat-actor': {
    threat_actor_types: ['crime-syndicate'],
    aliases: ['Actor--A "alt"'],
    first_seen: '2024-02-01T00:00:00.000Z',
    last_seen: '2026-02-01T00:00:00.000Z',
    roles: ['agent', 'custom <role>'],
    goals: ['Access {restricted} data; & [more]'],
    sophistication: 'advanced',
    resource_level: 'organization',
    primary_motivation: 'personal-gain',
    secondary_motivations: ['coercion'],
    personal_motivations: ['notoriety', "custom 'fame' --"],
  },
  tool: {
    tool_types: ['remote-access'],
    aliases: ['Admin--Tool; "x"'],
    tool_version: '5.0;beta <rc> & [1]',
  },
  vulnerability: {},
  'x-custom': {},
};

// Present in the source bundle but outside the export projection.
const unsupportedProperties: Record<string, Values> = {
  'attack-pattern': {
    kill_chain_phases: [{ kill_chain_name: 'test', phase_name: 'execution' }],
    external_references: [{ source_name: 'test', url: 'https://example.test/ref' }],
  },
  indicator: { kill_chain_phases: [{ kill_chain_name: 'test', phase_name: 'delivery' }] },
  malware: { kill_chain_phases: [{ kill_chain_name: 'test', phase_name: 'execution' }] },
  vulnerability: { external_references: [{ source_name: 'cve', external_id: 'CVE-2026-0001' }] },
};

// Editor changes. null clears the control, so the property must be omitted from export.
const editedProperties: Record<string, Values> = {
  'attack-pattern': { aliases: ['Edited "Alias" [2]', '<new> & --'] },
  campaign: { objective: 'Edited {objective}; "q" <x> & \\s --', last_seen: null },
  grouping: { context: 'malware-analysis' },
  identity: {
    contact_information: 'edited@example.test; "ext" [8] <x> &',
    sectors: ['government', 'edited--sector {y}'],
  },
  indicator: {
    pattern: "[ipv4-addr:value = '198.51.100.7'] AND [url:value = 'https://a--b.example/?q=\"x\"&y=<z>']",
    indicator_types: ['anomalous-activity'],
  },
  infrastructure: { first_seen: '2025-03-15T12:00:00.000Z' },
  'intrusion-set': { primary_motivation: 'ideology', goals: ['Edited [goal]; {x}'] },
  location: { city: 'Potsdam "Edited" [P]; <x> & --', region: 'northern-europe' },
  malware: { is_family: true, capabilities: ['evades-av', 'custom "cap" <x>'] },
  'malware-analysis': {
    product: 'Sandbox--Y "Edited" {2}',
    result: 'suspicious',
    sample_ref: 'malware--12121212-1212-4212-8212-121212121212',
  },
  note: { authors: ['Editor "Three" [3]'] },
  'observed-data': { number_observed: 42 },
  opinion: { opinion: 'disagree', explanation: 'Edited: source "B" [c]; <d> & --' },
  report: { published: '2026-07-15T08:30:00.000Z', report_types: ['campaign'] },
  'threat-actor': { sophistication: 'expert', personal_motivations: null },
  tool: { tool_version: '6.0 "final" [x]; <y> & --', aliases: null },
};

const typeIds = Object.fromEntries(Object.keys(importedProperties).map((type, index) => {
  const first = String(index + 1).padStart(8, '0');
  const tail = String(index + 1).padStart(12, '0');
  return [type, `${type}--${first}-2222-4222-8222-${tail}`];
}));

function importedCore(type: string) {
  return {
    name: `Name ${type} -- "q" [b]; <x>`,
    description: `Desc ${type}: 'a' {c}; \`t\` </textarea> &amp; \\p --`,
    labels: [`lbl-${type} [x]; "y"`, '<z> & --'],
  };
}

// Core edits for a subset of types; the other types keep their imported core values through editor save.
const editedCoreTypes = new Set(['course-of-action', 'indicator', 'malware', 'note', 'vulnerability', 'x-custom']);

function expectedCore(type: string) {
  if (!editedCoreTypes.has(type)) return importedCore(type);
  return {
    name: `Edited ${type} -- "n" [x]; <y> & z`,
    description: `Edited ${type}: </textarea> {d}; \`t\` 'q' \\p &amp; --`,
    labels: [`ed-${type} "l" [x]; <y>&`, 'second--label'],
  };
}

function expectedProperties(type: string): Values {
  const merged: Values = { ...importedProperties[type] };
  for (const [key, value] of Object.entries(editedProperties[type] || {})) {
    if (value === null) delete merged[key];
    else merged[key] = value;
  }
  return merged;
}

function sourceBundle() {
  return {
    type: 'bundle',
    id: 'bundle--cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    objects: Object.keys(importedProperties).map(type => ({
      type,
      spec_version: '2.1',
      id: typeIds[type],
      created,
      modified,
      ...importedCore(type),
      ...importedProperties[type],
      ...(unsupportedProperties[type] || {}),
      revoked: true,
      x_round_trip_extension: 'not projected',
    })),
  };
}

async function openApp(page: Page) {
  await installRequestGuard(page.context());
  await page.goto('/index.html');
  await expect(page.locator('#loading')).toHaveClass(/hidden/, { timeout: 60_000 });
  await page.evaluate(() => {
    (window as any).__rtExecuted = false;
  });
}

async function importBundleFile(page: Page, name: string, buffer: Buffer) {
  await page.locator('#toast').evaluate(element => { element.textContent = ''; });
  await page.locator('input[onchange="importStixBundle(event)"]').setInputFiles({
    name,
    mimeType: 'application/json',
    buffer,
  });
  const count = Object.keys(importedProperties).length;
  await expect(page.locator('#toast')).toHaveText(`Imported ${count} STIX objects`);
}

async function downloadStixBundle(page: Page) {
  const dropdown = page.locator('#export-dropdown');
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    (async () => {
      await dropdown.locator(':scope > button.btn').click();
      await dropdown.getByRole('button', { name: 'STIX Bundle', exact: true }).click();
    })(),
  ]);
  const downloadPath = await download.path();
  expect(downloadPath).not.toBeNull();
  const buffer = fs.readFileSync(downloadPath!);
  return { name: download.suggestedFilename(), buffer, bundle: JSON.parse(buffer.toString('utf8')) };
}

async function readFieldTypes(page: Page): Promise<Record<string, Record<string, string>>> {
  return page.evaluate(() => {
    const result: Record<string, Record<string, string>> = {};
    for (const [type, def] of Object.entries(eval('STIX_OBJECTS')) as [string, any][]) {
      result[type] = {};
      for (const field of [...(def.required || []), ...(def.optional || [])]) {
        result[type][field.key] = field.type;
      }
    }
    return result;
  });
}

async function expectEditorValue(page: Page, fieldType: string, key: string, value: unknown) {
  const control = page.locator(`#stix-edit-${key}`);
  if (fieldType === 'boolean') {
    await expect(control).toBeChecked({ checked: value as boolean });
  } else if (fieldType === 'list' || fieldType === 'list:open-vocab') {
    await expect(control).toHaveValue((value as string[]).join(', '));
  } else {
    await expect(control).toHaveValue(String(value));
  }
}

async function setEditorValue(page: Page, fieldType: string, key: string, value: unknown) {
  const control = page.locator(`#stix-edit-${key}`);
  if (fieldType === 'boolean') {
    await control.setChecked(value as boolean);
  } else if (fieldType === 'enum' || fieldType === 'open-vocab') {
    await control.selectOption(value === null ? '' : String(value));
  } else if (fieldType === 'list' || fieldType === 'list:open-vocab') {
    await control.fill(value === null ? '' : (value as string[]).join(', '));
  } else {
    await control.fill(value === null ? '' : String(value));
  }
}

function sortedObjects(bundle: any) {
  return [...bundle.objects].sort((a: any, b: any) => a.id.localeCompare(b.id));
}

test('punctuation-rich STIX values survive import, editor modification, download, and fresh re-import', async ({ page, browser }) => {
  test.setTimeout(180_000);
  await openApp(page);

  const fieldTypes = await readFieldTypes(page);
  const configuredTypes = await page.evaluate(() => eval('CONFIG').stixTypes.map((entry: any) => entry.value).sort());
  expect(Object.keys(importedProperties).sort()).toEqual(configuredTypes);
  expect(Object.keys(importedProperties).sort()).toEqual(Object.keys(fieldTypes).sort());

  // The matrix must cover every scalar and list property the export projection supports.
  const projected = new Set(['string', 'text', 'enum', 'open-vocab', 'timestamp', 'identifier', 'boolean', 'integer', 'list', 'list:open-vocab']);
  const excludedKeys = new Set(['name', 'description', 'labels', 'customTypeName']);
  for (const [type, fields] of Object.entries(fieldTypes)) {
    const supportedKeys = Object.entries(fields)
      .filter(([key, fieldType]) => projected.has(fieldType) && !excludedKeys.has(key))
      .map(([key]) => key)
      .sort();
    expect(Object.keys(importedProperties[type]).sort(), `matrix coverage for ${type}`).toEqual(supportedKeys);
    for (const key of Object.keys(editedProperties[type] || {})) {
      expect(supportedKeys, `edited key ${type}.${key}`).toContain(key);
    }
  }

  // 1. Real STIX bundle import.
  await importBundleFile(page, 'ef-round-trip-source.json', Buffer.from(JSON.stringify(sourceBundle()), 'utf8'));
  const imported = await page.evaluate(() => JSON.parse(JSON.stringify(eval('state').library.custom)));
  for (const type of Object.keys(importedProperties)) {
    expect(imported[typeIds[type]], `imported ${type}`).toMatchObject({
      id: typeIds[type],
      stixType: type,
      created,
      modified,
      ...importedCore(type),
      ...importedProperties[type],
    });
  }

  // 2. Real editor modification. Unedited controls are also read back on save.
  for (const type of Object.keys(importedProperties)) {
    await page.evaluate(id => (window as any).openStixEditor(id), typeIds[type]);
    await expect(page.locator('#edit-stix-modal')).toHaveClass(/visible/);

    const core = importedCore(type);
    await expect(page.locator('#stix-edit-name')).toHaveValue(core.name);
    await expect(page.locator('#stix-edit-description')).toHaveValue(core.description);
    await expect(page.locator('#stix-edit-labels')).toHaveValue(core.labels.join(', '));
    for (const [key, value] of Object.entries(importedProperties[type])) {
      await expectEditorValue(page, fieldTypes[type][key], key, value);
    }

    if (editedCoreTypes.has(type)) {
      const edited = expectedCore(type);
      await page.locator('#stix-edit-name').fill(edited.name);
      await page.locator('#stix-edit-description').fill(edited.description);
      await page.locator('#stix-edit-labels').fill(edited.labels.join(', '));
    }
    for (const [key, value] of Object.entries(editedProperties[type] || {})) {
      await setEditorValue(page, fieldTypes[type][key], key, value);
    }

    await page.locator('.btn-stix-save').click();
    await expect(page.locator('#edit-stix-modal')).not.toHaveClass(/visible/);
    await expect(page.locator('#toast')).toHaveText('STIX item updated');
  }
  await expect(page.locator('[data-rt-injected]')).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).__rtExecuted)).toBe(false);

  const edited = await page.evaluate(() => JSON.parse(JSON.stringify(eval('state').library.custom)));
  for (const type of Object.keys(importedProperties)) {
    expect(edited[typeIds[type]], `edited ${type}`).toMatchObject({ ...expectedCore(type), ...expectedProperties(type) });
    expect(edited[typeIds[type]].created).toBe(created);
    expect(edited[typeIds[type]].modified > modified, `modified timestamp for ${type}`).toBe(true);
  }

  // 3. Real STIX download.
  const download = await downloadStixBundle(page);
  const exportedObjects = sortedObjects(download.bundle);
  expect(exportedObjects).toHaveLength(Object.keys(importedProperties).length);
  for (const type of Object.keys(importedProperties)) {
    const object = exportedObjects.find((candidate: any) => candidate.id === typeIds[type]);
    const properties = expectedProperties(type);
    expect(object, `exported ${type}`).toEqual({
      type,
      spec_version: '2.1',
      id: typeIds[type],
      created,
      modified: edited[typeIds[type]].modified,
      ...expectedCore(type),
      ...properties,
    });
  }

  // 4. Re-import the downloaded bytes in a fresh browser context with empty state.
  const freshContext = await browser.newContext({
    baseURL: new URL(page.url()).origin, acceptDownloads: true, serviceWorkers: 'block',
  });
  try {
    const freshPage = await freshContext.newPage();
    await openApp(freshPage);
    expect(await freshPage.evaluate(() => Object.keys(eval('state').library.custom).length)).toBe(0);

    await importBundleFile(freshPage, download.name, download.buffer);
    const reimported = await freshPage.evaluate(() => JSON.parse(JSON.stringify(eval('state').library.custom)));
    for (const type of Object.keys(importedProperties)) {
      const entry = reimported[typeIds[type]];
      expect(entry, `re-imported ${type}`).toMatchObject({
        id: typeIds[type],
        stixType: type,
        created,
        modified: edited[typeIds[type]].modified,
        ...expectedCore(type),
        ...expectedProperties(type),
      });
      for (const [key, value] of Object.entries(editedProperties[type] || {})) {
        if (value === null) expect(entry, `cleared ${type}.${key}`).not.toHaveProperty(key);
      }
    }

    // The re-imported editor still renders the final values, and a second download is identical.
    await freshPage.evaluate(id => (window as any).openStixEditor(id), typeIds.indicator);
    await expect(freshPage.locator('#stix-edit-pattern')).toHaveValue(expectedProperties('indicator').pattern as string);
    await expect(freshPage.locator('#stix-edit-name')).toHaveValue(expectedCore('indicator').name);
    await freshPage.evaluate(() => (window as any).closeStixEditor());

    const second = await downloadStixBundle(freshPage);
    expect(sortedObjects(second.bundle)).toEqual(exportedObjects);
    await expect(freshPage.locator('[data-rt-injected]')).toHaveCount(0);
    expect(await freshPage.evaluate(() => (window as any).__rtExecuted)).toBe(false);
    expectNoExternalRequests(freshPage);
  } finally {
    await freshContext.close();
  }
});

// ---------------------------------------------------------------------------
// RT-06 supplements for the round-trip suite.
//
// Added here rather than in a new spec because both depend on this file's all-type
// coverage: one pins the projected/unsupported split for every configured descriptor so a
// new field type cannot be added without a contract decision, and the other reaches the
// STIX editor through a real card click, since the lifecycle above calls openStixEditor()
// directly and so never exercises the card entry point.
//
// Additive only: the all-type lifecycle above is unchanged.
// ---------------------------------------------------------------------------

test('every configured descriptor is classified as projected or explicitly unsupported', async ({ page }) => {
  await openApp(page);
  const fieldTypes = await readFieldTypes(page);

  // Hand-authored from buildSTIXBundle(): the shapes the export projection handles.
  const PROJECTED = new Set([
    'string', 'text', 'enum', 'open-vocab', 'timestamp', 'identifier',
    'boolean', 'integer', 'list', 'list:open-vocab',
  ]);
  // Hand-authored: structured shapes the main editor stores but export never emits.
  const UNSUPPORTED = new Set(['kill-chain-phases', 'external-references']);

  const unsupported: string[] = [];
  let projectedCount = 0;
  for (const [type, fields] of Object.entries(fieldTypes)) {
    for (const [key, fieldType] of Object.entries(fields)) {
      if (PROJECTED.has(fieldType)) { projectedCount += 1; continue; }
      // A descriptor that is neither projected nor a known structured shape means a new
      // field type was added without a manifest decision. Fail rather than ignore it.
      expect(UNSUPPORTED.has(fieldType), `unclassified descriptor ${type}.${key}: ${fieldType}`).toBe(true);
      unsupported.push(`${type}.${key}`);
    }
  }

  // Pinned counts so an added type or field forces a contract review.
  expect(Object.keys(fieldTypes)).toHaveLength(19);
  expect(projectedCount).toBe(122);
  expect(unsupported.sort()).toEqual([
    'attack-pattern.external_references', 'attack-pattern.kill_chain_phases',
    'indicator.kill_chain_phases', 'infrastructure.kill_chain_phases',
    'malware.kill_chain_phases', 'tool.kill_chain_phases', 'vulnerability.external_references',
  ]);
});

test('a real card click opens the STIX editor with the restored values', async ({ page }) => {
  await openApp(page);

  // Assign a custom object to a phase so a real card exists to click.
  const id = 'malware--abababab-abab-4bab-8bab-abababababab';
  await page.locator('#import-killchain-input').setInputFiles({
    name: 'rt-06-card.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify({
      assignments: {
        'IN:reconnaissance': {
          techniques: [], capecs: [], cwes: [],
          customItems: [{ id, instanceId: 'itm-card-1', type: 'custom', metadata: {} }],
          groups: [], layout: [],
        },
      },
      customLibrary: {
        [id]: {
          id, stixType: 'malware', name: 'Card "malware" <x>',
          description: 'Opened by clicking the card',
          labels: ['card-label'], is_family: false,
        },
      },
    }), 'utf8'),
  });
  await expect(page.locator('#toast')).toHaveText('Imported kill chain');

  // The existing lifecycle calls openStixEditor() directly; this drives the card button.
  const card = page.locator(`[draggable="true"]:has(.tag-action-btn.edit[onclick*="'itm-card-1'"])`);
  await expect(card).toHaveCount(1);
  await card.hover();
  await card.locator('.tag-action-btn.edit').click();

  await expect(page.locator('#edit-stix-modal')).toHaveClass(/visible/);
  await expect(page.locator('#stix-edit-name')).toHaveValue('Card "malware" <x>');
  await expect(page.locator('#stix-edit-description')).toHaveValue('Opened by clicking the card');
  await expect(page.locator('#stix-edit-labels')).toHaveValue('card-label');
  await expect(page.locator('#stix-edit-is_family')).not.toBeChecked();

  // Saving from a card-opened editor commits to the same library entry.
  await page.locator('#stix-edit-name').fill('Edited from the card');
  await page.locator('.btn-stix-save').click();
  await expect(page.locator('#toast')).toHaveText('STIX item updated');
  expect(await page.evaluate(k => eval('state').library.custom[k].name, id)).toBe('Edited from the card');

  await expect(page.locator('[data-rt-injected]')).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).__rtExecuted)).toBe(false);
});
