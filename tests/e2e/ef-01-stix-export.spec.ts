import fs from 'node:fs';
import { expect, test, type Page } from '@playwright/test';

const created = '2026-01-01T00:00:00.000Z';
const modified = '2026-01-02T00:00:00.000Z';

// Explicitly reviewed against stix-config.js. Core name/description/labels are
// exercised separately. Structured kill-chain-phases and external-references,
// common STIX properties, and the UI-only customTypeName are intentionally excluded.
const supportedProperties: Record<string, Record<string, unknown>> = {
  'attack-pattern': {
    aliases: ['Spear "Alias"', 'APT--Pattern'],
  },
  campaign: {
    aliases: ['Campaign Alias'],
    first_seen: '2025-01-01T00:00:00.000Z',
    last_seen: '2025-02-01T00:00:00.000Z',
    objective: 'Collect {records}; retain punctuation.',
  },
  'course-of-action': {},
  grouping: {
    context: 'suspicious-activity',
    object_refs: ['indicator--11111111-1111-4111-8111-111111111111'],
  },
  identity: {
    roles: ['incident responder'],
    identity_class: 'organization',
    sectors: ['technology'],
    contact_information: 'soc@example.test; ext. 7',
  },
  indicator: {
    pattern: "[domain-name:value = 'a--b.example']",
    pattern_type: 'stix',
    valid_from: '2026-03-01T00:00:00.000Z',
    indicator_types: ['malicious-activity'],
    valid_until: '2026-04-01T00:00:00.000Z',
    pattern_version: '2.1',
  },
  infrastructure: {
    infrastructure_types: ['command-and-control'],
    aliases: ['Relay--01'],
    first_seen: '2025-03-01T00:00:00.000Z',
    last_seen: '2025-04-01T00:00:00.000Z',
  },
  'intrusion-set': {
    aliases: ['The "Dukes"'],
    first_seen: '2024-01-01T00:00:00.000Z',
    last_seen: '2025-01-01T00:00:00.000Z',
    goals: ['Collect [research]', 'Maintain access'],
    resource_level: 'organization',
    primary_motivation: 'organizational-gain',
    secondary_motivations: ['dominance'],
  },
  location: {
    latitude: '52.5200',
    longitude: '13.4050',
    precision: '10.5',
    region: 'western-europe',
    country: 'DE',
    administrative_area: 'Berlin',
    city: 'Berlin',
    street_address: 'Example Str. 1; Building B',
    postal_code: '10115',
  },
  malware: {
    is_family: false,
    malware_types: ['ransomware'],
    aliases: ['Sample--Family'],
    first_seen: '2025-05-01T00:00:00.000Z',
    last_seen: '2025-06-01T00:00:00.000Z',
    operating_system_refs: ['software--22222222-2222-4222-8222-222222222222'],
    architecture_execution_envs: ['x86-64'],
    implementation_languages: ['c++'],
    capabilities: ['anti-debugging'],
    sample_refs: ['file--33333333-3333-4333-8333-333333333333'],
  },
  'malware-analysis': {
    product: 'Sandbox--X',
    result: 'malicious',
    version: '1.2.3',
    host_vm_ref: 'software--44444444-4444-4444-8444-444444444444',
    operating_system_ref: 'software--55555555-5555-4555-8555-555555555555',
    installed_software_refs: ['software--66666666-6666-4666-8666-666666666666'],
    configuration_version: 'config{7}',
    modules: ['static', 'dynamic'],
    analysis_engine_version: 'engine;4',
    analysis_definition_version: 'defs[9]',
    submitted: '2026-05-01T00:00:00.000Z',
    analysis_started: '2026-05-01T00:01:00.000Z',
    analysis_ended: '2026-05-01T00:02:00.000Z',
    result_name: 'Family "A"',
    sample_ref: 'malware--77777777-7777-4777-8777-777777777777',
  },
  note: {
    content: 'Analyst note: preserve [brackets], {braces}; and `ticks`.',
    abstract: 'Short -- summary',
    authors: ['Analyst "One"'],
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
    explanation: 'Corroborated by source "A"; confidence remains bounded.',
    authors: ['Reviewer--2'],
    object_refs: ['report--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'],
  },
  report: {
    published: '2026-07-01T00:00:00.000Z',
    report_types: ['threat-report'],
    object_refs: ['malware--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'],
  },
  'threat-actor': {
    threat_actor_types: ['crime-syndicate'],
    aliases: ['Actor--A'],
    first_seen: '2024-02-01T00:00:00.000Z',
    last_seen: '2026-02-01T00:00:00.000Z',
    roles: ['agent'],
    goals: ['Access {restricted} data'],
    sophistication: 'advanced',
    resource_level: 'organization',
    primary_motivation: 'personal-gain',
    secondary_motivations: ['coercion'],
    personal_motivations: ['notoriety'],
  },
  tool: {
    tool_types: ['remote-access'],
    aliases: ['Admin--Tool'],
    tool_version: '5.0;beta',
  },
  vulnerability: {},
  'x-custom': {},
};

const structuredProperties: Record<string, Record<string, unknown>> = {
  'attack-pattern': {
    kill_chain_phases: [{ kill_chain_name: 'test', phase_name: 'execution' }],
    external_references: [{ source_name: 'test', url: 'https://example.test/ref' }],
  },
  indicator: {
    kill_chain_phases: [{ kill_chain_name: 'test', phase_name: 'delivery' }],
  },
  infrastructure: {
    kill_chain_phases: [{ kill_chain_name: 'test', phase_name: 'command-and-control' }],
  },
  malware: {
    kill_chain_phases: [{ kill_chain_name: 'test', phase_name: 'execution' }],
  },
  tool: {
    kill_chain_phases: [{ kill_chain_name: 'test', phase_name: 'actions-on-objectives' }],
  },
  vulnerability: {
    external_references: [{ source_name: 'cve', external_id: 'CVE-2026-0001' }],
  },
};

async function openApp(page: Page) {
  await page.route('**/*', route => {
    const url = new URL(route.request().url());
    return url.hostname === '127.0.0.1' ? route.continue() : route.abort();
  });
  await page.goto('/index.html');
  await expect(page.locator('#loading')).toHaveClass(/hidden/, { timeout: 60_000 });
}

async function seedMatrix(page: Page) {
  return page.evaluate(({ matrix, structured, created, modified }) => {
    const appState = eval('state');
    const custom: Record<string, any> = Object.create(null);
    const ids: Record<string, string> = {};
    Object.entries(matrix).forEach(([type, properties], index) => {
      const first = String(index + 1).padStart(8, '0');
      const tail = String(index + 1).padStart(12, '0');
      const id = `${type}--${first}-1111-4111-8111-${tail}`;
      ids[type] = id;
      custom[id] = {
        id,
        stixType: type,
        name: `Name for ${type}`,
        description: `Description for ${type}`,
        labels: [`label-${type}`, 'evidence--label'],
        created,
        modified,
        ...properties,
        ...(structured[type] || {}),
        customTypeName: 'UI-only subtype',
        uiMetadata: { selected: true },
        arbitraryInternalField: 'must not export',
        revoked: true,
        confidence: 99,
        created_by_ref: 'identity--cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      };
    });
    appState.library.custom = custom;
    for (const phase of Object.values(appState.assignments) as any[]) {
      phase.techniques = [];
      phase.capecs = [];
      phase.cwes = [];
      phase.customItems = [];
      phase.groups = [];
      phase.layout = [];
    }
    return ids;
  }, { matrix: supportedProperties, structured: structuredProperties, created, modified });
}

async function readJsonDownload(page: Page, functionName: 'exportJSON' | 'exportSTIXBundle') {
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.evaluate(name => (window as any)[name](), functionName),
  ]);
  const downloadPath = await download.path();
  expect(downloadPath).not.toBeNull();
  return JSON.parse(fs.readFileSync(downloadPath!, 'utf8'));
}

test.beforeEach(async ({ page }) => {
  await openApp(page);
});

test('projects every configured type through the explicit supported-property matrix', async ({ page }) => {
  const ids = await seedMatrix(page);
  const result = await page.evaluate(() => {
    const appState = eval('state');
    const before = JSON.stringify(appState.library.custom);
    const bundle = (window as any).buildSTIXBundle();
    const after = JSON.stringify(appState.library.custom);
    return {
      configuredTypes: eval('CONFIG').stixTypes.map((entry: any) => entry.value).sort(),
      descriptorTypes: Object.keys(eval('STIX_OBJECTS')).sort(),
      before,
      after,
      objects: bundle.objects,
    };
  });

  expect(Object.keys(supportedProperties).sort()).toEqual(result.configuredTypes);
  expect(Object.keys(supportedProperties).sort()).toEqual(result.descriptorTypes);
  expect(result.after).toBe(result.before);

  for (const [type, properties] of Object.entries(supportedProperties)) {
    const object = result.objects.find((candidate: any) => candidate.id === ids[type]);
    expect(object).toBeDefined();
    expect(object).toMatchObject({
      type,
      spec_version: '2.1',
      id: ids[type],
      created,
      modified,
      name: `Name for ${type}`,
      description: `Description for ${type}`,
      labels: [`label-${type}`, 'evidence--label'],
      ...properties,
    });

    const expectedKeys = [
      'type', 'spec_version', 'id', 'created', 'modified', 'name', 'description', 'labels',
      ...Object.keys(properties),
    ].sort();
    expect(Object.keys(object).sort()).toEqual(expectedKeys);
  }

  const isolated = await page.evaluate(({ attackPatternId, malwareId }) => {
    const bundle = (window as any).buildSTIXBundle();
    bundle.objects.find((object: any) => object.id === attackPatternId).aliases.push('mutated');
    bundle.objects.find((object: any) => object.id === malwareId).labels.push('mutated');
    const custom = eval('state').library.custom;
    return {
      aliases: custom[attackPatternId].aliases,
      labels: custom[malwareId].labels,
      polluted: ({} as any).polluted,
    };
  }, { attackPatternId: ids['attack-pattern'], malwareId: ids.malware });
  expect(isolated.aliases).toEqual(supportedProperties['attack-pattern'].aliases);
  expect(isolated.labels).toEqual(['label-malware', 'evidence--label']);
  expect(isolated.polluted).toBeUndefined();
});

test('preserves integer zero while omitting explicitly absent supported values', async ({ page }) => {
  const result = await page.evaluate(({ created, modified }) => {
    const appState = eval('state');
    const observedId = 'observed-data--dddddddd-dddd-4ddd-8ddd-dddddddddddd';
    const identityId = 'identity--eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
    appState.library.custom = {
      [observedId]: {
        stixType: 'observed-data', name: 'Boundary value', created, modified,
        first_observed: created, last_observed: modified, number_observed: 0,
      },
      [identityId]: {
        stixType: 'identity', name: 'Absent values', created, modified,
        roles: [], identity_class: '', sectors: null, contact_information: undefined,
      },
    };
    const bundle = (window as any).buildSTIXBundle();
    return {
      observed: bundle.objects.find((object: any) => object.id === observedId),
      identity: bundle.objects.find((object: any) => object.id === identityId),
    };
  }, { created, modified });

  // Zero is a serializer boundary test; it is not claimed as a valid STIX observation count.
  expect(result.observed.number_observed).toBe(0);
  expect(result.identity).not.toHaveProperty('roles');
  expect(result.identity).not.toHaveProperty('identity_class');
  expect(result.identity).not.toHaveProperty('sectors');
  expect(result.identity).not.toHaveProperty('contact_information');
});

test('rejects populated supported fields with incompatible shapes', async ({ page }) => {
  const errors = await page.evaluate(({ created, modified }) => {
    const appState = eval('state');
    const cases = [
      { type: 'indicator', key: 'pattern', value: 7 },
      { type: 'malware', key: 'is_family', value: 'false' },
      { type: 'observed-data', key: 'number_observed', value: 1.5 },
      { type: 'observed-data', key: 'number_observed', value: Number.POSITIVE_INFINITY },
      { type: 'observed-data', key: 'number_observed', value: Number.NaN },
      { type: 'campaign', key: 'aliases', value: 'not-a-list' },
      { type: 'campaign', key: 'aliases', value: ['valid', 3] },
      { type: 'campaign', key: 'aliases', value: new Array(1) },
    ];
    return cases.map((entry, index) => {
      const id = `${entry.type}--f${String(index).padStart(7, '0')}-1111-4111-8111-f${String(index).padStart(11, '0')}`;
      appState.library.custom = {
        [id]: { stixType: entry.type, name: 'Invalid shape', created, modified, [entry.key]: entry.value },
      };
      try {
        (window as any).buildSTIXBundle();
        return '';
      } catch (error) {
        return error instanceof Error ? error.message : String(error);
      }
    });
  }, { created, modified });

  expect(errors).toEqual([
    'Cannot export STIX property "indicator.pattern": expected string.',
    'Cannot export STIX property "malware.is_family": expected boolean.',
    'Cannot export STIX property "observed-data.number_observed": expected finite integer.',
    'Cannot export STIX property "observed-data.number_observed": expected finite integer.',
    'Cannot export STIX property "observed-data.number_observed": expected finite integer.',
    'Cannot export STIX property "campaign.aliases": expected array of strings.',
    'Cannot export STIX property "campaign.aliases": expected array of strings.',
    'Cannot export STIX property "campaign.aliases": expected array of strings.',
  ]);
});

test('keeps inherited, poison, internal, and unknown-type fields out of the bundle', async ({ page }) => {
  const result = await page.evaluate(({ created, modified }) => {
    const appState = eval('state');
    const attackId = 'attack-pattern--12121212-1212-4212-8212-121212121212';
    const unknownId = 'x-unknown--13131313-1313-4313-8313-131313131313';
    const inherited = { aliases: ['inherited alias'] };
    const attack = Object.assign(Object.create(inherited), {
      stixType: 'attack-pattern', name: 'Own core fields', created, modified,
      arbitraryInternalField: 'private',
      constructor: 'poison',
      prototype: 'poison',
    });
    Object.defineProperty(attack, '__proto__', { value: 'poison', enumerable: true });
    const custom = Object.create(null);
    custom[attackId] = attack;
    custom[unknownId] = {
      stixType: 'x-unknown', name: 'Unknown custom type', created, modified,
      aliases: ['not configured'], objective: 'not configured', customTypeName: 'UI-only',
    };
    appState.library.custom = custom;
    const bundle = (window as any).buildSTIXBundle();
    return {
      attack: bundle.objects.find((object: any) => object.id === attackId),
      unknown: bundle.objects.find((object: any) => object.id === unknownId),
      polluted: ({} as any).polluted,
    };
  }, { created, modified });

  expect(Object.keys(result.attack).sort()).toEqual(
    ['type', 'spec_version', 'id', 'created', 'modified', 'name'].sort(),
  );
  expect(Object.keys(result.unknown).sort()).toEqual(
    ['type', 'spec_version', 'id', 'created', 'modified', 'name'].sort(),
  );
  expect(result.polluted).toBeUndefined();
});

test('actual STIX and JSON downloads carry the same supported values and full custom library', async ({ page }) => {
  const ids = await seedMatrix(page);
  const stateBefore = await page.evaluate(() => JSON.parse(JSON.stringify(eval('state').library.custom)));

  const stixDownload = await readJsonDownload(page, 'exportSTIXBundle');
  const jsonDownload = await readJsonDownload(page, 'exportJSON');

  expect(jsonDownload.customLibrary).toEqual(stateBefore);
  for (const [type, properties] of Object.entries(supportedProperties)) {
    const standalone = stixDownload.objects.find((object: any) => object.id === ids[type]);
    const embedded = jsonDownload.stixBundle.objects.find((object: any) => object.id === ids[type]);
    expect(standalone).toEqual(embedded);
    expect(standalone).toMatchObject(properties);
  }
  expect(await page.evaluate(() => JSON.parse(JSON.stringify(eval('state').library.custom)))).toEqual(stateBefore);
});

test('both download entry points report invalid fields and create no download', async ({ page }) => {
  const before = await page.evaluate(({ created, modified }) => {
    const appState = eval('state');
    const id = 'malware--14141414-1414-4414-8414-141414141414';
    appState.library.custom = {
      [id]: { stixType: 'malware', name: 'Wrong boolean', created, modified, is_family: 'false' },
    };
    return JSON.stringify(appState.library.custom);
  }, { created, modified });

  for (const functionName of ['exportSTIXBundle', 'exportJSON'] as const) {
    const downloadObserved = page.waitForEvent('download', { timeout: 500 })
      .then(() => true)
      .catch(() => false);
    await page.evaluate(name => (window as any)[name](), functionName);
    expect(await downloadObserved).toBe(false);
    await expect(page.locator('#toast')).toContainText('malware.is_family');
    await expect(page.locator('#toast')).toContainText('expected boolean');
  }

  expect(await page.evaluate(() => JSON.stringify(eval('state').library.custom))).toBe(before);
});

test('preserves representative relationship, ATT&CK, and mitigation generation', async ({ page }) => {
  const result = await page.evaluate(({ created, modified }) => {
    const appState = eval('state');
    for (const phase of Object.values(appState.assignments) as any[]) {
      phase.techniques = [];
      phase.capecs = [];
      phase.cwes = [];
      phase.customItems = [];
      phase.groups = [];
      phase.layout = [];
    }
    const malwareId = 'malware--15151515-1515-4515-8515-151515151515';
    const toolId = 'tool--16161616-1616-4616-8616-161616161616';
    appState.library.custom = {
      [malwareId]: { stixType: 'malware', name: 'Malware', created, modified, is_family: false },
      [toolId]: { stixType: 'tool', name: 'Tool', created, modified, tool_version: '1.0' },
    };
    appState.library.techniques.T1059 = {
      id: 'T1059',
      name: 'Command and Scripting Interpreter',
      description: 'Technique description',
      mitigations: [{ id: 'M1049', name: 'Antivirus/Antimalware', description: 'Mitigation description' }],
    };
    appState.assignments['IN:reconnaissance'].customItems = [{ id: malwareId }, { id: toolId }];
    appState.assignments['IN:reconnaissance'].techniques = [{ id: 'T1059' }];
    return {
      bundle: (window as any).buildSTIXBundle(),
      malwareId,
      toolId,
      techniqueId: (window as any).techniqueStixId('T1059'),
      mitigationId: (window as any).mitigationStixId('M1049'),
    };
  }, { created, modified });

  const objects = result.bundle.objects;
  expect(objects).toContainEqual(expect.objectContaining({
    type: 'relationship',
    relationship_type: 'related-to',
    source_ref: result.malwareId,
    target_ref: result.toolId,
    description: 'Co-located in phase IN:reconnaissance',
  }));
  expect(objects).toContainEqual(expect.objectContaining({
    type: 'attack-pattern',
    id: result.techniqueId,
    name: 'Command and Scripting Interpreter',
    external_references: [{
      source_name: 'mitre-attack',
      external_id: 'T1059',
      url: 'https://attack.mitre.org/techniques/T1059',
    }],
    kill_chain_phases: [{ kill_chain_name: 'unified-kill-chain', phase_name: 'reconnaissance' }],
  }));
  expect(objects).toContainEqual(expect.objectContaining({
    type: 'course-of-action',
    id: result.mitigationId,
    name: 'Antivirus/Antimalware',
  }));
  expect(objects).toContainEqual(expect.objectContaining({
    type: 'relationship',
    relationship_type: 'mitigates',
    source_ref: result.mitigationId,
    target_ref: result.techniqueId,
  }));
});

test('preserves punctuation-neutral supported fields through real kill-chain import and export', async ({ page }) => {
  const identityId = 'identity--17171717-1717-4717-8717-171717171717';
  const payload = {
    version: '2.9.3',
    schema: 'killchain-export-lite',
    assignments: {
      'IN:reconnaissance': {
        techniques: [], capecs: [], cwes: [], customItems: [], groups: [], layout: [],
      },
    },
    customLibrary: {
      [identityId]: {
        id: identityId,
        stixType: 'identity',
        name: 'Neutral Identity',
        description: 'Neutral description',
        roles: ['analyst'],
        identity_class: 'organization',
        sectors: ['technology'],
        contact_information: 'soc at example test',
      },
    },
  };

  await page.locator('#import-killchain-input').setInputFiles({
    name: 'ef-01-neutral-import.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(payload)),
  });
  await expect(page.locator('#toast')).toHaveText('Imported kill chain');

  const identity = await page.evaluate(id => {
    const bundle = (window as any).buildSTIXBundle();
    return bundle.objects.find((object: any) => object.id === id);
  }, identityId);
  expect(identity).toMatchObject({
    roles: ['analyst'],
    identity_class: 'organization',
    sectors: ['technology'],
    contact_information: 'soc at example test',
  });
});
