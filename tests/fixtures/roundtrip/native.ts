// Synthetic native kill-chain fixtures and their INDEPENDENT expected post-import state.
//
// Oracle rule: every expectation below is hand-authored from the contract the app is
// supposed to honour. Nothing here calls a production sanitizer, imports index.html, or
// derives an expected value from observed output.
//
// That independence is the whole point. An expectation computed by the same code it is
// meant to check would agree with any behavior, including a broken one, so the suite
// would re-derive defects instead of detecting them. When a value here and the app
// disagree, read the source and resolve it deliberately: either the app has a defect, or
// the transform is intended and this file gains a comment recording it. Never relax an
// assertion to make a run green.
//
// Analyst evidence is synthetic. Payload-shaped strings are inert render probes.

export const IDS = {
  identity: 'identity--11111111-1111-4111-8111-111111111111',
  malware: 'malware--22222222-2222-4222-8222-222222222222',
  indicator: 'indicator--33333333-3333-4333-8333-333333333333',
  tool: 'tool--44444444-4444-4444-8444-444444444444',
};

export const VECTOR_31 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
export const VECTOR_40 = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
// CVSS 2.0 is outside CVSS_VECTOR_PATTERNS (3.0, 3.1 and 4.0 only) and must normalize away.
export const VECTOR_20_REJECTED = 'AV:N/AC:L/Au:N/C:P/I:P/A:P';

// Printable evidence that must survive verbatim. Output encoding happens at the render
// sink, so preservation and inert rendering are separate assertions, never traded off.
export const EVIDENCE_LINES = [
  'Analyst evidence "quoted" & \'apostrophe\'',
  '[brackets] {braces}; `backticks` -- repeated hyphens \\backslash',
  'Angle <tags> & literal &amp; entity',
  'Non-ASCII: Ubungen uber Straße, naive cafe, Ελληνικά, 日本語',
  'Supplementary: \u{1F512}\u{1D400}',
  '</textarea><img data-rt-injected src=x onerror="window.__rtExecuted=true">',
];

// CONTRACT (verified in index.html): InputSecurity.normalize() strips U+0000-U+001F and
// U+007F, and both trust boundaries use it -- sanitizeForStorage() on the metadata
// textarea commit and sanitizeImportedString() on import. Newlines are therefore removed
// with no replacement separator, so comments are effectively single-line app-wide.
// The behavior is symmetric, so it is a preserved contract here, not a round-trip loss.
export const EVIDENCE_INPUT = EVIDENCE_LINES.join('\n');
export const EVIDENCE_STORED = EVIDENCE_LINES.join('');

// sanitizeImportedString also trims, so values are authored without leading or trailing
// whitespace unless a test is specifically asserting the documented trim.
export const TITLE = 'RT-02 Full "Native" [doc]; <title> & --chain';
export const DESCRIPTION_INPUT = `Round-trip description.\n${EVIDENCE_INPUT}`;
export const DESCRIPTION_STORED = `Round-trip description.${EVIDENCE_STORED}`;

// CONTRACT: InputSecurity.validators.url is /^https?:\/\/[^\s<>"{}|\\^`\[\]]+$/, so a URL
// containing raw brackets or braces is rejected and its whole hyperlink entry is dropped.
export const URL_BRACKETS_REJECTED = 'https://example.test/a?q=1&r=[2]';

export const ALL_OBSERVABLE_TYPES = [
  'ipv4-addr', 'ipv6-addr', 'domain-name', 'url', 'file-hash-md5', 'file-hash-sha1',
  'file-hash-sha256', 'file-name', 'email-addr', 'threat-actor', 'other',
] as const;

export const ALL_SCORES = ['unclassified', 'low', 'medium', 'high', 'critical'] as const;

function observables() {
  return ALL_OBSERVABLE_TYPES.map((type, index) => ({ type, value: `obs-${index}-${type} "v"` }));
}

/** Hand-authored default metadata, as documented for an assignment carrying none. */
export function defaultMeta() {
  return {
    score: 'unclassified', confidence: null, comments: '',
    cveEntries: [], cveId: '', cveIds: [], hyperlinks: [], observables: [],
  };
}

/** Hand-authored expected metadata: documented defaults plus only the fields that survive. */
export function expectMeta(overrides: Record<string, unknown> = {}) {
  const meta: Record<string, unknown> = { ...defaultMeta(), ...overrides };
  const entries = (meta.cveEntries as any[]) || [];
  meta.cveIds = entries.map(entry => entry.id);
  meta.cveId = entries.length ? entries[0].id : '';
  return meta;
}

type Item = { id: string; instanceId: string; type?: string; metadata?: unknown };

function item(id: string, instanceId: string, metadata?: unknown, type?: string): Item {
  const value: Item = { id, instanceId };
  if (type) value.type = type;
  if (metadata !== undefined) value.metadata = metadata;
  return value;
}

function emptyPhase() {
  return { techniques: [], capecs: [], cwes: [], customItems: [], groups: [], layout: [] };
}

// ---------------------------------------------------------------------------
// RT-02 full native document
// ---------------------------------------------------------------------------

export const FULL_PHASES = {
  recon: 'IN:reconnaissance',
  exploitation: 'IN:exploitation',
  lateral: 'THROUGH:lateral-movement',
  exfiltration: 'OUT:exfiltration',
};

export const GROUPS = { mixed: 'grp-rt-mixed', empty: 'grp-rt-empty', dup: 'grp-rt-dup' };

/** Input metadata for the richest assignment: every supported field populated. */
function richInputMeta() {
  return {
    score: 'critical',
    confidence: 100,
    comments: EVIDENCE_INPUT,
    cveEntries: [
      { id: 'cve-2026-10001', score: '9.8', vector: VECTOR_31 },
      { id: 'CVE-2026-10002', score: 4, vector: VECTOR_40 },
      { id: 'CVE-2026-10003', score: null, vector: VECTOR_20_REJECTED },
    ],
    hyperlinks: [
      { label: 'Primary "source" [1]', url: 'https://example.test/a?q=1&r=2' },
      { label: 'Rejected brackets', url: URL_BRACKETS_REJECTED },
      { label: 'Secondary', url: 'http://example.test/b' },
      { label: 'Blocked scheme', url: 'javascript:window.__rtExecuted=true' },
      { label: 'Blocked data', url: 'data:text/html,<script>window.__rtExecuted=true</script>' },
    ],
    observables: observables(),
  };
}

/** Hand-authored expectation for richInputMeta(). */
function richExpectedMeta() {
  return expectMeta({
    score: 'critical',
    confidence: 100,
    comments: EVIDENCE_STORED,
    // ids uppercase and trim; score coerces to a 0-10 number rounded to one decimal;
    // an unsupported vector version normalizes to an empty string but keeps its entry.
    cveEntries: [
      { id: 'CVE-2026-10001', score: 9.8, vector: VECTOR_31 },
      { id: 'CVE-2026-10002', score: 4, vector: VECTOR_40 },
      { id: 'CVE-2026-10003', score: null, vector: '' },
    ],
    // Only URLs passing the http(s) allowlist survive. The bracketed entry is dropped
    // whole; the order of the surviving entries is preserved.
    hyperlinks: [
      { label: 'Primary "source" [1]', url: 'https://example.test/a?q=1&r=2' },
      { label: 'Secondary', url: 'http://example.test/b' },
    ],
    observables: observables(),
  });
}

export function nativeFull() {
  const phases: Record<string, any> = {};
  for (const phase of [
    'IN:reconnaissance', 'IN:resource-development', 'IN:delivery', 'IN:social-engineering',
    'IN:exploitation', 'IN:persistence', 'IN:defense-evasion', 'IN:command-control',
    'THROUGH:pivoting', 'THROUGH:discovery', 'THROUGH:privilege-escalation', 'THROUGH:execution',
    'THROUGH:credential-access', 'THROUGH:lateral-movement',
    'OUT:collection', 'OUT:exfiltration', 'OUT:impact', 'OUT:objectives',
  ]) phases[phase] = emptyPhase();

  phases[FULL_PHASES.recon] = {
    techniques: [item('T1595', 'itm-rt-001', richInputMeta(), 'attack')],
    // No metadata at all: must acquire documented defaults, not vanish.
    capecs: [item('CAPEC-169', 'itm-rt-002')],
    cwes: [],
    customItems: [item(IDS.identity, 'itm-rt-003', { score: 'low', confidence: 0 }, 'custom')],
    groups: [
      {
        groupId: GROUPS.mixed, label: 'Mixed "group" <1>', collapsed: true,
        items: [
          item('T1059.001', 'itm-rt-004', { score: 'medium', comments: 'Subtechnique evidence' }, 'attack'),
          item(IDS.malware, 'itm-rt-005', { score: 'high' }, 'custom'),
          item('CWE-79', 'itm-rt-006', { score: 'unclassified', confidence: 50 }, 'cwe'),
        ],
      },
      { groupId: GROUPS.empty, label: 'Empty group', collapsed: false, items: [] },
    ],
    // Explicit interleaved order: groups and items alternate and must survive verbatim.
    layout: [
      { kind: 'item', type: 'capec', instanceId: 'itm-rt-002' },
      { kind: 'group', groupId: GROUPS.mixed },
      { kind: 'item', type: 'attack', instanceId: 'itm-rt-001' },
      { kind: 'group', groupId: GROUPS.empty },
      { kind: 'item', type: 'custom', instanceId: 'itm-rt-003' },
    ],
  };

  // Same entity twice in one phase plus once in another phase: three distinct instances.
  phases[FULL_PHASES.exploitation] = {
    ...emptyPhase(),
    techniques: [
      item('T1595', 'itm-rt-010', { score: 'high', comments: 'First exploitation instance' }, 'attack'),
      item('T1595', 'itm-rt-011', { score: 'low', comments: 'Second exploitation instance' }, 'attack'),
    ],
    layout: [],  // absent order: the importer must append, not drop.
  };

  phases[FULL_PHASES.lateral] = {
    ...emptyPhase(),
    customItems: [item(IDS.indicator, 'itm-rt-020', { score: 'critical' }, 'custom')],
    groups: [{
      groupId: GROUPS.dup, label: 'Repeat group', collapsed: false,
      // Same custom entity as itm-rt-003 in another phase, grouped, distinct instance.
      items: [item(IDS.identity, 'itm-rt-021', { score: 'medium', comments: 'Grouped repeat' }, 'custom')],
    }],
    layout: [
      { kind: 'group', groupId: GROUPS.dup },
      { kind: 'item', type: 'custom', instanceId: 'itm-rt-020' },
    ],
  };

  phases[FULL_PHASES.exfiltration] = {
    ...emptyPhase(),
    techniques: [item('T1041', 'itm-rt-030', {
      score: 'medium',
      // Legacy single-CVE representation plus a legacy vector alongside it.
      cveId: 'cve-2026-20001',
      cvssVector: VECTOR_31,
      comments: 'Exfiltration evidence\nwith an embedded newline',  // newline is stripped, not replaced
    }, 'attack')],
    layout: [],
  };

  return {
    version: '2.9.3',
    schema: 'killchain-export-lite',
    exportedAt: '2026-09-20T00:00:00.000Z',
    title: TITLE,
    description: DESCRIPTION_INPUT,
    view: 'killchain',
    activeTab: 'capec',
    filters: { attack: 'enterprise', capec: 'all', cwe: 'all', custom: 'all' },
    layers: { attack: true, capec: false, cwe: true, custom: true },
    hideEmpty: false,
    assignments: phases,
    selection: { type: 'attack', id: 'T1595' },
    customLibrary: {
      [IDS.identity]: {
        id: IDS.identity, stixType: 'identity', name: 'RT Identity "org"',
        description: 'Identity description & <x>', labels: ['rt-label', 'second--label'],
        identity_class: 'organization', created: '2026-01-01T00:00:00.000Z',
        modified: '2026-01-02T00:00:00.000Z',
      },
      [IDS.malware]: {
        id: IDS.malware, stixType: 'malware', name: 'RT Malware',
        description: '', labels: [],
        is_family: false,  // false must survive as false, not be dropped as falsy.
        created: '2026-01-03T00:00:00.000Z', modified: '2026-01-04T00:00:00.000Z',
      },
      [IDS.indicator]: {
        id: IDS.indicator, stixType: 'indicator', name: 'RT Indicator',
        description: 'Indicator description', labels: ['ioc'],
        pattern: "[file:name = 'a\\\\b.exe' AND file:size > 10] OR [domain-name:value = 'a--b.test']",
        pattern_type: 'stix', valid_from: '2026-02-01T00:00:00.000Z',
        created: '2026-01-05T00:00:00.000Z', modified: '2026-01-06T00:00:00.000Z',
      },
      // Library entry with no assignment anywhere: must survive the round trip.
      [IDS.tool]: {
        id: IDS.tool, stixType: 'tool', name: 'RT Unassigned Tool',
        description: 'Never assigned to a phase', labels: [],
        created: '2026-01-07T00:00:00.000Z', modified: '2026-01-08T00:00:00.000Z',
      },
    },
  };
}

/**
 * Hand-authored expected assignments after import of nativeFull().
 * Ungrouped entries carry no `type` (documented normalization); grouped entries keep it.
 */
export function expectedFullAssignments() {
  const phases: Record<string, any> = {};
  for (const phase of [
    'IN:reconnaissance', 'IN:resource-development', 'IN:delivery', 'IN:social-engineering',
    'IN:exploitation', 'IN:persistence', 'IN:defense-evasion', 'IN:command-control',
    'THROUGH:pivoting', 'THROUGH:discovery', 'THROUGH:privilege-escalation', 'THROUGH:execution',
    'THROUGH:credential-access', 'THROUGH:lateral-movement',
    'OUT:collection', 'OUT:exfiltration', 'OUT:impact', 'OUT:objectives',
  ]) phases[phase] = emptyPhase();

  phases[FULL_PHASES.recon] = {
    techniques: [{ id: 'T1595', instanceId: 'itm-rt-001', metadata: richExpectedMeta() }],
    capecs: [{ id: 'CAPEC-169', instanceId: 'itm-rt-002', metadata: expectMeta() }],
    cwes: [],
    customItems: [{
      id: IDS.identity, instanceId: 'itm-rt-003',
      metadata: expectMeta({ score: 'low', confidence: 0 }),
    }],
    groups: [
      {
        groupId: GROUPS.mixed, label: 'Mixed "group" <1>', collapsed: true,
        items: [
          { id: 'T1059.001', instanceId: 'itm-rt-004', type: 'attack', metadata: expectMeta({ score: 'medium', comments: 'Subtechnique evidence' }) },
          { id: IDS.malware, instanceId: 'itm-rt-005', type: 'custom', metadata: expectMeta({ score: 'high' }) },
          { id: 'CWE-79', instanceId: 'itm-rt-006', type: 'cwe', metadata: expectMeta({ score: 'unclassified', confidence: 50 }) },
        ],
      },
      { groupId: GROUPS.empty, label: 'Empty group', collapsed: false, items: [] },
    ],
    layout: [
      { kind: 'item', type: 'capec', instanceId: 'itm-rt-002' },
      { kind: 'group', groupId: GROUPS.mixed },
      { kind: 'item', type: 'attack', instanceId: 'itm-rt-001' },
      { kind: 'group', groupId: GROUPS.empty },
      { kind: 'item', type: 'custom', instanceId: 'itm-rt-003' },
    ],
  };

  phases[FULL_PHASES.exploitation] = {
    ...emptyPhase(),
    techniques: [
      { id: 'T1595', instanceId: 'itm-rt-010', metadata: expectMeta({ score: 'high', comments: 'First exploitation instance' }) },
      { id: 'T1595', instanceId: 'itm-rt-011', metadata: expectMeta({ score: 'low', comments: 'Second exploitation instance' }) },
    ],
    // Absent input order: entries are appended per entity type in list order.
    layout: [
      { kind: 'item', type: 'attack', instanceId: 'itm-rt-010' },
      { kind: 'item', type: 'attack', instanceId: 'itm-rt-011' },
    ],
  };

  phases[FULL_PHASES.lateral] = {
    ...emptyPhase(),
    customItems: [{ id: IDS.indicator, instanceId: 'itm-rt-020', metadata: expectMeta({ score: 'critical' }) }],
    groups: [{
      groupId: GROUPS.dup, label: 'Repeat group', collapsed: false,
      items: [{ id: IDS.identity, instanceId: 'itm-rt-021', type: 'custom', metadata: expectMeta({ score: 'medium', comments: 'Grouped repeat' }) }],
    }],
    layout: [
      { kind: 'group', groupId: GROUPS.dup },
      { kind: 'item', type: 'custom', instanceId: 'itm-rt-020' },
    ],
  };

  phases[FULL_PHASES.exfiltration] = {
    ...emptyPhase(),
    techniques: [{
      id: 'T1041', instanceId: 'itm-rt-030',
      // Legacy cveId + cvssVector are promoted into one cveEntry with a null score.
      metadata: expectMeta({
        score: 'medium',
        comments: 'Exfiltration evidencewith an embedded newline',
        cveEntries: [{ id: 'CVE-2026-20001', score: null, vector: VECTOR_31 }],
      }),
    }],
    layout: [{ kind: 'item', type: 'attack', instanceId: 'itm-rt-030' }],
  };

  return phases;
}

/**
 * Hand-authored expected custom library after import. sanitizeImportedData always
 * emits name, description, labels and customTypeName, so entries that omitted
 * customTypeName gain an empty string. Supported spec fields are preserved.
 */
export function expectedFullLibrary() {
  const source = nativeFull().customLibrary as Record<string, any>;
  const expected: Record<string, any> = {};
  for (const [id, entry] of Object.entries(source)) {
    expected[id] = {
      id: entry.id, stixType: entry.stixType, name: entry.name,
      description: entry.description ?? '', labels: entry.labels ?? [],
      customTypeName: '',
      created: entry.created, modified: entry.modified,
    };
    for (const key of ['identity_class', 'is_family', 'pattern', 'pattern_type', 'valid_from']) {
      if (Object.prototype.hasOwnProperty.call(entry, key)) expected[id][key] = entry[key];
    }
  }
  return expected;
}

// ---------------------------------------------------------------------------
// RT-01 minimal document
// ---------------------------------------------------------------------------

export function nativeMinimal() {
  return { schema: 'killchain-export-lite', assignments: { 'IN:reconnaissance': { techniques: [] } } };
}

// ---------------------------------------------------------------------------
// RT-15 legacy inputs
// ---------------------------------------------------------------------------

/** Legacy shapes: bare string assignments, flat metadata, and legacy CVE keys. */
export function nativeLegacy() {
  return {
    version: '2.4.2',
    assignments: {
      'IN:reconnaissance': {
        // Flat metadata (no metadata wrapper) is read directly off the assignment.
        techniques: [{ id: 'T1595', score: 'high', confidence: 71, comments: 'Flat legacy metadata', cve: 'cve-2026-30001', cvss: VECTOR_31 }],
        capecs: [],
        cwes: [{ id: 'CWE-79', metadata: { cveIds: 'CVE-2026-30002 CVE-2026-30003' } }],
      },
    },
  };
}

export function expectedLegacyRecon() {
  return {
    techniques: [{
      id: 'T1595',
      metadata: expectMeta({
        score: 'high', confidence: 71, comments: 'Flat legacy metadata',
        cveEntries: [{ id: 'CVE-2026-30001', score: null, vector: VECTOR_31 }],
      }),
    }],
    capecs: [],
    cwes: [{
      id: 'CWE-79',
      // A whitespace-delimited legacy string splits into separate entries.
      metadata: expectMeta({
        cveEntries: [
          { id: 'CVE-2026-30002', score: null, vector: '' },
          { id: 'CVE-2026-30003', score: null, vector: '' },
        ],
      }),
    }],
    customItems: [],
    groups: [],
  };
}
