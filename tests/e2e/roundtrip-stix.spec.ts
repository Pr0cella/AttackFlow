// RT-07 embedded/standalone STIX parity and RT-08 generated STIX graph identity.
//
// RT-06 (all 19 configured types through the STIX editor) lives in
// ef-combined-stix-round-trip.spec.ts and is extended there rather than duplicated here.
//
// The generated graph is a PROJECTION, not a restoration: the main importer skips
// relationship, sighting and marking-definition objects, so equal object counts across a
// STIX round trip are never asserted as a universal rule.

import fs from 'node:fs';
import path from 'node:path';
import { expect, test, type Page } from '@playwright/test';
import {
  EXPORT_NAME, UUID, clickExportControl, exportNative, exportStix, expectBundleEnvelope,
  expectIsoTimestampWithin, expectNoDownload, expectNoExternalRequests, importNative,
  importNavigatorLayer, importStix, openApp, readState, withFreshContext,
} from './helpers/roundtrip';
import { IDS, nativeFull } from '../fixtures/roundtrip/native';

const bytes = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8');

const REPO_ROOT = path.resolve(__dirname, '../..');

// ABSOLUTE oracle for DERIVED objects.
//
// Every other check on the generated graph is relational: it compares one export against
// another export of the same builder. A field the projection drops is dropped identically
// in both, so it cancels out and no amount of comparing can see it -- mutation testing
// confirmed that removing the attack-pattern description left the whole suite green.
//
// The fix is a source of truth OUTSIDE the builder: the pinned framework resource the app
// itself loads. Expectations are read from that file, never from the bundle under test, so
// a projection that silently stops copying a field now disagrees with its own input.
const ATTACK_TECHNIQUES = JSON.parse(
  fs.readFileSync(path.join(REPO_ROOT, 'resources/attack-techniques.json'), 'utf8'),
);

function pinnedTechnique(techniqueId: string) {
  const record = ATTACK_TECHNIQUES[techniqueId];
  expect(record, `pinned resource must describe ${techniqueId}`).toBeDefined();
  expect(typeof record.name, `${techniqueId} name`).toBe('string');
  // A silently emptied resource would make every expectation below vacuous.
  expect(record.description.length, `${techniqueId} description must be non-empty`)
    .toBeGreaterThan(0);
  return record;
}

test.use({ serviceWorkers: 'block' });
test.afterEach(async ({ page }) => expectNoExternalRequests(page));

const byType = (bundle: any, type: string) => bundle.objects.filter((o: any) => o.type === type);
const edgeKey = (o: any) => `${o.relationship_type}|${o.source_ref}|${o.target_ref}`;

test.describe('RT-07 embedded and standalone STIX parity', () => {
  // LIMITATION, confirmed by mutation testing: this test compares two outputs of the same
  // builder, so a loss that affects BOTH equally is invisible here by construction.
  // Dropping a supported field from buildSTIXBundle() leaves this test green and is
  // caught instead by the independent per-object key-set oracle in
  // ef-combined-stix-round-trip.spec.ts. Parity and fidelity are separate guarantees.
  test('the embedded bundle matches a standalone export of the same unchanged state', async ({ page }) => {
    const startedAt = Date.now();
    await openApp(page);
    await importNative(page, bytes(nativeFull()), 'rt-07-parity.json');

    const native = await exportNative(page);
    const standalone = await exportStix(page);
    // Generated name: the bundle prefix appears once, with no title-derived slug.
    expect(standalone.name).toMatch(EXPORT_NAME.stix);

    const embedded = native.json.stixBundle;
    expect(embedded, 'a non-empty custom library must embed a bundle').toBeDefined();
    expectBundleEnvelope(embedded, 'embedded bundle');
    expectBundleEnvelope(standalone.json, 'standalone bundle');

    const libraryIds = new Set(Object.keys(native.json.customLibrary));
    const isDerived = (o: any) => !libraryIds.has(o.id);

    // Analyst-owned SDOs are compared WHOLE, supplied timestamps included. Blanket
    // timestamp stripping would hide a library object whose `created` was rewritten.
    const preserved = (bundle: any) => bundle.objects
      .filter((o: any) => libraryIds.has(o.id))
      .sort((x: any, y: any) => x.id.localeCompare(y.id));
    expect(preserved(standalone.json)).toEqual(preserved(embedded));
    expect(preserved(embedded).length).toBe(libraryIds.size);

    // Only regenerated objects lose their volatile fields, and only after both artifacts
    // have been validated.
    const normalizeDerived = (bundle: any) => bundle.objects
      .filter(isDerived)
      .map((o: any) => {
        const copy = { ...o };
        delete copy.created;
        delete copy.modified;
        if (copy.type === 'relationship') delete copy.id;
        return copy;
      })
      .sort((x: any, y: any) => JSON.stringify(x).localeCompare(JSON.stringify(y)));
    expect(normalizeDerived(standalone.json)).toEqual(normalizeDerived(embedded));

    expect(standalone.json.objects.length).toBe(embedded.objects.length);
    expect(standalone.json.id).not.toBe(embedded.id);
    for (const [label, bundle] of [['embedded', embedded], ['standalone', standalone.json]] as const) {
      for (const object of bundle.objects.filter(isDerived)) {
        expectIsoTimestampWithin(object.created, startedAt);
        expectIsoTimestampWithin(object.modified, startedAt);
      }
      expect(bundle.objects.filter(isDerived).length, `${label} derived count`).toBeGreaterThan(0);
    }

    // An unassigned library object still reaches both bundles.
    expect(standalone.json.objects.some((o: any) => o.id === IDS.tool)).toBe(true);
    expect(embedded.objects.some((o: any) => o.id === IDS.tool)).toBe(true);
  });

  test('an empty document offers no STIX export at all', async ({ page }) => {
    await openApp(page);
    await importNative(page, bytes({ assignments: { 'IN:reconnaissance': { techniques: [] } } }), 'rt-07-empty.json');

    // Same control path as a successful export, so an unwired menu item fails here too.
    await expectNoDownload(page, () => clickExportControl(page, 'STIX Bundle'));
    await expect(page.locator('#toast')).toHaveText('No STIX objects to export');
  });
});

test.describe('RT-08 generated STIX graph', () => {
  // A controlled graph: two custom objects co-located twice, a grouped pair, and one
  // technique with real mitigations from the pinned framework resources.
  const A = 'malware--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const B = 'identity--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const C = 'tool--cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const D = 'indicator--dddddddd-dddd-4ddd-8ddd-dddddddddddd';

  function graphFixture() {
    const custom = (id: string, n: number) => ({ id, instanceId: `itm-g-${n}`, type: 'custom', metadata: {} });
    return {
      assignments: {
        // A and B ungrouped together: one co-location edge.
        'IN:reconnaissance': {
          techniques: [{ id: 'T1059.001', instanceId: 'itm-g-t1' }],
          capecs: [], cwes: [],
          customItems: [custom(A, 1), custom(B, 2)],
          groups: [], layout: [],
        },
        // The same A/B pair co-located again in a second phase, plus a grouped C/D pair.
        'IN:exploitation': {
          techniques: [{ id: 'T1059.001', instanceId: 'itm-g-t2' }],
          capecs: [], cwes: [],
          customItems: [custom(A, 3), custom(B, 4)],
          groups: [{ groupId: 'grp-g-1', label: 'Grouped pair', items: [custom(C, 5), custom(D, 6)] }],
          layout: [],
        },
      },
      customLibrary: {
        [A]: { id: A, stixType: 'malware', name: 'Graph malware', is_family: false },
        [B]: { id: B, stixType: 'identity', name: 'Graph identity', identity_class: 'organization' },
        [C]: { id: C, stixType: 'tool', name: 'Graph tool' },
        [D]: { id: D, stixType: 'indicator', name: 'Graph indicator', pattern: "[file:name = 'g.exe']", pattern_type: 'stix' },
      },
    };
  }

  test('derives attack patterns, mitigations and co-location edges with resolvable endpoints', async ({ page }) => {
    const startedAt = Date.now();
    await openApp(page);
    await importNative(page, bytes(graphFixture()), 'rt-08-graph.json');
    const bundle = (await exportStix(page)).json;

    await test.step('every reference resolves and every id is unique', async () => {
      const ids = bundle.objects.map((o: any) => o.id);
      expect(new Set(ids).size, 'duplicate object ids in bundle').toBe(ids.length);
      const present = new Set(ids);
      for (const edge of byType(bundle, 'relationship')) {
        expect(present.has(edge.source_ref), `dangling source_ref ${edge.source_ref}`).toBe(true);
        expect(present.has(edge.target_ref), `dangling target_ref ${edge.target_ref}`).toBe(true);
      }
    });

    await test.step('one attack-pattern per technique, aggregating its phases', async () => {
      const patterns = byType(bundle, 'attack-pattern');
      // The technique is assigned in two phases but yields a single deterministic SDO.
      expect(patterns).toHaveLength(1);
      const pattern = patterns[0];
      expect(pattern.external_references).toEqual([{
        source_name: 'mitre-attack', external_id: 'T1059.001',
        url: 'https://attack.mitre.org/techniques/T1059/001',
      }]);
      expect(pattern.kill_chain_phases.map((p: any) => p.phase_name).sort())
        .toEqual(['exploitation', 'reconnaissance']);
      for (const phase of pattern.kill_chain_phases) {
        expect(phase.kill_chain_name).toBe('unified-kill-chain');
      }
      expectIsoTimestampWithin(pattern.created, startedAt);
      expectIsoTimestampWithin(pattern.modified, startedAt);

      // COMPLETE key set plus exact values against the pinned resource. Without this, a
      // dropped `description` is invisible to every relational check in the suite.
      const technique = pinnedTechnique('T1059.001');
      expect(Object.keys(pattern).sort(), 'derived attack-pattern key set').toEqual([
        'created', 'description', 'external_references', 'id', 'kill_chain_phases',
        'modified', 'name', 'spec_version', 'type',
      ]);
      expect(pattern.id).toMatch(new RegExp(`^attack-pattern--${UUID}$`));
      expect(pattern.spec_version).toBe('2.1');
      expect(pattern.name, 'name copied from the framework resource').toBe(technique.name);
      expect(pattern.description, 'description copied from the framework resource')
        .toBe(technique.description);
    });

    await test.step('mitigations are derived once each and linked by mitigates edges', async () => {
      const mitigations = byType(bundle, 'course-of-action');

      // Reviewed expectation, read from the pinned resources/attack-techniques.json, not
      // from the export under test. Using the exported count as its own oracle would
      // accept silently losing a mitigation. A framework update can change this list.
      const EXPECTED_MITIGATIONS = ['M1026', 'M1038', 'M1042', 'M1045', 'M1049'];
      const externalIds = mitigations
        .map((m: any) => m.external_references[0].external_id).sort();
      expect(externalIds, 'derived mitigations for T1059.001').toEqual(EXPECTED_MITIGATIONS);

      const mitigationIds = mitigations.map((m: any) => m.id);
      expect(new Set(mitigationIds).size).toBe(mitigationIds.length);

      const patternId = byType(bundle, 'attack-pattern')[0].id;
      const mitigates = byType(bundle, 'relationship').filter((r: any) => r.relationship_type === 'mitigates');
      // Exactly one edge per REVIEWED mitigation, all pointing at the one attack pattern.
      expect(mitigates).toHaveLength(EXPECTED_MITIGATIONS.length);
      expect(new Set(mitigates.map((r: any) => r.source_ref))).toEqual(new Set(mitigationIds));
      for (const edge of mitigates) {
        expect(edge.target_ref).toBe(patternId);
        // Complete record, so a dropped or corrupted field on a derived edge is caught.
        expect(Object.keys(edge).sort()).toEqual([
          'created', 'id', 'modified', 'relationship_type', 'source_ref', 'spec_version',
          'target_ref', 'type',
        ]);
        expect(edge.spec_version).toBe('2.1');
      }

      // Same absolute treatment for the other derived SDO class: complete key set and
      // exact name/description read from the pinned resource, not from the export.
      const pinnedMitigations = new Map<string, any>(
        pinnedTechnique('T1059.001').mitigations.map((m: any) => [m.id, m]),
      );
      for (const mitigation of mitigations) {
        const mitreId = mitigation.external_references[0].external_id;
        expect(mitigation.external_references[0].source_name).toBe('mitre-attack');
        expect(mitigation.external_references[0].url)
          .toBe(`https://attack.mitre.org/mitigations/${mitreId}`);

        const pinned = pinnedMitigations.get(mitreId);
        expect(pinned, `pinned resource must describe ${mitreId}`).toBeDefined();
        expect(Object.keys(mitigation).sort(), `derived ${mitreId} key set`).toEqual([
          'created', 'description', 'external_references', 'id', 'modified', 'name',
          'spec_version', 'type',
        ]);
        expect(mitigation.id).toMatch(new RegExp(`^course-of-action--${UUID}$`));
        expect(mitigation.spec_version).toBe('2.1');
        expect(mitigation.name, `${mitreId} name`).toBe(pinned.name);
        expect(mitigation.description, `${mitreId} description`).toBe(pinned.description);
        expectIsoTimestampWithin(mitigation.created, startedAt);
        expectIsoTimestampWithin(mitigation.modified, startedAt);
      }
    });

    await test.step('co-location edges are custom-to-custom only and deduplicated across phases', async () => {
      const coLocation = byType(bundle, 'relationship')
        .filter((r: any) => r.relationship_type !== 'mitigates');
      const keys = coLocation.map(edgeKey).sort();

      // A/B are co-located in two phases but yield ONE edge, described by the first phase.
      // C/D are co-located inside a group. No edge involves a technique, CAPEC or CWE:
      // buildSTIXBundle() computes the non-custom lists but never relates them.
      expect(keys).toEqual([
        `related-to|${A}|${B}`,
        `related-to|${C}|${D}`,
      ].sort());
      expect(coLocation).toHaveLength(2);

      // COMPLETE hand-authored records for the generated edges, not just their endpoints.
      // Endpoint-only comparison is blind to a dropped description or a corrupted
      // spec_version, and the export/re-export comparator cannot see those either because
      // a symmetric loss appears in both artifacts. This is the independent oracle.
      const withoutVolatile = (edge: any) => {
        const copy = { ...edge };
        delete copy.id;
        delete copy.created;
        delete copy.modified;
        return copy;
      };
      expect(coLocation.map(withoutVolatile).sort((x: any, y: any) =>
        x.source_ref.localeCompare(y.source_ref))).toEqual([
        {
          type: 'relationship', spec_version: '2.1', relationship_type: 'related-to',
          source_ref: A, target_ref: B, description: 'Co-located in phase IN:reconnaissance',
        },
        {
          type: 'relationship', spec_version: '2.1', relationship_type: 'related-to',
          source_ref: C, target_ref: D, description: 'Co-located in phase IN:exploitation',
        },
      ]);

      const ab = coLocation.find((r: any) => r.source_ref === A);
      expect(ab.description).toBe('Co-located in phase IN:reconnaissance');

      // Every co-location edge is `related-to`, never a type-specific verb. Recorded in
      // CONTEXT.md during EF-01: STIX_RELATIONSHIP_MAP maps a source type to a STRING,
      // but addRelationship() reads it as MAP[sourceType][targetType], so the lookup is
      // always undefined and the `related-to` fallback always wins. Asserted as current
      // behavior, not as desired behavior; relationship semantics are a separate task.
      expect(new Set(coLocation.map((r: any) => r.relationship_type))).toEqual(new Set(['related-to']));
      const mapEntry = await page.evaluate(() => (eval('STIX_RELATIONSHIP_MAP') as any).malware);
      expect(typeof mapEntry, 'the map is flat, which is why the lookup never resolves').toBe('string');

      const patternId = byType(bundle, 'attack-pattern')[0].id;
      expect(coLocation.some((r: any) => r.source_ref === patternId || r.target_ref === patternId)).toBe(false);
    });

    await test.step('re-export keeps identical derived identities and edge multiplicity', async () => {
      const second = (await exportStix(page)).json;
      const stableId = (objects: any[]) => objects.map((o: any) => o.id).sort();
      expect(stableId(byType(second, 'attack-pattern'))).toEqual(stableId(byType(bundle, 'attack-pattern')));
      expect(stableId(byType(second, 'course-of-action'))).toEqual(stableId(byType(bundle, 'course-of-action')));
      expect(byType(second, 'relationship').map(edgeKey).sort())
        .toEqual(byType(bundle, 'relationship').map(edgeKey).sort());
      // Edges are the one class whose ids are regenerated each export.
      expect(new Set(byType(second, 'relationship').map((o: any) => o.id)))
        .not.toEqual(new Set(byType(bundle, 'relationship').map((o: any) => o.id)));
    });
  });

  test('STIX import restores supported SDOs and skips SROs without inventing assignments', async ({ page, browser }) => {
    await openApp(page);
    await importNative(page, bytes(graphFixture()), 'rt-08-source.json');
    const exported = await exportStix(page);
    const sourceCounts = {
      sdo: exported.json.objects.filter((o: any) => o.type !== 'relationship').length,
      sro: exported.json.objects.filter((o: any) => o.type === 'relationship').length,
    };
    expect(sourceCounts.sro).toBeGreaterThan(0);

    await withFreshContext(browser, async freshPage => {
      await importStix(freshPage, exported.buffer, exported.name);
      await expect(freshPage.locator('#toast')).toHaveText(`Imported ${sourceCounts.sdo} STIX objects`);

      const restored = await readState(freshPage);
      // Every SDO lands in the library, including derived attack patterns and mitigations.
      expect(Object.keys(restored.customLibrary)).toHaveLength(sourceCounts.sdo);
      for (const id of [A, B, C, D]) expect(restored.customLibrary[id]).toBeDefined();
      expect(restored.customLibrary[D].pattern).toBe("[file:name = 'g.exe']");
      expect(restored.customLibrary[A].is_family).toBe(false);

      // Relationships are skipped by design, so the graph is NOT restored, and a STIX
      // import never fabricates phase assignments.
      for (const phase of Object.values(restored.assignments) as any[]) {
        expect(phase.customItems).toEqual([]);
        expect(phase.groups).toEqual([]);
      }
    });
  });

  // Exports the graph and imports that bundle again, so the derived attack pattern and its
  // mitigations are also library entries while the technique stays assigned.
  async function reimportOwnBundle(page: Page) {
    await openApp(page);
    await importNative(page, bytes(graphFixture()), 'rt-08-source.json');
    const first = await exportStix(page);
    const derivedIds: string[] = first.json.objects
      .filter((o: any) => o.type === 'attack-pattern' || o.type === 'course-of-action')
      .map((o: any) => o.id);
    expect(derivedIds).toHaveLength(6);
    await importStix(page, first.buffer, first.name);
    await expect(page.locator('#toast')).toHaveText('Imported 6 STIX objects, 4 duplicates skipped');
    const patternId = byType(first.json, 'attack-pattern')[0].id;
    return { first, derivedIds, patternId };
  }

  test('exporting after importing its own bundle writes each derived object once', async ({ page, browser }) => {
    // A re-imported bundle puts the derived attack pattern and mitigations in the library too.
    // Objects with one id are versions of one object (STIX 2.1 section 3.2), so the export writes
    // only the complete derived copy while the technique is assigned.
    const { first, derivedIds } = await reimportOwnBundle(page);

    const second = (await exportStix(page)).json;
    const ids = second.objects.map((o: any) => o.id);
    expect(ids.filter((id: string, i: number) => ids.indexOf(id) !== i), 'ids written twice').toEqual([]);

    // Library objects without a derived id are still written, in library order, and the
    // bundle keeps its layout: library objects, co-location edges, derived SDOs, mitigates.
    expect(second.objects.slice(0, 4).map((o: any) => [o.id, o.name])).toEqual([
      [A, 'Graph malware'], [B, 'Graph identity'], [C, 'Graph tool'], [D, 'Graph indicator'],
    ]);
    const kind = (o: any) => (o.type === 'relationship' ? `relationship:${o.relationship_type}` : o.type);
    expect(second.objects.map(kind)).toEqual([
      'malware', 'identity', 'tool', 'indicator',
      'relationship:related-to', 'relationship:related-to',
      'attack-pattern', ...Array(5).fill('course-of-action'),
      ...Array(5).fill('relationship:mitigates'),
    ]);

    const pattern = byType(second, 'attack-pattern');
    expect(pattern).toHaveLength(1);
    expect(Object.keys(pattern[0]).sort()).toEqual([
      'created', 'description', 'external_references', 'id', 'kill_chain_phases',
      'modified', 'name', 'spec_version', 'type',
    ]);
    const mitigations = byType(second, 'course-of-action');
    expect(mitigations).toHaveLength(5);
    for (const mitigation of mitigations) {
      expect(Object.keys(mitigation).sort()).toEqual([
        'created', 'description', 'external_references', 'id', 'modified', 'name',
        'spec_version', 'type',
      ]);
    }
    const present = new Set(ids);
    for (const edge of byType(second, 'relationship')) {
      expect(present.has(edge.source_ref), `dangling source_ref ${edge.source_ref}`).toBe(true);
      expect(present.has(edge.target_ref), `dangling target_ref ${edge.target_ref}`).toBe(true);
    }
    expect(byType(second, 'relationship').filter((r: any) => r.relationship_type === 'mitigates')).toHaveLength(5);

    // The imported library entries stay in the native export, whose embedded bundle is deduplicated too.
    const native = (await exportNative(page)).json;
    for (const id of derivedIds) expect(native.customLibrary[id], `library keeps ${id}`).toBeDefined();
    const embeddedIds = native.stixBundle.objects.map((o: any) => o.id);
    expect(embeddedIds.filter((id: string, i: number) => embeddedIds.indexOf(id) !== i), 'embedded ids written twice').toEqual([]);

    // Without the technique assigned, the library entry is the only copy and is still written.
    await withFreshContext(browser, async freshPage => {
      await importStix(freshPage, first.buffer, first.name);
      const alone = (await exportStix(freshPage)).json;
      const patterns = byType(alone, 'attack-pattern');
      expect(patterns.map((o: any) => o.id)).toEqual([pattern[0].id]);
      expect(Object.keys(patterns[0]).sort()).toEqual([
        'created', 'description', 'id', 'modified', 'name', 'spec_version', 'type',
      ]);
      expect(byType(alone, 'course-of-action')).toHaveLength(5);
    });
  });

  test('an edit to a library entry with a derived id stays in the library, not in the STIX export', async ({ page }) => {
    // While the technique is assigned, the derived copy is written in place of the library entry.
    const { patternId } = await reimportOwnBundle(page);
    await page.evaluate(id => (window as any).openStixEditor(id), patternId);
    await page.locator('#stix-edit-name').fill('Edited library copy');
    await page.locator('#stix-edit-aliases').fill('Edited alias');
    await page.locator('.btn-stix-save').click();
    await expect(page.locator('#toast')).toHaveText('STIX item updated');

    const bundle = (await exportStix(page)).json;
    const patterns = byType(bundle, 'attack-pattern');
    expect(patterns.map((o: any) => o.id)).toEqual([patternId]);
    expect(patterns[0].name).toBe(pinnedTechnique('T1059.001').name);
    expect(patterns[0]).not.toHaveProperty('aliases');
    const library = (await exportNative(page)).json.customLibrary[patternId];
    expect([library.name, library.aliases]).toEqual(['Edited library copy', ['Edited alias']]);
  });

  test('an invalid value in a library entry with a derived id still stops the export', async ({ page }) => {
    // The entry is type-checked before it is left out, so both exports refuse and write nothing.
    const { patternId } = await reimportOwnBundle(page);
    await page.evaluate(id => { eval('state').library.custom[id].aliases = [1]; }, patternId);
    const message = 'Cannot export STIX property "attack-pattern.aliases": expected array of strings.';

    await expectNoDownload(page, () => clickExportControl(page, 'STIX Bundle'));
    await expect(page.locator('#toast')).toHaveText(`STIX export failed: ${message}`);
    await expectNoDownload(page, () => clickExportControl(page, 'JSON'));
    await expect(page.locator('#toast')).toHaveText(`JSON export failed: ${message}`);
  });

  test('a technique without ATT&CK data is exported from the library entry with its derived id', async ({ page, browser }) => {
    // With no technique record (or one without a description), the library entry knows more: its
    // content is written with the ATT&CK reference and phases, keeping its created (STIX 2.1 section 3.2).
    const { first, patternId } = await reimportOwnBundle(page);
    const original = byType(first.json, 'attack-pattern')[0];
    await importNavigatorLayer(page, bytes({ name: 'Parent only', domain: 'enterprise-attack', techniques: [{ techniqueID: 'T1059' }] }));
    await expect(page.locator('#toast')).toHaveText('Loaded 1 techniques (library replaced)');
    const technique = pinnedTechnique('T1059.001');
    const reference = [{
      source_name: 'mitre-attack', external_id: 'T1059.001', url: 'https://attack.mitre.org/techniques/T1059/001',
    }];
    const phases = (...names: string[]) => names.map(phase_name => ({ kill_chain_name: 'unified-kill-chain', phase_name }));

    const libraryBefore = (await exportNative(page)).json.customLibrary[patternId];
    expect([libraryBefore.name, libraryBefore.description.length > 0]).toEqual([technique.name, true]);
    let startedAt = Date.now();
    let patterns = byType((await exportStix(page)).json, 'attack-pattern');
    expect(patterns).toEqual([{
      type: 'attack-pattern', spec_version: '2.1', id: patternId, created: original.created,
      modified: patterns[0]?.modified, name: technique.name, description: libraryBefore.description,
      external_references: reference, kill_chain_phases: expect.arrayContaining(phases('reconnaissance', 'exploitation')),
    }]);
    expect(patterns[0].kill_chain_phases).toHaveLength(2);
    expectIsoTimestampWithin(patterns[0].modified, startedAt);
    expect(Date.parse(patterns[0].modified)).toBeGreaterThanOrEqual(Date.parse(original.created));
    expect((await exportNative(page)).json.customLibrary[patternId], 'export leaves the entry as stored').toEqual(libraryBefore);

    // An edit to the library entry reaches the export for such a technique.
    await page.evaluate(id => (window as any).openStixEditor(id), patternId);
    await page.locator('#stix-edit-name').fill('Edited library copy');
    await page.locator('.btn-stix-save').click();
    patterns = byType((await exportStix(page)).json, 'attack-pattern');
    expect(patterns.map((o: any) => [o.id, o.name, o.created])).toEqual([[patternId, 'Edited library copy', original.created]]);

    // A technique the ATT&CK data does not know gets a placeholder record without a description.
    expect(ATTACK_TECHNIQUES['T1999'], 'pinned resource must not describe T1999').toBeUndefined();
    await withFreshContext(browser, async freshPage => {
      await importNative(freshPage, bytes({ assignments: { 'IN:delivery': {
        techniques: [{ id: 'T1999', instanceId: 'itm-u-1' }], capecs: [], cwes: [], customItems: [], groups: [], layout: [],
      } } }), 'rt-08-unknown.json');
      const placeholder = byType((await exportStix(freshPage)).json, 'attack-pattern');
      expect(placeholder.map((o: any) => o.name)).toEqual(['Technique T1999']);
      const unknownId = placeholder[0].id;
      await importStix(freshPage, bytes({
        type: 'bundle', id: 'bundle--e0e0e0e0-0000-4000-8000-000000000001', objects: [{
          type: 'attack-pattern', spec_version: '2.1', id: unknownId,
          created: '2020-01-01T00:00:00.000Z', modified: '2021-01-01T00:00:00.000Z',
          name: 'Newer technique', description: 'Described by a newer ATT&CK release', labels: ['newer'], aliases: ['Other name'],
        }],
      }), 'rt-08-newer.json');
      startedAt = Date.now();
      const written = byType((await exportStix(freshPage)).json, 'attack-pattern');
      expect(written).toEqual([{
        type: 'attack-pattern', spec_version: '2.1', id: unknownId,
        created: '2020-01-01T00:00:00.000Z', modified: written[0]?.modified,
        name: 'Newer technique', description: 'Described by a newer ATT&CK release', labels: ['newer'], aliases: ['Other name'],
        external_references: [{ source_name: 'mitre-attack', external_id: 'T1999', url: 'https://attack.mitre.org/techniques/T1999' }],
        kill_chain_phases: phases('delivery'),
      }]);
      expectIsoTimestampWithin(written[0].modified, startedAt);
    });
  });

  test('a library entry for a technique without ATT&CK data brings its created only when it is a STIX timestamp', async ({ page }) => {
    // created and modified need the UTC "Z" form with at least millisecond precision (STIX 2.1
    // sections 2.16.1 and 3.2), and modified is never earlier than created.
    await openApp(page);
    const techniques = ['T1998', 'T1999'];
    for (const id of techniques) expect(ATTACK_TECHNIQUES[id], `pinned resource must not describe ${id}`).toBeUndefined();
    await importNative(page, bytes({ assignments: { 'IN:delivery': {
      techniques: techniques.map((id, n) => ({ id, instanceId: `itm-t-${n}` })), capecs: [], cwes: [], customItems: [], groups: [], layout: [],
    } } }), 'rt-08-timestamps.json');
    const idOf = new Map(byType((await exportStix(page)).json, 'attack-pattern')
      .map((o: any) => [o.external_references[0].external_id, o.id]));
    const entry = (technique: string, created: string) => ({
      type: 'attack-pattern', spec_version: '2.1', id: idOf.get(technique), created, modified: created, name: `Newer ${technique}`,
    });
    await importStix(page, bytes({
      type: 'bundle', id: 'bundle--e0e0e0e0-0000-4000-8000-000000000002',
      objects: [entry('T1998', '2999-01-01T00:00:00.000Z'), entry('T1999', '2020-01-01T00:00:00Z')],
    }), 'rt-08-timestamps-bundle.json');

    const startedAt = Date.now();
    const written = new Map(byType((await exportStix(page)).json, 'attack-pattern')
      .map((o: any) => [o.external_references[0].external_id, o]));
    // A future created is kept, so modified moves up to it.
    expect(['name', 'created', 'modified'].map(key => written.get('T1998')[key]))
      .toEqual(['Newer T1998', '2999-01-01T00:00:00.000Z', '2999-01-01T00:00:00.000Z']);
    // Without milliseconds it is not a valid created, so the export time is used; the content stays.
    const late = written.get('T1999');
    expect(late.name).toBe('Newer T1999');
    expectIsoTimestampWithin(late.created, startedAt);
    expect(late.modified).toBe(late.created);
  });
});

test.describe('STIX identifiers with uppercase UUID hex', () => {
  // STIX 2.1 section 2.9 requires an RFC 4122 UUID, whose hex digits are case-insensitive on
  // input, and a lowercase type name. Such ids are kept, stored in lowercase and reported.
  const UPPER = 'malware--AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE';
  const UPPER_STORED = 'malware--aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
  const MIXED = 'tool--Cccccccc-dDdD-4eEe-8FfF-000000000000';
  const MIXED_STORED = 'tool--cccccccc-dddd-4eee-8fff-000000000000';
  const TYPE_CASE = 'Malware--11111111-2222-4333-8444-555555555555';
  const at = '2026-01-01T00:00:00.000Z';
  const sdo = (type: string, id: string, name: string, extra: Record<string, unknown> = {}) =>
    ({ type, spec_version: '2.1', id, created: at, modified: at, name, ...extra });
  const bundleOf = (objects: unknown[]) =>
    bytes({ type: 'bundle', id: 'bundle--99999999-8888-4777-8666-555555555555', objects });

  test('imports uppercase-hex ids in lowercase, reports them and treats case variants as one id', async ({ page }) => {
    await openApp(page);
    await importStix(page, bundleOf([
      sdo('malware', UPPER, 'Upper malware', { is_family: false }),
      sdo('tool', MIXED, 'Mixed tool'),
      sdo('malware', TYPE_CASE, 'Type-case malware', { is_family: false }),
    ]));

    const library = (await readState(page)).customLibrary;
    // A capital in the type name is still refused, so only two objects arrive.
    expect(Object.keys(library).sort()).toEqual([UPPER_STORED, MIXED_STORED]);
    expect(library[UPPER_STORED]).toMatchObject({ id: UPPER_STORED, name: 'Upper malware' });
    expect(library[MIXED_STORED]).toMatchObject({ id: MIXED_STORED, name: 'Mixed tool' });
    await expect(page.locator('#toast'))
      .toHaveText('Imported 2 STIX objects, 2 identifiers lowercased, 1 invalid skipped');

    const exported = (await exportStix(page)).json;
    const ids = exported.objects.map((o: any) => o.id);
    expect(ids).toEqual(expect.arrayContaining([UPPER_STORED, MIXED_STORED]));
    for (const id of ids) expect(id).toMatch(new RegExp(`^[a-z][a-z0-9-]*--${UUID}$`));

    // The uppercase form of an id already in the library names the same object.
    await importStix(page, bundleOf([sdo('malware', UPPER, 'Second copy', { is_family: false })]));
    await expect(page.locator('#toast'))
      .toHaveText('Imported 0 STIX objects, 1 identifier lowercased, 1 duplicate skipped');
    const after = (await readState(page)).customLibrary;
    expect(Object.keys(after).sort()).toEqual([UPPER_STORED, MIXED_STORED]);
    expect(after[UPPER_STORED].name).toBe('Upper malware');
  });

  test('keeps the first of two ids in one bundle that differ only in case', async ({ page }) => {
    // Both orders: the first object wins and the second counts as a duplicate; only ids
    // that were changed count as lowercased.
    await openApp(page);
    await importStix(page, bundleOf([
      sdo('malware', UPPER, 'First upper', { is_family: false }),
      sdo('malware', UPPER_STORED, 'Second lower', { is_family: false }),
      sdo('tool', MIXED_STORED, 'First lower'),
      sdo('tool', MIXED, 'Second mixed'),
    ]));

    const library = (await readState(page)).customLibrary;
    expect(Object.keys(library).sort()).toEqual([UPPER_STORED, MIXED_STORED]);
    expect(library[UPPER_STORED].name).toBe('First upper');
    expect(library[MIXED_STORED].name).toBe('First lower');
    await expect(page.locator('#toast'))
      .toHaveText('Imported 2 STIX objects, 2 identifiers lowercased, 2 duplicates skipped');
  });

  test('stores id-valued references in lowercase and counts them with the ids', async ({ page }) => {
    // Properties ending in _ref or _refs hold identifiers (STIX 2.1 section 3.1). Valid ids are
    // lowercased like object ids, list entries that become equal are both kept, other values stay.
    const REPORT = 'report--12121212-3434-4565-8787-909090909090';
    const ANALYSIS = 'malware-analysis--23232323-4545-4676-8989-010101010101';
    const FILE_UPPER = 'file--0A0A0A0A-1B1B-4C2C-8D3D-4E4E4E4E4E4E';
    const FILE = 'file--0a0a0a0a-1b1b-4c2c-8d3d-4e4e4e4e4e4e';
    const SOFTWARE_UPPER = 'software--5F5F5F5F-6A6A-4B7B-8C8C-9D9D9D9D9D9D';
    const SOFTWARE = 'software--5f5f5f5f-6a6a-4b7b-8c8c-9d9d9d9d9d9d';
    const refs = [UPPER, UPPER_STORED, TYPE_CASE, 'not an id'];
    await openApp(page);
    await importStix(page, bundleOf([
      sdo('malware', UPPER, 'Upper malware', { is_family: false }),
      sdo('report', REPORT, 'Report', { published: at, object_refs: refs }),
      sdo('malware-analysis', ANALYSIS, 'Analysis', {
        product: 'scanner', sample_ref: FILE_UPPER,
        host_vm_ref: SOFTWARE_UPPER, installed_software_refs: [SOFTWARE_UPPER],
      }),
      // A duplicate is not imported, so its references are not counted.
      sdo('report', REPORT, 'Report copy', { published: at, object_refs: [UPPER] }),
    ]));

    const expectedRefs = [UPPER_STORED, UPPER_STORED, TYPE_CASE, 'not an id'];
    const library = (await readState(page)).customLibrary;
    expect(library[REPORT].object_refs).toEqual(expectedRefs);
    expect(library[ANALYSIS]).toMatchObject({
      sample_ref: FILE, host_vm_ref: SOFTWARE, installed_software_refs: [SOFTWARE],
    });
    // One object id and four references were lowercased.
    await expect(page.locator('#toast'))
      .toHaveText('Imported 3 STIX objects, 5 identifiers lowercased, 1 duplicate skipped');

    const exported = (await exportStix(page)).json;
    const byId = (id: string) => exported.objects.find((o: any) => o.id === id);
    expect(byId(REPORT).object_refs).toEqual(expectedRefs);
    expect(byId(ANALYSIS).sample_ref).toBe(FILE);
  });
});

test.describe('STIX identifiers whose type part holds a double hyphen', () => {
  // A type never contains "--" (STIX 2.1 sections 7.3.2.2 and 11.2.1), so the type part of an
  // id ends at the final "--" before the UUID. No rule forbids a type that ends in a hyphen.
  const VALID = 'malware--aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
  const INNER = 'malware--tool--11111111-2222-4333-8444-555555555555';
  const TRAILING = 'malware---22222222-3333-4444-8555-666666666666';
  const at = '2026-01-01T00:00:00.000Z';
  const sdo = (type: string, id: string, name: string, extra: Record<string, unknown> = {}) =>
    ({ type, spec_version: '2.1', id, created: at, modified: at, name, ...extra });
  const bundleOf = (objects: unknown[]) =>
    bytes({ type: 'bundle', id: 'bundle--99999999-8888-4777-8666-555555555555', objects });

  test('the identifier grammar refuses "--" inside the type part', async ({ page }) => {
    await openApp(page);
    const rows: Array<[string, boolean]> = [
      [VALID, true], [TRAILING, true], ['x-acme---aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', true],
      [INNER, false], ['x--y--aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', false],
      ['malware----aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', false],
    ];
    const results = await page.evaluate(
      (ids) => ids.map((id) => [id, (eval('STIX_ID_PATTERN') as RegExp).test(id)]), rows.map(([id]) => id),
    );
    expect(results).toEqual(rows);
  });

  test('bundle import skips objects whose id type part is not their type', async ({ page }) => {
    // TRAILING matches the grammar, but its type part is "malware-", not "malware".
    await openApp(page);
    await importStix(page, bundleOf([
      sdo('malware', VALID, 'Valid malware', { is_family: false }),
      sdo('malware', INNER, 'Inner malware', { is_family: false }),
      sdo('malware', TRAILING, 'Trailing malware', { is_family: false }),
    ]));

    expect(Object.keys((await readState(page)).customLibrary)).toEqual([VALID]);
    await expect(page.locator('#toast')).toHaveText('Imported 1 STIX object, 2 invalid skipped');
    const ids = (await exportStix(page)).json.objects.map((o: any) => o.id);
    expect(ids).toContain(VALID);
    for (const id of [INNER, TRAILING]) expect(ids).not.toContain(id);
  });

  test('a reference is lowercased only when its type part is a type name', async ({ page }) => {
    // "x-acme-" is a valid type name, so that reference is an id; "tool--x" is not.
    const REPORT = 'report--12121212-3434-4565-8787-909090909090';
    const TRAILING_REF = 'x-acme---AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE';
    const INNER_REF = 'tool--x--AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE';
    await openApp(page);
    await importStix(page, bundleOf([
      sdo('report', REPORT, 'Report', { published: at, object_refs: [TRAILING_REF, INNER_REF] }),
    ]));

    const expectedRefs = ['x-acme---aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', INNER_REF];
    expect((await readState(page)).customLibrary[REPORT].object_refs).toEqual(expectedRefs);
    await expect(page.locator('#toast')).toHaveText('Imported 1 STIX object, 1 identifier lowercased');
  });
});
