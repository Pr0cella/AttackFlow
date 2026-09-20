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
import { expect, test } from '@playwright/test';
import {
  UUID, clickExportControl, exportNative, exportStix, expectBundleEnvelope,
  expectIsoTimestampWithin, expectNoDownload, expectNoExternalRequests, importNative,
  importStix, openApp, readState, withFreshContext,
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
    expect(standalone.name).toBe('RT-02-Full-Native-doc-title---chain-stix-bundle.json');

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
});
