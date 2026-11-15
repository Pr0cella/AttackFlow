#!/usr/bin/env python3
"""
Extract ATT&CK technique data from STIX bundles
Generates attack-techniques.json and the Nav_Layer_*.json library layers
for use in the Kill Chain Editor, and remaps revoked technique IDs in the
CAPEC mapping files (capec-full, capec-to-technique, technique-to-capec)

Usage: python3 scripts/extract-attack.py
"""

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

# kill chain names used by attack-pattern objects in each ATT&CK domain bundle
ATTACK_KILL_CHAINS = {'mitre-attack', 'mitre-mobile-attack', 'mitre-ics-attack'}

# navigator layer file per domain (existing file is used as the settings template)
NAV_LAYER_FILES = {
    'enterprise': 'Nav_Layer_ENTERPRISE.json',
    'mobile': 'Nav_Layer_MOBILE.json',
    'ics': 'Nav_Layer_ICS.json'
}


def extract_external_id(obj):
    """Extract external ID (e.g., T1055.011) from external_references."""
    for ref in obj.get('external_references', []):
        if ref.get('source_name') == 'mitre-attack':
            return ref.get('external_id')
    return None


def extract_mitigation_id(obj):
    """Extract mitigation ID (e.g., M1040) from external_references."""
    for ref in obj.get('external_references', []):
        if ref.get('source_name') == 'mitre-attack':
            ext_id = ref.get('external_id', '')
            if ext_id.startswith('M'):
                return ext_id
    return None


def extract_references(obj, limit=5):
    """Extract external references (limit to avoid huge payloads)."""
    refs = []
    for ref in obj.get('external_references', [])[:limit]:
        if ref.get('url'):
            refs.append({
                'name': ref.get('source_name', 'Reference'),
                'url': ref.get('url'),
                'description': ref.get('description', '')[:200] if ref.get('description') else ''
            })
    return refs


def extract_tactics(obj):
    """Extract tactic names from kill_chain_phases."""
    tactics = []
    for phase in obj.get('kill_chain_phases', []):
        if phase.get('kill_chain_name') in ATTACK_KILL_CHAINS:
            tactics.append(phase.get('phase_name'))
    return tactics


def extract_any_attack_id(obj):
    """External ID from any ATT&CK source name; older revoked mobile/ics objects
    use mitre-mobile-attack / mitre-ics-attack instead of mitre-attack."""
    for ref in obj.get('external_references', []):
        if ref.get('source_name') in ATTACK_KILL_CHAINS and ref.get('external_id'):
            return ref.get('external_id')
    return None


def new_revocations():
    """Container for revoked attack-pattern data collected across bundles."""
    return {'revoked': {}, 'stix_to_ext': {}}


def process_stix_bundle(file_path, techniques, mitigations, detection_strategies, relationships, layer_entries,
                        revocations):
    """Process a STIX bundle file and extract relevant data."""
    print(f'  Processing {os.path.basename(file_path)}...')

    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    objects = data.get('objects', [])
    tech_count = 0
    mit_count = 0
    rel_count = 0

    for obj in objects:
        obj_type = obj.get('type')

        # record every attack-pattern id (incl. revoked) to resolve revoked-by relationships
        if obj_type == 'attack-pattern':
            any_ext_id = extract_any_attack_id(obj)
            if any_ext_id:
                revocations['stix_to_ext'][obj.get('id')] = any_ext_id
                if obj.get('revoked'):
                    revocations['revoked'][obj.get('id')] = any_ext_id

        # Skip deprecated and revoked items
        if obj.get('x_mitre_deprecated') or obj.get('revoked'):
            continue
        
        if obj_type == 'attack-pattern':
            ext_id = extract_external_id(obj)
            if not ext_id:
                continue
            
            # Determine domain
            domains = obj.get('x_mitre_domains', [])
            if 'enterprise-attack' in domains:
                domain = 'enterprise'
            elif 'mobile-attack' in domains:
                domain = 'mobile'
            elif 'ics-attack' in domains:
                domain = 'ics'
            else:
                domain = 'enterprise'

            tactics = extract_tactics(obj)
            for tactic in tactics:
                layer_entries.setdefault(domain, set()).add((ext_id, tactic))

            # Only add if not already present (avoid duplicates across files)
            if ext_id not in techniques:
                techniques[ext_id] = {
                    'id': ext_id,
                    'stixId': obj.get('id'),
                    'name': obj.get('name', ''),
                    'description': (obj.get('description', '') or '')[:3000],
                    'platforms': obj.get('x_mitre_platforms', []),
                    'tactics': tactics,
                    'domain': domain,
                    'isSubtechnique': obj.get('x_mitre_is_subtechnique', False),
                    'parentTechnique': None,  # Will be resolved later
                    'version': obj.get('x_mitre_version', '1.0'),
                    'references': extract_references(obj),
                    'mitigations': [],  # Will be populated later
                    'detectionStrategies': []  # Will be populated later
                }
                tech_count += 1

        elif obj_type == 'x-mitre-detection-strategy':
            # ATT&CK v18+ replaces technique detection text with detection strategies
            det_id = extract_external_id(obj)
            if det_id:
                detection_strategies[obj.get('id')] = {
                    'id': det_id,
                    'name': obj.get('name', '')
                }

        elif obj_type == 'course-of-action':
            mit_id = extract_mitigation_id(obj)
            if mit_id:
                mitigations[obj.get('id')] = {
                    'id': mit_id,
                    'stixId': obj.get('id'),
                    'name': obj.get('name', ''),
                    'description': (obj.get('description', '') or '')[:2000]
                }
                mit_count += 1
        
        elif obj_type == 'relationship':
            rel_type = obj.get('relationship_type')
            if rel_type in ('mitigates', 'subtechnique-of', 'detects', 'revoked-by'):
                relationships.append({
                    'type': rel_type,
                    'source': obj.get('source_ref'),
                    'target': obj.get('target_ref'),
                    'description': (obj.get('description', '') or '')[:1000]
                })
                rel_count += 1
    
    print(f'    Found: {tech_count} techniques, {mit_count} mitigations, {rel_count} relevant relationships')


def resolve_relationships(techniques, mitigations, detection_strategies, relationships):
    """Resolve relationships to link mitigations, detection strategies, and parent techniques."""
    print('Resolving relationships...')

    # Build STIX ID to external ID mapping for techniques
    stix_to_ext = {}
    for ext_id, tech in techniques.items():
        stix_to_ext[tech['stixId']] = ext_id

    mit_count = 0
    parent_count = 0
    det_count = 0

    for rel in relationships:
        if rel['type'] == 'mitigates':
            # source is course-of-action, target is attack-pattern
            mit_stix_id = rel['source']
            tech_stix_id = rel['target']
            
            if mit_stix_id in mitigations and tech_stix_id in stix_to_ext:
                tech_ext_id = stix_to_ext[tech_stix_id]
                mit = mitigations[mit_stix_id]
                
                # Add mitigation to technique
                techniques[tech_ext_id]['mitigations'].append({
                    'id': mit['id'],
                    'name': mit['name'],
                    'description': rel['description'] or mit['description']
                })
                mit_count += 1
        
        elif rel['type'] == 'subtechnique-of':
            # source is sub-technique, target is parent technique
            sub_stix_id = rel['source']
            parent_stix_id = rel['target']
            
            if sub_stix_id in stix_to_ext and parent_stix_id in stix_to_ext:
                sub_ext_id = stix_to_ext[sub_stix_id]
                parent_ext_id = stix_to_ext[parent_stix_id]
                techniques[sub_ext_id]['parentTechnique'] = parent_ext_id
                parent_count += 1

        elif rel['type'] == 'detects':
            # source is x-mitre-detection-strategy, target is attack-pattern
            det_stix_id = rel['source']
            tech_stix_id = rel['target']

            if det_stix_id in detection_strategies and tech_stix_id in stix_to_ext:
                det = detection_strategies[det_stix_id]
                strategies = techniques[stix_to_ext[tech_stix_id]]['detectionStrategies']
                if det not in strategies:
                    strategies.append(dict(det))
                    det_count += 1

    print(f'  Resolved: {mit_count} mitigation links, {det_count} detection strategy links, '
          f'{parent_count} parent technique links')

    # Clean up stixId from output (not needed in final JSON); sort for stable output
    for tech in techniques.values():
        del tech['stixId']
        tech['detectionStrategies'].sort(key=lambda d: d['id'])


def build_revoked_map(revocations, relationships, active_ids):
    """Map revoked technique IDs to their active replacement via revoked-by chains.

    IDs without an active replacement (e.g. deprecated with no successor) are omitted.
    """
    direct = {}
    for rel in relationships:
        if rel['type'] != 'revoked-by' or rel['source'] not in revocations['revoked']:
            continue
        new_id = revocations['stix_to_ext'].get(rel['target'])
        if new_id:
            direct[revocations['revoked'][rel['source']]] = new_id

    resolved = {}
    for old_id in direct:
        if old_id in active_ids:
            continue  # never remap an id that is still active
        current, seen = old_id, set()
        while current not in active_ids and current in direct and current not in seen:
            seen.add(current)
            current = direct[current]
        if current in active_ids:
            resolved[old_id] = current
    return resolved


def dedupe(items):
    """Remove duplicates, keeping first-seen order."""
    return list(dict.fromkeys(items))


def remap_capec_mappings(resources_dir, revoked_map, active_ids):
    """Rewrite revoked ATT&CK IDs in the CAPEC mapping files to their replacements.

    CAPEC's own ATT&CK mappings predate many ATT&CK revocations. capec-full.json is
    remapped (affected patterns record the change in attackRemaps), then
    capec-to-technique.json and technique-to-capec.json are rebuilt from it the same
    way extract-data.py builds them, so all three stay consistent. Idempotent.
    """
    capec_path = resources_dir / 'capec-full.json'
    if not capec_path.exists():
        print('  Skipped CAPEC remap: capec-full.json not found')
        return

    with open(capec_path, 'r', encoding='utf-8') as f:
        capec = json.load(f)

    remap_count = 0
    affected = []
    for capec_id, pattern in capec.get('patterns', {}).items():
        original = pattern.get('techniques', [])
        if not any(t in revoked_map for t in original):
            continue
        remaps = pattern.get('attackRemaps', [])
        for old_id in dedupe(t for t in original if t in revoked_map):
            entry = {'from': old_id, 'to': revoked_map[old_id]}
            if entry not in remaps:
                remaps.append(entry)
            remap_count += 1
        pattern['attackRemaps'] = remaps
        pattern['techniques'] = dedupe(revoked_map.get(t, t) for t in original)
        affected.append(capec_id)

    # rebuild both mapping files from capec-full (same logic as extract-data.py)
    capec_to_technique = {}
    technique_to_capec = {}
    for capec_id, pattern in capec.get('patterns', {}).items():
        techniques = pattern.get('techniques', [])
        if techniques:
            capec_to_technique[capec_id] = techniques
        for tech_id in techniques:
            technique_to_capec.setdefault(tech_id, []).append(capec_id)

    outputs = [
        (capec_path, capec),
        (resources_dir / 'capec-to-technique.json', capec_to_technique),
        (resources_dir / 'technique-to-capec.json', technique_to_capec)
    ]
    for path, data in outputs:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    unresolved = sorted(t for t in technique_to_capec if t not in active_ids)
    print(f'  CAPEC remap: {remap_count} revoked technique references in {len(affected)} patterns '
          f'{affected if affected else ""}'.rstrip())
    print(f'  CAPEC mappings after remap: {len(capec_to_technique)} CAPECs, '
          f'{len(technique_to_capec)} techniques')
    if unresolved:
        print(f'  Warning: CAPEC references without an active technique: {unresolved}')


def remap_capec_from_bundles(project_dir, resources_dir):
    """Parse the configured ATT&CK bundles and remap the CAPEC mapping files.

    Entry point for extract-data.py, which regenerates the CAPEC files and would
    otherwise drop the remap. Returns False when no bundles are available.
    """
    attack_config = load_config(project_dir)['sources']['attack']
    stix_files = [project_dir / attack_config[d] for d in ('enterprise', 'mobile', 'ics')]
    stix_files = [f for f in stix_files if f.exists()]
    if not stix_files:
        return False

    techniques, relationships, revocations = {}, [], new_revocations()
    for stix_file in stix_files:
        process_stix_bundle(str(stix_file), techniques, {}, {}, relationships, {}, revocations)
    revoked_map = build_revoked_map(revocations, relationships, set(techniques))
    remap_capec_mappings(resources_dir, revoked_map, set(techniques))
    return True


def write_nav_layers(resources_dir, layer_entries, attack_version, techniques):
    """Regenerate the Nav_Layer_*.json library layers from the extracted techniques.

    The existing layer file is the template: its settings and the default
    technique entry style are kept; versions.attack and techniques are replaced,
    and platforms used by the domain's techniques are added to filters.platforms
    (otherwise ATT&CK Navigator would hide those techniques).
    """
    major_version = str(attack_version).split('.')[0]
    for domain, file_name in NAV_LAYER_FILES.items():
        entries = layer_entries.get(domain)
        layer_path = resources_dir / file_name
        if not entries:
            print(f'  Skipped {file_name}: no {domain} techniques extracted')
            continue
        if not layer_path.exists():
            print(f'  Skipped {file_name}: template layer not found')
            continue

        with open(layer_path, 'r', encoding='utf-8') as f:
            layer = json.load(f)

        template_entries = layer.get('techniques') or [{}]
        entry_template = copy.deepcopy(template_entries[0])

        entries_out = []
        for ext_id, tactic in sorted(entries):
            entry = copy.deepcopy(entry_template)
            entry['techniqueID'] = ext_id
            entry['tactic'] = tactic
            entries_out.append(entry)

        layer.setdefault('versions', {})['attack'] = major_version
        layer['techniques'] = entries_out

        # keep the template's platform order; append platforms new in this ATT&CK version
        filters = layer.setdefault('filters', {})
        platforms = list(filters.get('platforms', []))
        used = {p for t in techniques.values() if t['domain'] == domain for p in t['platforms']}
        platforms += sorted(used - set(platforms))
        filters['platforms'] = platforms

        with open(layer_path, 'w', encoding='utf-8') as f:
            json.dump(layer, f, indent=2, ensure_ascii=False)
        print(f'  Written: {file_name} ({len(entries_out)} technique/tactic entries, '
              f'platform filter: {platforms})')


def load_config(project_dir):
    """Load configuration from config.js."""
    config_path = project_dir / 'config.js'
    config = {
        'sources': {
            'attack': {
                'version': '20.1',
                'enterprise': 'frameworks/ATTCK/ENTERPRISE.json',
                'mobile': 'frameworks/ATTCK/MOBILE.json',
                'ics': 'frameworks/ATTCK/ICS.json'
            }
        }
    }
    
    # Try to parse config.js for source paths
    if config_path.exists():
        import re
        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # Extract ATT&CK paths (in attack: { ... } block)
            attack_block = re.search(r"attack:\s*\{([^}]+)\}", content)
            if attack_block:
                block = attack_block.group(1)
                m = re.search(r"version:\s*['\"]([^'\"]+)['\"]", block)
                if m:
                    config['sources']['attack']['version'] = m.group(1)
                m = re.search(r"enterprise:\s*['\"]([^'\"]+)['\"]", block)
                if m:
                    config['sources']['attack']['enterprise'] = m.group(1)
                m = re.search(r"mobile:\s*['\"]([^'\"]+)['\"]", block)
                if m:
                    config['sources']['attack']['mobile'] = m.group(1)
                m = re.search(r"ics:\s*['\"]([^'\"]+)['\"]", block)
                if m:
                    config['sources']['attack']['ics'] = m.group(1)
    
    return config


def run_sanitizer(project_dir, stage):
    """Run JSON sanitization before/after parsing."""
    script_path = project_dir / 'scripts' / 'sanitize-json.py'
    if not script_path.exists():
        print(f'Warning: sanitize-json.py not found ({stage})')
        return
    print(f'\n=== JSON Sanitization ({stage}) ===')
    subprocess.run([sys.executable, str(script_path)], check=False)


def main():
    script_dir = Path(__file__).parent
    project_dir = script_dir.parent
    resources_dir = project_dir / 'resources'

    # Sanitize JSON before parsing (cleans ATT&CK bundles)
    run_sanitizer(project_dir, 'before')
    
    # Load config
    config = load_config(project_dir)
    attack_config = config['sources']['attack']
    
    # Build file paths from config
    stix_files = [
        project_dir / attack_config['enterprise'],
        project_dir / attack_config['mobile'],
        project_dir / attack_config['ics']
    ]
    stix_files = [f for f in stix_files if f.exists()]
    
    if not stix_files:
        print('No ATT&CK STIX bundle files found. Check config.js sources.attack paths:')
        print(f"  - {attack_config['enterprise']}")
        print(f"  - {attack_config['mobile']}")
        print(f"  - {attack_config['ics']}")
        return 1
    
    print('=== ATT&CK Technique Extraction ===\n')
    
    # Data structures
    techniques = {}
    mitigations = {}
    detection_strategies = {}
    relationships = []
    layer_entries = {}
    revocations = new_revocations()

    # Process each STIX bundle
    for stix_file in stix_files:
        process_stix_bundle(str(stix_file), techniques, mitigations, detection_strategies,
                            relationships, layer_entries, revocations)

    revoked_map = build_revoked_map(revocations, relationships, set(techniques))

    # Resolve relationships
    resolve_relationships(techniques, mitigations, detection_strategies, relationships)

    # Write output
    output_file = resources_dir / 'attack-techniques.json'
    print(f'\nWriting {output_file.name}...')

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(techniques, f, indent=2, ensure_ascii=False)

    print('Writing Navigator layers...')
    write_nav_layers(resources_dir, layer_entries, attack_config['version'], techniques)

    print('Remapping revoked techniques in CAPEC mappings...')
    remap_capec_mappings(resources_dir, revoked_map, set(techniques))

    # Summary
    print('\n=== Extraction Complete ===')
    print(f'\nSummary:')
    print(f'  Total techniques: {len(techniques)}')
    
    # Count by domain
    by_domain = {'enterprise': 0, 'mobile': 0, 'ics': 0}
    for tech in techniques.values():
        by_domain[tech['domain']] = by_domain.get(tech['domain'], 0) + 1
    
    for domain, count in by_domain.items():
        print(f'    {domain}: {count}')
    
    # Count sub-techniques
    sub_count = sum(1 for t in techniques.values() if t['isSubtechnique'])
    print(f'  Sub-techniques: {sub_count}')
    
    # Count techniques with mitigations
    with_mit = sum(1 for t in techniques.values() if t['mitigations'])
    print(f'  With mitigations: {with_mit}')
    with_det = sum(1 for t in techniques.values() if t['detectionStrategies'])
    print(f'  With detection strategies: {with_det}')
    no_tactics = sum(1 for t in techniques.values() if not t['tactics'])
    print(f'  Without tactics: {no_tactics}')

    # Sanitize JSON after parsing (cleans generated files)
    run_sanitizer(project_dir, 'after')
    
    return 0


if __name__ == '__main__':
    exit(main())
