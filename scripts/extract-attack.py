#!/usr/bin/env python3
"""
Extract ATT&CK technique data from STIX bundles
Generates attack-techniques.json for use in the Kill Chain Editor

Usage: python3 scripts/extract-attack.py
"""

import json
import os
from pathlib import Path


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
        if phase.get('kill_chain_name') == 'mitre-attack':
            tactics.append(phase.get('phase_name'))
    return tactics


def process_stix_bundle(file_path, techniques, mitigations, relationships):
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
            
            # Only add if not already present (avoid duplicates across files)
            if ext_id not in techniques:
                techniques[ext_id] = {
                    'id': ext_id,
                    'stixId': obj.get('id'),
                    'name': obj.get('name', ''),
                    'description': (obj.get('description', '') or '')[:3000],
                    'platforms': obj.get('x_mitre_platforms', []),
                    'tactics': extract_tactics(obj),
                    'domain': domain,
                    'isSubtechnique': obj.get('x_mitre_is_subtechnique', False),
                    'parentTechnique': None,  # Will be resolved later
                    'detection': (obj.get('x_mitre_detection', '') or '')[:2000],
                    'version': obj.get('x_mitre_version', '1.0'),
                    'references': extract_references(obj),
                    'mitigations': []  # Will be populated later
                }
                tech_count += 1
        
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
            if rel_type in ('mitigates', 'subtechnique-of'):
                relationships.append({
                    'type': rel_type,
                    'source': obj.get('source_ref'),
                    'target': obj.get('target_ref'),
                    'description': (obj.get('description', '') or '')[:1000]
                })
                rel_count += 1
    
    print(f'    Found: {tech_count} techniques, {mit_count} mitigations, {rel_count} relevant relationships')


def resolve_relationships(techniques, mitigations, relationships):
    """Resolve relationships to link mitigations and parent techniques."""
    print('Resolving relationships...')
    
    # Build STIX ID to external ID mapping for techniques
    stix_to_ext = {}
    for ext_id, tech in techniques.items():
        stix_to_ext[tech['stixId']] = ext_id
    
    mit_count = 0
    parent_count = 0
    
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
    
    print(f'  Resolved: {mit_count} mitigation links, {parent_count} parent technique links')
    
    # Clean up stixId from output (not needed in final JSON)
    for tech in techniques.values():
        del tech['stixId']


def main():
    script_dir = Path(__file__).parent
    resources_dir = script_dir.parent / 'resources'
    
    # STIX bundle files
    stix_files = [
        resources_dir / 'enterprise-attack-18.1.json',
        resources_dir / 'mobile-attack-18.1.json',
        resources_dir / 'ics-attack-18.1.json'
    ]
    stix_files = [f for f in stix_files if f.exists()]
    
    if not stix_files:
        print('No ATT&CK STIX bundle files found in resources/')
        print('Expected: enterprise-attack-*.json, mobile-attack-*.json, ics-attack-*.json')
        return 1
    
    print('=== ATT&CK Technique Extraction ===\n')
    
    # Data structures
    techniques = {}
    mitigations = {}
    relationships = []
    
    # Process each STIX bundle
    for stix_file in stix_files:
        process_stix_bundle(str(stix_file), techniques, mitigations, relationships)
    
    # Resolve relationships
    resolve_relationships(techniques, mitigations, relationships)
    
    # Write output
    output_file = resources_dir / 'attack-techniques.json'
    print(f'\nWriting {output_file.name}...')
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(techniques, f, indent=2, ensure_ascii=False)
    
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
    
    return 0


if __name__ == '__main__':
    exit(main())
