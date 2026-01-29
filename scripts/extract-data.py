#!/usr/bin/env python3
"""
Extract CAPEC and CWE data from XML files
Generates JSON files for use in the Kill Chain Editor

Usage: python3 scripts/extract-data.py
"""

import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path

# XML namespaces
CAPEC_NS = {'capec': 'http://capec.mitre.org/capec-3', 'xhtml': 'http://www.w3.org/1999/xhtml'}
CWE_NS = {'cwe': 'http://cwe.mitre.org/cwe-7', 'xhtml': 'http://www.w3.org/1999/xhtml'}


def get_text(element, default=''):
    """Extract text from an element, handling mixed content."""
    if element is None:
        return default
    
    # Get direct text
    text = element.text or ''
    
    # Get tail text from children
    for child in element:
        child_text = get_text(child, '')
        text += ' ' + child_text
        if child.tail:
            text += ' ' + child.tail
    
    return re.sub(r'\s+', ' ', text).strip()


def extract_capec(xml_files):
    """Extract CAPEC attack patterns from XML files."""
    print('Extracting CAPEC data...')
    patterns = {}
    categories = {}
    
    for xml_file in xml_files:
        print(f'  Processing {os.path.basename(xml_file)}...')
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
        except ET.ParseError as e:
            print(f'    Error parsing {xml_file}: {e}')
            continue
        
        # Find Attack_Patterns
        attack_patterns_el = root.find('capec:Attack_Patterns', CAPEC_NS)
        if attack_patterns_el is not None:
            pattern_elements = attack_patterns_el.findall('capec:Attack_Pattern', CAPEC_NS)
            print(f'    Found {len(pattern_elements)} attack patterns')
            
            for pattern in pattern_elements:
                id_val = pattern.get('ID', '')
                name = pattern.get('Name', '')
                abstraction = pattern.get('Abstraction', '')
                status = pattern.get('Status', '')
                
                if not id_val:
                    continue
                
                capec_id = f'CAPEC-{id_val}'
                
                # Description
                desc_el = pattern.find('capec:Description', CAPEC_NS)
                description = get_text(desc_el)[:500]  # Limit length
                
                # Severity and Likelihood
                severity_el = pattern.find('capec:Typical_Severity', CAPEC_NS)
                likelihood_el = pattern.find('capec:Likelihood_Of_Attack', CAPEC_NS)
                severity = get_text(severity_el) or 'Unknown'
                likelihood = get_text(likelihood_el) or 'Unknown'
                
                # Related CWEs
                cwes = []
                related_weaknesses = pattern.find('capec:Related_Weaknesses', CAPEC_NS)
                if related_weaknesses is not None:
                    for rw in related_weaknesses.findall('capec:Related_Weakness', CAPEC_NS):
                        cwe_id = rw.get('CWE_ID', '')
                        if cwe_id:
                            cwes.append(f'CWE-{cwe_id}')
                
                # Related ATT&CK techniques
                techniques = []
                taxonomy_mappings = pattern.find('capec:Taxonomy_Mappings', CAPEC_NS)
                if taxonomy_mappings is not None:
                    for tm in taxonomy_mappings.findall('capec:Taxonomy_Mapping', CAPEC_NS):
                        if tm.get('Taxonomy_Name') == 'ATTACK':
                            entry_id_el = tm.find('capec:Entry_ID', CAPEC_NS)
                            if entry_id_el is not None:
                                tech_id = get_text(entry_id_el)
                                # Normalize: 1574.010 -> T1574.010
                                if tech_id and not tech_id.startswith('T'):
                                    tech_id = 'T' + tech_id
                                if tech_id:
                                    techniques.append(tech_id)
                
                # Parent CAPEC (ChildOf relationship)
                parent = None
                related_patterns = pattern.find('capec:Related_Attack_Patterns', CAPEC_NS)
                if related_patterns is not None:
                    for rp in related_patterns.findall('capec:Related_Attack_Pattern', CAPEC_NS):
                        if rp.get('Nature') == 'ChildOf':
                            parent_id = rp.get('CAPEC_ID', '')
                            if parent_id:
                                parent = f'CAPEC-{parent_id}'
                            break
                
                patterns[capec_id] = {
                    'id': capec_id,
                    'name': name,
                    'description': description,
                    'abstraction': abstraction,
                    'status': status,
                    'severity': severity,
                    'likelihood': likelihood,
                    'cwes': cwes,
                    'techniques': techniques,
                    'parent': parent,
                    'children': []
                }
        
        # Find Categories
        categories_el = root.find('capec:Categories', CAPEC_NS)
        if categories_el is not None:
            category_elements = categories_el.findall('capec:Category', CAPEC_NS)
            print(f'    Found {len(category_elements)} categories')
            
            for cat in category_elements:
                cat_id = cat.get('ID', '')
                cat_name = cat.get('Name', '')
                if not cat_id:
                    continue
                
                members = []
                relationships = cat.find('capec:Relationships', CAPEC_NS)
                if relationships is not None:
                    for member in relationships.findall('capec:Has_Member', CAPEC_NS):
                        member_id = member.get('CAPEC_ID', '')
                        if member_id:
                            members.append(f'CAPEC-{member_id}')
                
                categories[cat_id] = {'id': cat_id, 'name': cat_name, 'members': members}
    
    # Build children arrays from parent relationships
    for capec_id, pattern in patterns.items():
        if pattern['parent'] and pattern['parent'] in patterns:
            patterns[pattern['parent']]['children'].append(capec_id)
    
    print(f'  Total: {len(patterns)} patterns, {len(categories)} categories')
    return {'patterns': patterns, 'categories': categories}


def extract_cwe(xml_files):
    """Extract CWE weaknesses from XML files."""
    print('Extracting CWE data...')
    weaknesses = {}
    categories = {}
    
    for xml_file in xml_files:
        print(f'  Processing {os.path.basename(xml_file)}...')
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
        except ET.ParseError as e:
            print(f'    Error parsing {xml_file}: {e}')
            continue
        
        # Find Weaknesses
        weaknesses_el = root.find('cwe:Weaknesses', CWE_NS)
        if weaknesses_el is not None:
            weakness_elements = weaknesses_el.findall('cwe:Weakness', CWE_NS)
            print(f'    Found {len(weakness_elements)} weaknesses')
            
            for weakness in weakness_elements:
                id_val = weakness.get('ID', '')
                name = weakness.get('Name', '')
                abstraction = weakness.get('Abstraction', '')
                status = weakness.get('Status', '')
                
                if not id_val:
                    continue
                
                cwe_id = f'CWE-{id_val}'
                
                # Description
                desc_el = weakness.find('cwe:Description', CWE_NS)
                description = get_text(desc_el)[:500]
                
                # Related CAPECs
                capecs = []
                related_patterns = weakness.find('cwe:Related_Attack_Patterns', CWE_NS)
                if related_patterns is not None:
                    for rp in related_patterns.findall('cwe:Related_Attack_Pattern', CWE_NS):
                        capec_id = rp.get('CAPEC_ID', '')
                        if capec_id:
                            capecs.append(f'CAPEC-{capec_id}')
                
                # Parent CWE
                parent = None
                related_weaknesses = weakness.find('cwe:Related_Weaknesses', CWE_NS)
                if related_weaknesses is not None:
                    for rw in related_weaknesses.findall('cwe:Related_Weakness', CWE_NS):
                        if rw.get('Nature') == 'ChildOf':
                            parent_id = rw.get('CWE_ID', '')
                            if parent_id:
                                parent = f'CWE-{parent_id}'
                            break
                
                weaknesses[cwe_id] = {
                    'id': cwe_id,
                    'name': name,
                    'description': description,
                    'abstraction': abstraction,
                    'status': status,
                    'capecs': capecs,
                    'parent': parent,
                    'children': []
                }
        
        # Find Categories
        categories_el = root.find('cwe:Categories', CWE_NS)
        if categories_el is not None:
            category_elements = categories_el.findall('cwe:Category', CWE_NS)
            print(f'    Found {len(category_elements)} categories')
            
            for cat in category_elements:
                cat_id = cat.get('ID', '')
                cat_name = cat.get('Name', '')
                if not cat_id:
                    continue
                
                categories[cat_id] = {'id': cat_id, 'name': cat_name}
    
    # Build children arrays
    for cwe_id, weakness in weaknesses.items():
        if weakness['parent'] and weakness['parent'] in weaknesses:
            weaknesses[weakness['parent']]['children'].append(cwe_id)
    
    print(f'  Total: {len(weaknesses)} weaknesses, {len(categories)} categories')
    return {'weaknesses': weaknesses, 'categories': categories}


def build_capec_to_technique(capec_data):
    """Build CAPEC -> Technique mapping."""
    print('Building CAPEC → Technique mapping...')
    mapping = {}
    technique_count = 0
    
    for capec_id, pattern in capec_data['patterns'].items():
        if pattern['techniques']:
            mapping[capec_id] = pattern['techniques']
            technique_count += len(pattern['techniques'])
    
    print(f'  Total: {len(mapping)} CAPECs with {technique_count} technique mappings')
    return mapping


def build_technique_to_capec(capec_data):
    """Build Technique -> CAPEC mapping (reverse)."""
    print('Building Technique → CAPEC mapping...')
    mapping = {}
    
    for capec_id, pattern in capec_data['patterns'].items():
        for tech_id in pattern['techniques']:
            if tech_id not in mapping:
                mapping[tech_id] = []
            mapping[tech_id].append(capec_id)
    
    print(f'  Total: {len(mapping)} techniques mapped to CAPECs')
    return mapping


def build_cwe_to_capec(capec_data):
    """Build CWE -> CAPEC mapping (reverse)."""
    print('Building CWE → CAPEC mapping...')
    mapping = {}
    
    for capec_id, pattern in capec_data['patterns'].items():
        for cwe_id in pattern['cwes']:
            if cwe_id not in mapping:
                mapping[cwe_id] = []
            mapping[cwe_id].append(capec_id)
    
    print(f'  Total: {len(mapping)} CWEs mapped to CAPECs')
    return mapping


def add_missing_cwes(cwe_data, capec_data):
    """Add stub entries for CWEs referenced by CAPECs but not in CWE list."""
    print('Adding missing CWE stubs...')
    
    # Collect all CWEs referenced by CAPECs
    referenced_cwes = set()
    for pattern in capec_data['patterns'].values():
        for cwe_id in pattern['cwes']:
            referenced_cwes.add(cwe_id)
    
    # Find missing ones
    existing_cwes = set(cwe_data['weaknesses'].keys())
    missing_cwes = referenced_cwes - existing_cwes
    
    if missing_cwes:
        print(f'  Found {len(missing_cwes)} CWEs referenced by CAPECs but not in CWE list')
        
        for cwe_id in missing_cwes:
            # Create stub entry
            cwe_data['weaknesses'][cwe_id] = {
                'id': cwe_id,
                'name': f'CWE {cwe_id.replace("CWE-", "")}',
                'description': 'This CWE is referenced by CAPEC patterns but detailed information is not available in the current CWE view.',
                'abstraction': 'Unknown',
                'status': 'Referenced',
                'capecs': [],
                'parent': None,
                'children': []
            }
        
        # Now update capecs field for these stubs from capec_data
        for capec_id, pattern in capec_data['patterns'].items():
            for cwe_id in pattern['cwes']:
                if cwe_id in missing_cwes:
                    if capec_id not in cwe_data['weaknesses'][cwe_id]['capecs']:
                        cwe_data['weaknesses'][cwe_id]['capecs'].append(capec_id)
        
        print(f'  Added {len(missing_cwes)} stub entries')
    else:
        print('  No missing CWEs found')
    
    return cwe_data


def main():
    script_dir = Path(__file__).parent
    resources_dir = script_dir.parent / 'resources'
    
    # Check for XML files
    capec_files = [
        resources_dir / 'CAPEC_Mechanisms.xml',
        resources_dir / 'CAPEC_Domains.xml'
    ]
    capec_files = [f for f in capec_files if f.exists()]
    
    cwe_files = [
        resources_dir / 'CWE_Software_Development.xml',
        resources_dir / 'CWE_Hardware_Design.xml'
    ]
    cwe_files = [f for f in cwe_files if f.exists()]
    
    if not capec_files:
        print('No CAPEC XML files found in resources/')
        return 1
    
    if not cwe_files:
        print('No CWE XML files found in resources/')
        return 1
    
    print('=== Attack Chain Data Extraction ===\n')
    
    # Extract data
    capec_data = extract_capec([str(f) for f in capec_files])
    cwe_data = extract_cwe([str(f) for f in cwe_files])
    
    # Add missing CWEs referenced by CAPECs
    cwe_data = add_missing_cwes(cwe_data, capec_data)
    
    # Build mappings
    capec_to_technique = build_capec_to_technique(capec_data)
    technique_to_capec = build_technique_to_capec(capec_data)
    cwe_to_capec = build_cwe_to_capec(capec_data)
    
    # Write output files
    print('\nWriting output files...')
    
    output_files = [
        ('capec-full.json', capec_data),
        ('cwe-full.json', cwe_data),
        ('capec-to-technique.json', capec_to_technique),
        ('technique-to-capec.json', technique_to_capec),
        ('cwe-to-capec.json', cwe_to_capec)
    ]
    
    for name, data in output_files:
        file_path = resources_dir / name
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f'  Written: {name}')
    
    print('\n=== Extraction Complete ===')
    
    # Summary stats
    print('\nSummary:')
    print(f'  CAPEC patterns: {len(capec_data["patterns"])}')
    print(f'  CAPEC categories: {len(capec_data["categories"])}')
    print(f'  CWE weaknesses: {len(cwe_data["weaknesses"])}')
    print(f'  CAPEC→Technique mappings: {len(capec_to_technique)}')
    print(f'  Technique→CAPEC mappings: {len(technique_to_capec)}')
    print(f'  CWE→CAPEC mappings: {len(cwe_to_capec)}')
    
    return 0


if __name__ == '__main__':
    exit(main())
