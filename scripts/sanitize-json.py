#!/usr/bin/env python3
"""
Sanitize JSON data files by removing HTML tags and stray < > characters.
This prevents potential XSS vectors in the data layer.

Usage: python3 scripts/sanitize-json.py
"""

import json
import re
import os
from pathlib import Path


def strip_html_tags(text):
    """Remove HTML tags from text, keeping the content between tags."""
    if not isinstance(text, str):
        return text
    
    # Remove paired HTML tags like <code>...</code>, <a href="...">...</a>
    # Keep the content between the tags
    text = re.sub(r'<(\w+)(?:\s+[^>]*)?>([^<]*)</\1>', r'\2', text)
    
    # Remove self-closing tags like <br/>, <hr/>
    text = re.sub(r'<\w+\s*/>', '', text)
    
    # Remove any remaining HTML tags (unpaired or malformed)
    text = re.sub(r'<[^>]+>', '', text)
    
    # Remove stray < and > characters that aren't part of valid comparisons
    # Keep patterns like "a < b" or "x > y" where there's space around the operator
    # Remove patterns like "<script" or "onclick>" that look like partial tags
    text = re.sub(r'<(?!\s)', '', text)  # < not followed by space
    text = re.sub(r'(?<!\s)>', '', text)  # > not preceded by space
    
    return text


def sanitize_value(value):
    """Recursively sanitize a value (string, list, or dict)."""
    if isinstance(value, str):
        return strip_html_tags(value)
    elif isinstance(value, list):
        return [sanitize_value(item) for item in value]
    elif isinstance(value, dict):
        return {k: sanitize_value(v) for k, v in value.items()}
    else:
        return value


def sanitize_json_file(file_path):
    """Sanitize a JSON file by removing HTML tags from all string values."""
    print(f'  Processing {os.path.basename(file_path)}...')
    
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Count changes
    original = json.dumps(data)
    sanitized = sanitize_value(data)
    modified = json.dumps(sanitized)
    
    # Count removed tags
    tag_pattern = r'<[^>]+>'
    original_tags = len(re.findall(tag_pattern, original))
    
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(sanitized, f, indent=2, ensure_ascii=False)
    
    if original_tags > 0:
        print(f'    Removed {original_tags} HTML tags/fragments')
    else:
        print(f'    No HTML tags found')
    
    return original_tags


def main():
    script_dir = Path(__file__).parent
    resources_dir = script_dir.parent / 'resources'
    
    print('=== JSON Sanitization ===\n')
    
    # Files to sanitize
    json_files = [
        'attack-techniques.json',
        'capec-full.json',
        'cwe-full.json'
    ]
    
    total_removed = 0
    for filename in json_files:
        file_path = resources_dir / filename
        if file_path.exists():
            removed = sanitize_json_file(file_path)
            total_removed += removed
        else:
            print(f'  Warning: {filename} not found')
    
    print(f'\n=== Sanitization Complete ===')
    print(f'Total HTML tags/fragments removed: {total_removed}')
    
    return 0


if __name__ == '__main__':
    exit(main())
