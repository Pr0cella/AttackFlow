#!/usr/bin/env python3
"""
Sanitize JSON data files by removing HTML tags and stray < > characters.
This prevents potential XSS vectors in the data layer.

Usage: python3 scripts/sanitize-json.py
"""

import argparse
import json
import re
import os
import glob
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
    
    # Encode any remaining angle brackets to prevent unencoded < or >
    text = text.replace('<', '&lt;').replace('>', '&gt;')
    
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
    
    # Count removed HTML tags (ignore comparison operators like "< 5")
    tag_pattern = r'</?\w+[^>]*>'
    original_tags = len(re.findall(tag_pattern, original))
    
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(sanitized, f, indent=2, ensure_ascii=False)
    
    if original_tags > 0:
        print(f'    Removed {original_tags} HTML tags/fragments')
    else:
        print(f'    No HTML tags found')
    
    return original_tags


def load_config_paths(project_dir):
    """Load sanitization paths from config.js, with defaults."""
    default_paths = [
        'resources/**/*.json',
        'frameworks/ATTCK/**/*.json'
    ]

    config_path = project_dir / 'config.js'
    if not config_path.exists():
        return default_paths

    try:
        content = config_path.read_text(encoding='utf-8')
    except Exception:
        return default_paths

    # Look for sanitize: { paths: [ ... ] }
    match = re.search(r"sanitize\s*:\s*\{[^}]*paths\s*:\s*\[([^\]]*)\]", content, re.DOTALL)
    if not match:
        return default_paths

    raw = match.group(1)
    # Extract quoted strings
    paths = re.findall(r"['\"]([^'\"]+)['\"]", raw)
    return paths if paths else default_paths


def resolve_paths(project_dir, patterns):
    """Resolve glob patterns to a unique list of JSON files."""
    files = set()
    for pattern in patterns:
        if os.path.isabs(pattern):
            matches = glob.glob(pattern, recursive=True)
        else:
            matches = glob.glob(str(project_dir / pattern), recursive=True)
        for match in matches:
            p = Path(match)
            if p.is_file() and p.suffix.lower() == '.json':
                files.add(p)
    return sorted(files)


def main():
    script_dir = Path(__file__).parent
    project_dir = script_dir.parent

    parser = argparse.ArgumentParser(description='Sanitize JSON files by removing HTML tags and stray < > characters.')
    parser.add_argument('--path', action='append', default=[], help='Additional glob path(s) to sanitize')
    args = parser.parse_args()
    
    print('=== JSON Sanitization ===\n')

    config_paths = load_config_paths(project_dir)
    patterns = config_paths + args.path
    json_files = resolve_paths(project_dir, patterns)

    if not json_files:
        print('  Warning: No JSON files found for sanitization')
        return 0

    total_removed = 0
    for file_path in json_files:
        removed = sanitize_json_file(file_path)
        total_removed += removed
    
    print(f'\n=== Sanitization Complete ===')
    print(f'Total HTML tags/fragments removed: {total_removed}')
    
    return 0


if __name__ == '__main__':
    exit(main())
