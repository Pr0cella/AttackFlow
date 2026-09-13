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
    project_dir = project_dir.resolve()
    allowed_relative_roots = (Path('resources'), Path('frameworks/ATTCK'))
    allowed_roots = tuple((project_dir / root).resolve() for root in allowed_relative_roots)
    files = set()
    for pattern in patterns:
        relative_pattern = Path(pattern)
        if (not pattern or '\0' in pattern or relative_pattern.is_absolute()
                or '..' in relative_pattern.parts):
            raise ValueError(f'Unsafe sanitization path: {pattern!r}')
        if not any(relative_pattern.parts[:len(root.parts)] == root.parts
                   for root in allowed_relative_roots):
            raise ValueError(f'Sanitization path is outside allowed roots: {pattern!r}')

        matches = glob.glob(str(project_dir / relative_pattern), recursive=True)
        for match in matches:
            p = Path(match)
            relative_match = p.relative_to(project_dir)
            current = project_dir
            for part in relative_match.parts:
                current /= part
                if current.is_symlink():
                    raise ValueError(f'Symlinked sanitization path is not allowed: {p}')

            resolved = p.resolve()
            if not any(resolved == root or root in resolved.parents for root in allowed_roots):
                raise ValueError(f'Sanitization path is outside allowed roots: {p}')
            if resolved.is_file() and resolved.suffix.lower() == '.json':
                files.add(resolved)
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
    try:
        json_files = resolve_paths(project_dir, patterns)
    except ValueError as exc:
        print(f'  Error: {exc}')
        return 1

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
