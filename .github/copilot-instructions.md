# Copilot Instructions — AttackFlow

## Architecture

Zero-dependency vanilla JS browser app for mapping MITRE ATT&CK / CAPEC / CWE to Unified Kill Chain phases. No build step, no bundler, no module system.

- **`index.html`** (5,700+ lines) — monolith containing all HTML, embedded CSS, and inline JS. The JS block (~lines 2624–5775) is organized into banner-delimited sections (`// ====...====`). Preserve these section markers.
- **`explorer.html`** — standalone Relationship Explorer view (ATT&CK ↔ CAPEC ↔ CWE ↔ Mitigations).
- **`config.js`** — `CONFIG` object (version, source paths, colors, theme presets) plus `resolveTheme()` / `applyConfigColors()`. Version lives here as `CONFIG.version`.
- **`kill-chain-visualizer.js`** — legacy read-only `KillChainVisualizer` class for Navigator layers. Not loaded by the main editor.

Everything runs in **global scope**. All mutable state lives in a single `state` object. DOM rendering uses `innerHTML` template strings.

## Key Conventions

- **Phase keys** use `SUPER:phase-name` format: `IN:reconnaissance`, `THROUGH:lateral-movement`, `OUT:exfiltration`.
- **Assignment objects**: `{ id, instanceId, metadata }` — IDs like `itm-{base36ts}-{random}`, groups like `grp-{base36ts}-{random}`.
- **`renderAll()`** is the canonical full re-render. Call it after any state mutation.
- **Security is mandatory**: all user input goes through `InputSecurity.escapeHtml()` / `InputSecurity.sanitize()` / `InputSecurity.validators`. Never insert unsanitized strings into DOM via `innerHTML`. See `FINDINGS.md` for past XSS findings (IDs `KCE-SEC-00X`).
- **CSV export** prefixes cells starting with `=`, `+`, `@` with `'` to prevent formula injection.
- **URLs** are validated against `http://` / `https://` allowlist only.
- **External links** must use `rel="noopener noreferrer"` to prevent tabnabbing.

## Data Pipeline

```
frameworks/ATTCK/*.json  ──┐
frameworks/CAPEC/*.xml   ──┤── Python scripts ──► resources/*.json ──► browser fetch() ──► state.library
frameworks/CWE/*.xml     ──┘
```

- `scripts/extract-attack.py` — STIX bundles → `resources/attack-techniques.json`
- `scripts/extract-data.py` — CAPEC/CWE XML → `resources/capec-full.json`, `cwe-full.json`, mapping files. Uses `defusedxml` (optional) to prevent XXE.
- `scripts/sanitize-json.py` — strips HTML from all JSON in `resources/`. Run after extraction.
- **`resources/` files are generated** — never edit them directly; regenerate via the scripts.

## JSON Export Schema

Schema name: `killchain-export-lite`. Structure:
```json
{
  "version": "2.5.3", "schema": "killchain-export-lite",
  "assignments": {
    "IN:reconnaissance": {
      "techniques": [{ "id": "T1595", "metadata": { "score": "high", "confidence": 85, "cves": [{"id":"CVE-2024-1234","score":"9.8"}], "observables": [], "hyperlinks": [], "comments": "" } }],
      "capecs": [], "cwes": []
    }
  }
}
```

Metadata fields — `score` (unclassified/low/medium/high/critical), `confidence` (0–100), `comments`, `cves[]`, `hyperlinks[]`, `observables[]` (types: ipv4-addr, domain-name, url, md5, sha1, sha256, etc.).

## Testing

- **Import validation suite**: `tests/import-validation/test-runner.html` — runs in-browser. Includes valid imports, schema-rejection tests (`reject-*.json`), and security bypass vectors (`bypass-*.json`).
- **Demo files**: `examples/demo.json` (full metadata), `examples/grouping-demo.json` (grouped ransomware TTPs).
- Test across Chrome, Firefox, Safari — no automated CI.

## DevOps

- `scripts/backup.sh` — creates timestamped copy in `old/` as `AttackFlow_v{ver}_{date}`.
- `scripts/deploy.sh` — rsync to `/var/www/html/` with proper permissions.
- Version is dual-sourced: `CONFIG.version` in config.js and parsed at runtime from `CHANGELOG.md` header `## [x.y.z]`.
- Changelog follows **Keep a Changelog** format: `## [x.y.z] - YYYY-MM-DD` with `### Added/Changed/Fixed/Removed` sections.

## When Modifying Code

1. The inline JS in `index.html` is sectioned — locate the right section banner before editing.
2. Any new user-facing text must be escaped via `InputSecurity`. Check `FINDINGS.md` for context.
3. Theme changes go in `config.js` theme presets; runtime theme uses CSS variables set by `applyConfigColors()`.
4. New entity types or phases must update `KILL_CHAIN` / `ALL_PHASES` constants and `renderKillChain()`.
5. State changes → call `renderAll()`. localStorage keys: `af-theme-mode`, `af-compact-mode`.
6. Python scripts use only stdlib + optional `defusedxml` — no pip dependencies.
