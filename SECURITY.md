# Security Policy — AttackFlow

## Project Status Disclaimer

AttackFlow is a **showcase / demonstration project** developed in spare time. While it holds itself to strict security standards and applies defense-in-depth principles throughout, it is **neither designed nor fully ready for production use**. Security issues may still exist. This status may change in the future.

Use at your own risk. No warranty is provided.

---

## Reporting Vulnerabilities

If you discover a security issue, please report it through one of the following channels:

| Severity | Channel |
|----------|---------|
| **Low / Medium** | [GitHub Issues](https://github.com/Pr0cella/AttackFlow/issues) — use the `security` label |
| **Critical / Urgent** | Report via [GitHub Disclosure](https://github.com/Pr0cella/AttackFlow/security)

Please include:
- A clear description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- The version of AttackFlow affected (see `config.js` or `CHANGELOG.md`)

We will acknowledge receipt as soon as possible and aim to provide a fix or mitigation promptly. Responsible disclosure is appreciated — please allow reasonable time for a patch before public disclosure.

---

## Threat Model

AttackFlow is a **client-side single-page application** that runs entirely in the browser. There is no backend, no authentication, and no server-side state. The primary threat surface is:

| Threat | Vector | Impact |
|--------|--------|--------|
| **Cross-Site Scripting (XSS)** | Malicious content in imported JSON/STIX files, navigator layers, or user input rendered via `innerHTML` | Code execution in the user's browser session |
| **Formula Injection** | Crafted entity names or metadata exported to CSV and opened in a spreadsheet application | Arbitrary formula execution in Excel/Sheets |
| **Prototype Pollution** | Malformed JSON payloads with `__proto__` or `constructor` keys | Potential state corruption |
| **XML External Entity (XXE)** | Malicious CAPEC/CWE XML processed by the Python extraction scripts | Local file disclosure on the build machine |
| **Denial of Service** | Extremely large import files or deeply nested JSON | Browser tab hang or crash |
| **Tabnabbing** | External links opened via `target="_blank"` without `rel` protections | Phishing via `window.opener` |

Since there is no server component, threats like SQL injection, SSRF, or authentication bypass do not apply.

---

## Security Principles

### 1. Sanitize Everything

All user input — whether typed, pasted, dropped, or imported from files — passes through sanitization before it reaches the DOM or application state.

- **Output encoding:** Every dynamic value inserted into `innerHTML` is escaped via `InputSecurity.escapeHtml()` (for element content) or `InputSecurity.sanitizeAttr()` (for attribute values).
- **Input guards:** Five document-level event listeners (`keydown`, `beforeinput`, `paste`, `drop`, `input`) block dangerous characters (`< > { } [ ] ; \` " '`) in real time across all text inputs.
- **Storage sanitization:** Text entering metadata fields is stripped, normalized, and truncated before being stored in `state`.

### 2. Distrust All Imported Data

Every external data source is treated as untrusted:

- **JSON resources** fetched at startup have all angle brackets replaced recursively (`stripAngleBracketsFromJson`).
- **Kill chain imports** go through a multi-stage pipeline: JSON parse → structural validation → recursive string sanitization (strips `<script>`, event handlers, SQL comments, control chars) → ID format validation → enum clamping → count limits.
- **STIX bundle imports** are validated against the STIX 2.1 spec, type-checked, size-limited, and individually sanitized before entering the library.
- **Navigator layer imports** validate technique ID format, enforce file size limits (25 MB), and cap technique count (5,000).

### 3. Enforce Strict Limits

All import paths enforce hard limits to prevent resource exhaustion:

- File size caps (5 MB for kill chains, 25 MB for navigator layers, 10 MB for STIX bundles)
- Per-phase assignment caps, observable counts, hyperlink counts
- String length truncation on all text fields
- Maximum object counts for STIX bundle imports

### 4. Validate URLs and External Links

- Only `http://` and `https://` URLs are permitted. `javascript:`, `data:`, and other schemes are rejected.
- All external links use `rel="noopener noreferrer"` to prevent tabnabbing.

### 5. Protect Exported Data

- CSV exports prefix cells starting with `=`, `+`, `-`, `@`, `\t`, or `\r` with a single quote (`'`) to prevent formula injection in spreadsheet applications.

### 6. Secure the Build Pipeline

- Python extraction scripts use `defusedxml` (when available) to prevent XXE attacks during CAPEC/CWE XML parsing.
- The `sanitize-json.py` script strips residual HTML from all generated JSON in `resources/`.
- Scripts use only the Python standard library — no third-party pip dependencies beyond the optional `defusedxml`.

---

## Scope of Security Measures

These protections cover the current attack surface of a **static client-side application**. They do **not** constitute a production-hardened security posture. Notable limitations:

- No Content Security Policy (CSP) headers are set — this depends on the hosting server configuration.
- No Subresource Integrity (SRI) — there are no external CDN dependencies, but `config.js` and `stix-config.js` are loaded via `<script src>`.
- No automated security CI/CD pipeline — testing is manual and browser-based.
- `localStorage` is used for theme and compact mode preferences only (no sensitive data).

---

*AttackFlow is maintained as an open-source project. Contributions that improve security are always welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).*
