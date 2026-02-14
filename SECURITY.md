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

## Scope of Security Measures

The protections cover the current attack surface of a **static client-side application**. A comprehensive security audit was completed on 2026-02-15 (see [SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md)). Notable security measures:

### ✅ Implemented Security Controls
- **Input Sanitization:** Comprehensive `InputSecurity` class with HTML and attribute escaping
- **DOM XSS Prevention:** All user input and external data properly escaped before rendering
- **CSV Formula Injection Prevention:** Export functions sanitize dangerous formula characters
- **Tabnabbing Protection:** All external links use `rel="noopener noreferrer"`
- **URL Validation:** Scheme allowlisting (HTTP/HTTPS only) for external URLs
- **Entity ID Validation:** Format validation before URL construction
- **Content Security Policy:** CSP headers present (with `unsafe-inline` for single-file architecture)
- **Security Headers:** X-Frame-Options and X-XSS-Protection configured

### ⚠️ Known Limitations
- CSP includes `'unsafe-inline'` for script-src and style-src (necessary for single-file HTML architecture)
- No Subresource Integrity (SRI) — there are no external CDN dependencies
- No automated security CI/CD pipeline — testing performed manually
- `localStorage` is used for theme and compact mode preferences only (no sensitive data)
- File size limits not enforced on JSON imports (acceptable for local tool usage)

### 📊 Security Test Results
- 37/37 security tests passed (100% success rate)
- All DOM XSS vulnerabilities fixed
- CSV formula injection prevention verified
- Entity ID validation confirmed
- URL scheme restrictions validated

For detailed audit findings, see [SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md).

---

*AttackFlow is maintained as an open-source project. Contributions that improve security are always welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).*
