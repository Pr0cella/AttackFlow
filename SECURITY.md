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

The protections cover the current attack surface of a **static client-side application**. They do **not** constitute a production-hardened security posture. Notable limitations:

- No Content Security Policy (CSP) headers are set — this depends on the hosting server configuration.
- No Subresource Integrity (SRI) — there are no external CDN dependencies, but `config.js` and `stix-config.js` are loaded via `<script src>`.
- No automated security CI/CD pipeline — testing is manual and browser-based.
- `localStorage` is used for theme and compact mode preferences only (no sensitive data).

---

*AttackFlow is maintained as an open-source project. Contributions that improve security are always welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).*
