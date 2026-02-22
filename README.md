# ![](favicon.ico) AttackFlow - Kill Chain Editor & Visualizer

An editor for creating enriched Cyber Kill Chain assessments by mapping MITRE ATT&CK, CAPEC, CWE & STIX 2.1 objects to the Unified Kill Chain framework and enriching phase parts with additional data. Visualize and assess complex attack scenarios easily by combining flexible TTPs with atomic IOCs and forensic data.

### Work in progress 

![Version](https://img.shields.io/badge/version-2.9.0-blue)
[![MITRE ATT&CK® 18](https://img.shields.io/badge/MITRE%20ATT%26CK®-v18-red)](https://attack.mitre.org/versions/v18/)
![License](https://img.shields.io/badge/license-Apache%202.0-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

## Features

### Implementation
- **Vanilla CSS & JavaScript** 
    - Core modules have no external dependencies or any third party libraries.
    - No build step and no package-manager runtime dependencies, runs in any browser
- **Offline Operation** 
    - No CDN or remote runtime requests; module dependencies are vendored locally and modules can be disabled.
    - Can be used offline in a browser by opening the `index.html` file. 
    - Offline module communication is achieved via hardened IPC channels only allowed in `file://` protocol context. Disabled by default in `config.js`. See [Local iframe IPC](#Local-iframe-IPC) for detailed information.
    - In case the IPC Bridge is disabled or fails to initialise the application falls back to manual import of the `resources` directory
- **STIX Visualizer Module** — Modular Visualization of STIX Bundles
    - Visualizer Module can be disabled via `config.js` flag. See [STIX Visualizer Toggle](#STIX-Visualizer-Toggle)
    - For a list of bundled runtime dependencies used by the visualizer see: [STIX Visualizer Dependencies](#Bundled-STIX-Visualizer-Dependencies)
- **Lightweight Theming Engine** 
    - Toggle configurable light/dark theme with shared settings (via `config.js`) across views 

### Resource Corpus
- **Unified Kill Chain** — Map entities to IN → THROUGH → OUT phases
- **Multi-Domain ATT&CK** — 898 techniques across Enterprise, Mobile, and ICS
- **CAPEC/CWE Integration** — Link attack patterns and weaknesses
- **STIX 2.1 Objects** — Create and manage all 18 SDO types plus custom objects

### Import & Sharing
- **Import/Export** — JSON sharing, CSV exports (with mitigation rows), and STIX 2.1 bundle exports (with mitigations and relationships)
- **STIX Bundle Export** — Export assigned techniques as `attack-pattern` SDOs with mitigations as `course-of-action` SDOs and `mitigates` SROs, using deterministic UUIDv5 IDs
- **STIX Bundle Import** — Import multiple STIX 2.1 bundles to extract SDOs with full property preservation (Configurable auto-clear on bundle or kill chain import via `config.js`). Aggregates data by default.
- **Navigator Layers** — Import ATT&CK Navigator JSON exports

### Editor
- **Drag & Drop** — Intuitive assignment of entities to phases
- **Grouping** — Organize items into collapsible named groups within phases
- **Rich Metadata** — Comments, hyperlinks, observables, multi-CVE/CVSS references
- **Score & Confidence** — Rate items by severity and assessment confidence
- **Compact Mode** — Dense ID-only tags to fit large kill chains, collapsible sidebar & hiding empty phases
- **STIX Editor** — Edit all spec-defined fields per SDO type with vocabulary dropdowns

![Preview](/docs/images/preview.png)

#### Kill Chain Relationships
- **Browsable Mapping Explorer** — Browse kill chain related CAPEC → CWE → ATT&CK → Mitigation patterns per Phase in a dedicated view with phase detail modal dialogs

![Relations View](/docs/images/relations.png)

### Relationship Explorer 
- **Integrated Resource Corpus Explorer** Explore & search the complete corpus of related ATT&CK ↔ CAPEC ↔ CWE ↔ Mitigations patterns
- **Technique Cross-References** — Item relationships & techniques referenced by ID in descriptions link to the Relationship Explorer

![Explorer View](/docs/images/explorer.png)

### STIX Composer
#### Interactive STIX Object/Bundle Editor & Visualizer
![Composer View](/docs/images/visualizer.png)

## Quick Start

The Relationship Explorer is a second main view that lets you investigate ATT&CK ↔ CAPEC ↔ CWE ↔ Mitigations without assigning items first. Use the header navigation to switch views, click any node to load its details in the right panel, and open mitigation links to explore cross‑framework relationships in context.

1. Clone or download this repository
2. Open `index.html` in a browser, or deploy to a web server
3. Browse techniques in the left sidebar
4. Drag items onto kill chain phases
5. Click items in the diagram to add metadata
6. Switch to the **STIX** tab to create or import STIX 2.1 objects
7. Click **Import STIX Bundle** to load a STIX 2.1 bundle JSON (e.g., Operation Midnight Eclipse bundle)
8. Use the header navigation to switch to Relationship Explorer
9. Toggle light/dark theme in the header as needed
10. Enable compact mode for dense layouts when needed
11. Export your attack chain as JSON, CSV, or STIX Bundle

## Usecases

See the usecases [README](docs/Usecases/README.md) for details.

1. Incident Response TTP Mapping
2. Red Team Operation Planning
3. Blue Team Defense Posture Assessment
4. CTI Report Building
5. Vulnerability-Centric Risk Analysis
6. Purple Team Exercise Planning and Debrief
7. Ransomware Playbook Documentation
8. Supply Chain Attack Analysis

## Testing

- **Demo kill chain**: Import [examples/demo.json](examples/demo.json) to exercise all metadata fields (CVE/CVSS, observables, links, confidence) and multi-phase coverage.
- **Grouping demo**: Import [examples/grouping-demo.json](examples/grouping-demo.json) for a ransomware-focused TTP mapping that showcases grouping.
- **STIX demo**: Import [examples/stix-demo.json](examples/stix-demo.json) for a full STIX 2.1 showcase with all 19 SDO types across UKC phases.
- **STIX bundle**: Import [examples/Operation-Midnight-Eclipse-stix-bundle.json](examples/Operation-Midnight-Eclipse-stix-bundle.json) via the STIX tab's "Import STIX Bundle" button to test STIX bundle parsing (25 SDOs across 19 types + 18 phase-relationship SROs).
## Project Structure

```
├── index.html                      # Main application
├── explorer.html                   # Relationship Explorer view
├── stix-builder.html               # STIX Composer (STIX 2.1 Bundle Creator & Visualizer)
├── stix-builder.config.js          # STIX Composer configuration & STIX 2.1 spec reference
├── config.js                       # Centralized configuration 
│                                   # (paths, colors, imports, settings)
├── stix-config.js                  # STIX 2.1 SDO type definitions and vocabularies
├── examples/*                      # Sample kill chain exports
├── docs/
│   └── Usecases/*                  # Usecase documentation and sample exports
├── scripts/
│   ├── extract-attack.py           # ATT&CK STIX bundle parser
│   ├── extract-data.py             # CAPEC/CWE XML parser
│   └── sanitize-json.py            # Remove markup from data files
├── frameworks/                     # Source data (configure paths in config.js)
│   ├── ATTCK/
│   │   ├── ENTERPRISE.json         # Enterprise ATT&CK STIX bundle
│   │   ├── MOBILE.json             # Mobile ATT&CK STIX bundle
│   │   └── ICS.json                # ICS ATT&CK STIX bundle
│   ├── CAPEC/
│   │   ├── DOMAINS.xml             # CAPEC domains view
│   │   └── MECHANISMS.xml          # CAPEC mechanisms view
│   └── CWE/
│       ├── ALL.xml                 # Full CWE list
│       ├── HARDWARE.xml            # CWE hardware design weaknesses
│       └── SOFTWARE.xml            # CWE software development weaknesses
└── resources/                      # Generated data (do not edit directly)
    ├── attack-techniques.json      # ATT&CK library (898 techniques)
    ├── capec-full.json             # CAPEC attack patterns
    ├── cwe-full.json               # CWE weaknesses
    ├── capec-to-technique.json     # CAPEC → ATT&CK mappings
    ├── cwe-to-capec.json           # CWE → CAPEC mappings
    ├── Nav_Layer_ENTERPRISE.json   # Enterprise Navigator layer
    ├── Nav_Layer_MOBILE.json       # Mobile Navigator layer
    └── Nav_Layer_ICS.json          # ICS Navigator layer
```

## Unified Kill Chain Phases

| Phase | Stages |
|-------|--------|
| **IN** (Initial Foothold) | Reconnaissance, Resource Development, Delivery, Social Engineering, Exploitation, Persistence, Defense Evasion, Command & Control |
| **THROUGH** (Network Propagation) | Pivoting, Discovery, Privilege Escalation, Execution, Credential Access, Lateral Movement |
| **OUT** (Action on Objectives) | Collection, Exfiltration, Impact, Objectives |

## Metadata Fields

Each assigned item supports:

| Field | Description |
|-------|-------------|
| **Score** | Severity rating: Unclassified, Low, Medium, High, Critical |
| **Confidence** | Assessment confidence: 0% (Unknown) to 100% (High) |
| **CVE-ID(s)** | Vulnerability references (e.g., CVE-2024-12345) |
| **CVE Score** | Optional per-CVE score (0.0–10.0) |
| **CVSS Vector** | Optional per-CVE CVSS 3.1 vector string |
| **Comments** | Free-text notes |
| **Hyperlinks** | External references with labels |
| **Observables** | Threat indicators (IPs, hashes, domains, etc.) |

## Data Sources

- [MITRE ATT&CK](https://attack.mitre.org/) — Adversarial tactics and techniques
- [MITRE ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator)
- [CAPEC](https://capec.mitre.org/) — Common Attack Pattern Enumeration
- [CWE](https://cwe.mitre.org/) — Common Weakness Enumeration
- [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/) — Structured Threat Information Expression
- [Unified Kill Chain](https://www.unifiedkillchain.com/) — Attack phase framework

## Security

[SECURITY POLICY](SECURITY.md)

AttackFlow implements defense-in-depth protections and adheres to security by design principles. 
(Note: Application NOT production ready yet - may still contain vulnerable components) 
Please do not hesitate to create an issue / pull request or contact me directly if you find any security related issues or have suggestions for further improving application security and mitigating exploitation scenarios. 

- **Input Blocking** — Dangerous characters (`` < > [ ] { } " ' ; -- ` ``) blocked at input level
- **Output Encoding** — All user-supplied values HTML-encoded before rendering
- **DOM-Safe Rendering** — Uses `textContent` and DOM APIs instead of `innerHTML`
- **Import Validation** — File size, item count, and pattern validation on imports
- **Sanitized Data** — Source data cleaned of embedded markup during extraction
- **XXE Protection** — Secure XML parsing with entity expansion disabled
- **CSV Safety** — Formula injection protection on exports

### Prototype Pollution Hardening

Import paths and JSON processing include explicit prototype pollution defenses:

- **Dangerous key blocklist** — `__proto__`, `constructor`, and `prototype` keys are rejected in parse/sanitize paths.
- **Safe JSON parsing** — untrusted JSON is parsed with a reviver that drops dangerous prototype keys.
- **Null-prototype accumulators** — sanitized object collectors use `Object.create(null)` for untrusted key maps.
- **Own-property checks** — import logic uses own-property guards for dynamic field copy to avoid inherited-property abuse.

### Local iframe IPC

AttackFlow includes a local-use IPC bridge between `index.html` (parent) and embedded `explorer.html` / `stix-builder.html` iframes. This allows using all features by simply opening the `index.html` file in a browser, letting the IPC bridge handle all data exchange between iframes. 

Note: Designed strictly for local, non-webserver usage (requires `file://` as protocol)

- **Purpose**: Theme synchronization and shared data handoff to reduce redundant iframe loading paths.
- **Scope**: Designed for local usage mode (requires `file://` protocol) and controlled by `CONFIG.ConfigIframeIPC.enableLocalIframeIPC`.
- **Transport**: Channel-only `MessageChannel` transport (no legacy request/response fallback path).
- **Session binding**: Per-iframe session nonce is required for channel messages.
- **Validation**: IPC message types/keys are allowlisted; unknown keys/types are rejected.
- **Shared payload safety**: `AF_SHARED_DATA` is schema-checked, cloned, and deep-frozen before use.
- **Containment**: Embedded iframes are sandboxed (`allow-scripts allow-same-origin allow-modals`).
- **Throttling**: Parent applies per-frame/per-request-type token-bucket rate limiting.
- **Resilience**: Parent bootstrap uses bounded timeout/retry/backoff; children detect terminal bootstrap failure and recover without legacy transport.

Configuration in `config.js`:

- `CONFIG.ConfigIframeIPC.enableLocalIframeIPC`
- `CONFIG.debugging.traceLocalIframeIPCLogs`
- `CONFIG.debugging.localIframeIPCRateLimit.enabled`
- `CONFIG.debugging.localIframeIPCRateLimit.refillPerSecond`
- `CONFIG.debugging.localIframeIPCRateLimit.burst`
- `CONFIG.debugging.localIframeIPCBootstrap.timeoutMs`
- `CONFIG.debugging.localIframeIPCBootstrap.maxRetries`
- `CONFIG.debugging.localIframeIPCBootstrap.retryBaseDelayMs`
- `CONFIG.debugging.localIframeIPCBootstrap.retryBackoffMultiplier`
- `CONFIG.debugging.localIframeIPCBootstrap.maxRetryDelayMs`
- `CONFIG.debugging.localIframeIPCBootstrap.graceMs`

See [IPC API DOCS](docs/IPC_API-DOCS.md) for concise architecture and threat-model documentation.

### STIX Visualizer Toggle

The integrated STIX visualizer can be fully disabled via config:

- `CONFIG.visualizer.enabled = false`

When disabled, AttackFlow prevents the visualizer from loading and executing by not injecting its own visualizer assets and bundled third-party visualizer libraries.

### Bundled STIX Visualizer Dependencies

The [STIX visualizer](https://github.com/oasis-open/cti-stix-visualization)  is shipped as vendored local files (no CDN):

- RequireJS `2.3.6` (`stix-visualization/stix_visualizer/require.js`)
- RequireJS domReady plugin `2.0.1` (`stix-visualization/stix_visualizer/domReady.js`)
- vis-network (vendored build used by stix2viz; (`stix-visualization/stix_visualizer/stix2viz/visjs/vis-network.js`))
- stix2viz module (`stix-visualization/stix_visualizer/stix2viz/stix2viz/stix2viz.js`)

### Security Objectives
1. **No execution of untrusted content** from local or upstream data (MITRE JSON/XML, user-imported layers).
2. **Defensive rendering**: all UI output is treated as untrusted until sanitized & encoded.
3. **Safe file import/export** with integrity and injection-resistant outputs.
4. **Resilient parsing** of large/hostile XML/JSON inputs.
5. **Predictable standalone, offline operation** No CDN requests, remote resource retrievals or third party dependencies to protect against upstream supply-chain compromises.

## Updating Data

Download the latest framework data and run the extraction scripts:

```bash
# Download ATT&CK STIX bundles from https://github.com/mitre-attack/attack-stix-data
# Place in frameworks/ATTCK/ as ENTERPRISE.json, MOBILE.json, ICS.json

# Download CAPEC XML views from https://capec.mitre.org/data/
# Place in frameworks/CAPEC/ as DOMAINS.xml, MECHANISMS.xml

# Download CWE XML views from https://cwe.mitre.org/data/
# Place in frameworks/CWE/ as ALL.xml, SOFTWARE.xml, HARDWARE.xml

# Run extraction scripts
python3 scripts/extract-attack.py    # Parse ATT&CK techniques
python3 scripts/extract-data.py      # Parse CAPEC/CWE

# File paths are configurable in config.js under sources.*
# JSON sanitization paths are configurable in config.js under sanitize.paths
# Sanitization runs before and after parsing to keep source and generated files clean
```

## Installation

### For Installation on servers:
- Just drop the files on a webserver, (optionally) set CSP headers and navigate to index.html.

### For local use (in a browser):
1. Set `CONFIG.ConfigIframeIPC.enableLocalIframeIPC` to `true` and open the `index.html` file in a web browser.
2. Upload the `resources/` directory as instructed to populate the framework database and use all application features.

## Contributing & Reporting Issues

See the [CONTRIBUTING Guide](CONTRIBUTING.md) for details on how to contribute.


See the [SECURITY POLICY](SECURITY.md) for details on how to report vulnerabilities.


## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.


---

## Third-Party Notices

AttackFlow uses data and references from the following third-party sources:

- MITRE ATT&CK: https://attack.mitre.org/
- MITRE ATT&CK Navigator: https://github.com/mitre-attack/attack-navigator
- CAPEC: https://capec.mitre.org/
- CWE: https://cwe.mitre.org/
- STIX 2.1: https://oasis-open.github.io/cti-documentation/
- STIX Visualizer (stix2viz): https://github.com/oasis-open/cti-stix-visualization
- Unified Kill Chain: https://www.unifiedkillchain.com/
- FontAwesome: https://github.com/FortAwesome/Font-Awesome

MITRE and ATT&CK are trademarks of The MITRE Corporation. This project is not
affiliated with or endorsed by MITRE. CAPEC and CWE are maintained by MITRE.
Use of these frameworks is subject to the applicable terms and usage guidelines
published by their respective owners.

AttackFlow is not affiliated with or endorsed by the Center for Threat-Informed
Defense (CTID) or the CTID "Attack Flow" project.
