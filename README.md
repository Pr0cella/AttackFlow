# KillChainEdit - Kill Chain Editor & Visualizer

Interactive editor for mapping MITRE ATT&CK techniques, CAPEC attack patterns, and CWE weaknesses to the Unified Kill Chain framework.

![Version](https://img.shields.io/badge/version-2.4.1-blue)
![License](https://img.shields.io/badge/license-Apache%202.0-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

![Preview](preview.png)

## Features

- **Vanilla JavaScript** — No external dependencies, runs in any browser
- **Unified Kill Chain** — Map entities to IN → THROUGH → OUT phases
- **Multi-Domain ATT&CK** — 898 techniques across Enterprise, Mobile, and ICS
- **CAPEC/CWE Integration** — Link attack patterns and weaknesses
- **Drag & Drop** — Intuitive assignment of entities to phases
- **Rich Metadata** — Comments, hyperlinks, observables, CVE/CVSS references
- **Score & Confidence** — Rate items by severity and assessment confidence
- **Visual Indicators** — Color-coded ribbons and metadata icons
- **Import/Export** — JSON and CSV with full metadata support
- **Navigator Layers** — Import ATT&CK Navigator JSON exports

![Relations View](relations.png)

## Quick Start

1. Clone or download this repository
2. Open `index.html` in a browser, or deploy to a web server
3. Browse techniques in the left sidebar
4. Drag items onto kill chain phases
5. Click items in the diagram to add metadata
6. Export your attack chain as JSON or CSV

## Project Structure

```
├── index.html                  # Main application
├── config.js                   # Centralized configuration
├── kill-chain-visualizer.js    # Core visualization component
├── scripts/
│   ├── extract-attack.py       # ATT&CK STIX bundle parser
│   └── extract-data.py         # CAPEC/CWE XML parser
└── resources/
    ├── attack-techniques.json  # ATT&CK library (898 techniques)
    ├── capec-full.json         # CAPEC attack patterns
    ├── cwe-full.json           # CWE weaknesses
    ├── capec-to-technique.json # CAPEC → ATT&CK mappings
    ├── cwe-to-capec.json       # CWE → CAPEC mappings
    ├── kill-chain-mappings.json# Technique → Phase mappings
    ├── enterprise.json         # Enterprise Navigator layer
    ├── mobile.json             # Mobile Navigator layer
    └── ics.json                # ICS Navigator layer
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
| **CVE-ID** | Vulnerability reference (e.g., CVE-2024-12345) |
| **CVSS Vector** | CVSS 3.1 vector string |
| **Comments** | Free-text notes |
| **Hyperlinks** | External references with labels |
| **Observables** | Threat indicators (IPs, hashes, domains, etc.) |

## Data Sources

- [MITRE ATT&CK](https://attack.mitre.org/) — Adversarial tactics and techniques
- [CAPEC](https://capec.mitre.org/) — Common Attack Pattern Enumeration
- [CWE](https://cwe.mitre.org/) — Common Weakness Enumeration
- [Unified Kill Chain](https://www.unifiedkillchain.com/) — Attack phase framework

## Updating Data

Download the latest STIX bundles and run the extraction scripts:

```bash
cd resources
# Download ATT&CK STIX bundles from https://github.com/mitre-attack/attack-stix-data

cd ../scripts
python3 extract-attack.py    # Parse ATT&CK techniques
python3 extract-data.py      # Parse CAPEC/CWE (requires XML files)
```

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.
