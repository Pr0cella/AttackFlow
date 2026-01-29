# Unified Kill Chain Visualizer

A JavaScript component that visualizes MITRE ATT&CK techniques mapped to the Unified Kill Chain framework. Supports all ATT&CK domains: **Enterprise**, **Mobile**, and **ICS**.

![Version](https://img.shields.io/badge/version-2.4.1-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- 🎯 **Unified Kill Chain Mapping** - Techniques mapped to IN → THROUGH → OUT phases
- 🌐 **Multi-Domain Support** - Enterprise, Mobile, and ICS ATT&CK matrices
- 📊 **Navigator Layer Import** - Import MITRE ATT&CK Navigator JSON layers
- 🎨 **Configurable Colors** - Fully customizable color scheme
- 📱 **Responsive Design** - Works on desktop and mobile
- 🔗 **MITRE Links** - Click techniques to open ATT&CK documentation
- 📈 **Statistics** - Real-time technique counts per phase
- 🗜️ **Compact Mode** - Toggle between full and compact views

### New in v2.4.0 - Phase Item Metadata

- 📝 **Rich Metadata** - Add comments, hyperlinks, observables to any assigned item
- 🔒 **CVE/CVSS Support** - Link items to specific vulnerabilities with CVSS scores
- 🎚️ **Confidence Levels** - Rate items as Unclassified/Low/Medium/High/Critical
- 🎨 **Visual Indicators** - Color-coded ribbons and icons show metadata at a glance
- 🛡️ **Input Security** - All user input validated, sanitized, and escaped
- 📊 **Enhanced Exports** - JSON and CSV include full metadata

### v2.3.0 - Attack Chain Editor

- 🖱️ **Drag & Drop** - Drag techniques, CAPECs, and CWEs directly onto kill chain phases
- 📚 **Full ATT&CK Library** - 898 techniques with descriptions, mitigations, platforms, and more
- 🔍 **Rich Detail Panel** - View complete technique info including detection and mitigations
- 🔗 **CAPEC/CWE Integration** - Link attack patterns and weaknesses to your kill chain
- 💾 **Save/Load Projects** - Export and import your custom attack chains as JSON
- ⚙️ **Centralized Config** - All colors and settings in `config.js`
- 📖 **Usage Guide** - Built-in help modal with keyboard shortcut
- 🎨 **Distinct Phase Colors** - IN (green), THROUGH (cyan), OUT (red)

## Quick Start

### Basic Usage

```html
<div id="kill-chain"></div>
<div id="stats-bar"></div>

<script src="kill-chain-visualizer.js"></script>
<script>
    const viz = new KillChainVisualizer('kill-chain', 'stats-bar');
    
    viz.setTechniques({
        'T1566': 'Phishing',
        'T1059': 'Command and Scripting Interpreter',
        'T1486': 'Data Encrypted for Impact'
    });
</script>
```

### Import Navigator Layer

```javascript
// Load from ATT&CK Navigator JSON export
fetch('layer.json')
    .then(r => r.json())
    .then(layer => {
        const techniques = viz.parseNavigatorLayer(layer);
        viz.setTechniques(techniques);
    });
```

## API Reference

### Constructor

```javascript
new KillChainVisualizer(containerId, statsId, options?)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `containerId` | string | ID of the container element for the visualization |
| `statsId` | string | ID of the container for statistics bar |
| `options` | object | Optional configuration object |
| `options.colors` | object | Custom color configuration |

### Methods

| Method | Description |
|--------|-------------|
| `setTechniques(techniques)` | Set techniques to visualize (object: `{id: name}`) |
| `parseNavigatorLayer(json)` | Parse ATT&CK Navigator layer JSON, returns techniques object |
| `expandAll()` | Expand all phases |
| `collapseAll()` | Collapse all phases |
| `toggleCompactMode()` | Toggle compact mode (ID only vs ID + name) |
| `showOnlyActive()` | Hide phases with no techniques |
| `resetView()` | Reset to default view |
| `setColors(colors)` | Update color configuration |
| `highlightTechniques(ids[])` | Highlight specific techniques |
| `clearHighlights()` | Remove all highlights |
| `exportData()` | Export current state as JSON |
| `getMitreAttackUrl(techId)` | Get MITRE ATT&CK URL for a technique |
| `detectDomain(techId)` | Detect domain (enterprise/mobile/ics) from technique ID |

### Color Configuration

```javascript
const viz = new KillChainVisualizer('container', 'stats', {
    colors: {
        phaseIn: '#6b7280',      // IN phase accent
        phaseThrough: '#78716c', // THROUGH phase accent
        phaseOut: '#64748b',     // OUT phase accent
        bgDark: '#1a1a1a',       // Page background
        bgCard: '#242424',       // Card background
        bgPhase: '#2d2d2d',      // Phase background
        textPrimary: '#e5e5e5',  // Primary text
        textSecondary: '#a3a3a3', // Secondary text
        borderColor: '#404040',  // Borders
        accent: '#71717a'        // Accent color
    }
});
```

## Unified Kill Chain Phases

### IN (Initial Foothold)
- Reconnaissance
- Resource Development
- Delivery
- Social Engineering
- Exploitation
- Persistence
- Defense Evasion
- Command & Control

### THROUGH (Network Propagation)
- Pivoting
- Discovery
- Privilege Escalation
- Execution
- Credential Access
- Lateral Movement

### OUT (Action on Objectives)
- Collection
- Exfiltration
- Impact
- Objectives

## Domain Support

| Domain | Technique Format | Example |
|--------|-----------------|---------|
| Enterprise | T1xxx | T1566, T1059 |
| Mobile | T1xxx (specific ranges) | T1418, T1430 |
| ICS | T0xxx | T0800, T0879 |

Visual indicators:
- Enterprise: Default styling
- Mobile: Green left border
- ICS: Brown left border

## Files

```
├── index.html                # Attack Chain Editor (main app)
├── demo.html                 # Interactive demo with scenarios
├── demo-advanced.html        # Advanced mode with manual mapping
├── demo-capec-test.html      # CAPEC integration demo
├── kill-chain-visualizer.js  # Core JavaScript component
├── config.js                 # Centralized configuration (colors, version)
├── README.md                 # This file
├── CHANGELOG.md              # Version history
├── TASKS.md                  # Planned features
├── scripts/
│   ├── extract-attack.py     # ATT&CK STIX bundle parser
│   └── extract-data.py       # CAPEC/CWE XML parser
└── resources/
    ├── attack-techniques.json  # Full ATT&CK technique library (898)
    ├── capec-library.json      # CAPEC patterns
    ├── cwe-library.json        # CWE weaknesses
    ├── capec-to-technique.json # CAPEC → ATT&CK mappings
    ├── cwe-to-capec.json       # CWE → CAPEC mappings
    ├── enterprise.json         # Enterprise Navigator layer
    ├── mobile.json             # Mobile Navigator layer
    ├── ics.json                # ICS Navigator layer
    └── *-attack-18.1.json      # ATT&CK STIX bundles (source data)
```

## Browser Support

- Chrome 80+
- Firefox 75+
- Safari 13+
- Edge 80+

## License

MIT License - See LICENSE file for details.

## Related Links

- [MITRE ATT&CK](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [Unified Kill Chain](https://www.unifiedkillchain.com/)
- [CAPEC](https://capec.mitre.org/) - Common Attack Pattern Enumeration
- [CWE](https://cwe.mitre.org/) - Common Weakness Enumeration
