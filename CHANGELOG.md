# Changelog

All notable changes to the AttackFlow application are documented here.

This changelog also serves as a development context document for AI agents continuing this project.

---

## [2.4.2] - 2026-01-29

### Security - General Security Improvements

Security audit remediation implementing defense-in-depth protections across the application.

#### Input/Output Security
- Applied HTML output encoding to all dynamic content rendering
- Added shorthand utilities for consistent escaping throughout the codebase
- Strengthened input validation patterns for structured data fields

#### Import Protection
- Added file size limits for Navigator JSON imports (25 MB maximum)
- Implemented technique count limits (5,000 max) to prevent resource exhaustion
- Added string length validation for imported fields
- Added ID pattern validation to reject malformed import data

#### Data Layer Hardening
- Sanitized source data files to remove embedded markup and HTML artifacts
- Cleaned 1,700+ description fields containing formatting remnants
- Ensured data extraction produces clean, display-ready content
 - Sanitizer now encodes remaining angle brackets as &lt; and &gt;
 - Sanitizer covers resources/ and frameworks/ATTCK by default via config

#### External Resource Protection
- Hardened all external links with `target="_blank"` and `rel=\"noopener noreferrer\"`
- Prevents reverse tabnapping and referrer leakage attacks

#### XML Processing Security
- Migrated to secure XML parsing with entity expansion disabled
- Prevents XXE (XML External Entity) and billion laughs attacks

#### Export Safety
- Added formula injection protection for CSV exports
- Prefixes potential formula triggers to prevent spreadsheet exploits

#### Error Handling
- Sanitized error message display to prevent reflected content injection
- Error messages rendered safely without interpreting user input

#### Data Pipeline & Config
- Framework source paths moved under frameworks/ and made configurable in config.js
- Extraction scripts run sanitization before and after parsing
- JSON loader encodes angle brackets on read to prevent unencoded < or >

#### Deployment
- deploy.sh now skips files/directories ignored by .gitignore

#### Description Improvements
- Increased description length limits for ATT&CK techniques (3,000 chars)
- Increased detection and mitigation guidance limits (2,000 chars each)
- Increased CAPEC and CWE description limits (2,000 chars)
- Fuller context now available without truncation

### Added - UI Enhancements

#### Hide Empty Phases
- New **Hide Empty** button in kill chain view controls
- Hides phases with no assigned entities for a cleaner view
- Toggle on/off to focus on active phases

#### CVE Badge Display
- CVE-IDs now display as full badges on phase items (e.g., "CVE-2024-12345")
- Replaces the previous "V" indicator for better visibility

#### Changelog Modal
- Version number click now opens changelog in a modal dialog
- No longer opens external file in new tab
- Changelog content displayed in scrollable modal

#### Dynamic Version Loading
- Version number loaded dynamically from CHANGELOG.md
- Ensures UI always reflects current release version
- Used in JSON exports for schema versioning

#### Expanded Usage Guide
- Added Metadata & Enrichment section covering CVE, observables, and hyperlinks
- Added View Controls section with Hide Empty and Relationships view
- Reorganized Import & Export section with Navigator import info
- Updated Tips section with new feature hints

---

## [2.4.1] - 2026-01-29

### Changed - Score/Confidence Separation & Icon Visibility

Minor update clarifying the distinction between severity scoring and confidence assessment.

#### Score vs Confidence
- **Score** (renamed from Confidence): Color-coded severity indicator
  - Unclassified (gray), Low (green), Medium (yellow), High (orange), Critical (red)
  - Controls the left border ribbon color on phase items
- **Confidence** (NEW): Percentage-based assessment (0-100%)
  - 0 = Unknown (default)
  - 1-33% = Low confidence
  - 34-66% = Medium confidence  
  - 67-100% = High confidence
  - Interactive slider in metadata editor
  - Displayed as percentage badge on phase items

#### Improved Metadata Icon Visibility
- Increased icon size from 12×12px to 16×16px
- Increased font size from 7px to 10px
- Removed 0.7 opacity for full visibility
- Icons now displayed in a row below the item title (not inline)
- Added confidence percentage badge icon when set

#### Updated Data Model
```javascript
function createDefaultMetadata() {
    return {
        score: 'unclassified',    // Color-coded: unclassified|low|medium|high|critical
        confidence: null,          // Percentage: null (Unknown) or 1-100
        comments: '',
        cveId: '',
        cvssVector: '',
        hyperlinks: [],
        observables: []
    };
}
```

#### CSS Renames
- `data-confidence` → `data-score`
- `.confidence-legend` → `.score-legend`
- `.confidence-selector` → `.score-selector`
- `.confidence-option` → `.score-option`
- `CONFIDENCE_LEVELS` → `SCORE_LEVELS`

#### Export Updates
- CSV now includes both "Score" and "Confidence" columns
- JSON version bumped to 2.4.1

---

## [2.4.0] - 2026-01-29

### Added - Phase Item Metadata System

Major update adding rich metadata capabilities to assigned kill chain items.

#### Metadata Features
- **Comments**: Free-text notes for any assigned entity
- **CVE-ID**: Link to specific vulnerabilities (CVE-YYYY-NNNNN format)
- **CVSS Vector**: CVSS 3.1 vector strings with validation
- **Hyperlinks**: External references with label/URL pairs
- **Observables**: Structured threat indicators including:
  - IPv4/IPv6 addresses
  - File hashes (MD5, SHA1, SHA256)
  - Domain names and URLs
  - File names, malware names, threat actor names
- **Confidence Score**: 5-level rating (Unclassified, Low, Medium, High, Critical)

#### Visual Indicators
- **Confidence Ribbon**: Colored left border on phase items
  - Low (green), Medium (yellow), High (orange), Critical (red)
- **Background Tint**: Subtle color based on confidence level
- **Metadata Icons**: Small indicators showing presence of:
  - `V` - CVE reference
  - `O` - Observables
  - `L` - Hyperlinks
  - `C` - Comments
- **Confidence Legend**: Visual guide below stats bar

#### Input Security
- **InputSecurity utility**: Centralized validation, sanitization, escaping
- HTML escaping to prevent XSS attacks
- Regex validation for all structured fields (IPs, hashes, CVE, CVSS)
- Control character stripping and length limits
- All user input treated as unsafe by default

#### Dual-Panel Interaction
- **Left sidebar click**: Shows general entity info (read-only)
- **Central diagram click**: Opens metadata editor modal
- Clear separation between browsing and editing

#### Metadata Editor Modal
- Confidence level selector with visual indicators
- CVE-ID and CVSS vector fields with inline validation
- Comments textarea
- Dynamic hyperlink list (add/remove)
- Dynamic observable list with type selector
- Save/Cancel buttons
- Escape key and click-outside to close

#### Export Updates
- **JSON export**: Includes schema version (2.4.0), full metadata
- **CSV export**: Added Confidence, CVE, Comments columns
- Backward compatible import (migrates old format)

### Technical Context for Agents

#### Data Model
```javascript
// New assignment structure (replaces simple ID arrays)
{
  id: "T1595",
  metadata: {
    confidence: "high",           // unclassified|low|medium|high|critical
    comments: "Used in Q4 campaign",
    cveId: "CVE-2024-12345",
    cvssVector: "CVSS:3.1/AV:N/AC:L/...",
    hyperlinks: [{ label: "Report", url: "https://..." }],
    observables: [{ type: "ipv4-addr", value: "192.168.1.100" }]
  }
}
```

#### Key Functions
```javascript
InputSecurity.escapeHtml(str)       // XSS prevention
InputSecurity.sanitize(str, max)    // Clean user input
InputSecurity.validators.cveId(v)   // Validation functions
createDefaultMetadata()             // Empty metadata object
getAssignmentId(assignment)         // Extract ID from old/new format
getAssignmentMetadata(assignment)   // Extract metadata
findAssignment(phase, type, id)     // Find assignment object
updateAssignmentMetadata(...)       // Update metadata
openMetadataEditor(type, id, phase) // Show editor modal
saveMetadata()                      // Save with validation
```

---

## [2.3.0] - 2026-01-29

### Added - Unified Attack Chain Editor

Major update renaming `demo-editor.html` to `index.html` as the main application.

#### Centralized Configuration
- **New file**: `config.js` - Centralized color and settings configuration
  - Phase colors: IN (#10b981 emerald), THROUGH (#06b6d4 cyan), OUT (#ef4444 red)
  - Framework colors: ATT&CK (blue), CAPEC (purple), CWE (orange)
  - UI colors and display settings
  - `applyConfigColors()` function for runtime updates

#### UI/UX Polish
- **Export Dropdown** - JSON and CSV buttons consolidated into dropdown menu
- **Version Badge** - Clickable version link (v2.3.0) opens CHANGELOG.md
- **Usage Guide Modal** - Built-in help with 6 sections:
  - Getting Started, Drag & Drop, Kill Chain Phases
  - Filters & Views, Export Options, Tips
  - Opens via `?` help icon or programmatically
  - Closes on Escape key or click outside
- **Fixed Close Button** - Detail panel header uses flexbox, no more overlap
- **Brighter Phase Colors** - Distinct colors for IN/THROUGH/OUT (not framework colors)

#### ATT&CK STIX Bundle Parsing
- **New script**: `scripts/extract-attack.py` - Parses ATT&CK v18.1 STIX bundles
  - Extracts 898 techniques across Enterprise (691), Mobile (124), ICS (83)
  - Resolves 1,943 mitigation relationships
  - Links 522 sub-techniques to parent techniques
  - Outputs `resources/attack-techniques.json` with full metadata

- **New data file**: `resources/attack-techniques.json`
  - Complete technique library with: id, name, description, platforms, tactics
  - Sub-technique info with parent technique links
  - Mitigations (id, name, description) per technique
  - Detection guidance and external references
  - Version info from STIX bundles

#### Drag and Drop Support
- **Drag entities from sidebar** to kill chain phases
- All entity types supported: ATT&CK techniques, CAPECs, CWEs
- Visual feedback: items dim while dragging, phases highlight as drop targets
- Grab cursor on draggable items
- Auto-reassignment: dropping on new phase moves entity from previous phase
- Toast notifications confirm assignments

#### Enhanced Entity Display
- **Sidebar entity list improvements**:
  - ATT&CK: Shows ↳ indicator for sub-techniques, first tactic badge, platforms
  - Description preview tooltip on hover
  
- **Kill chain phase tags now show names**:
  - All three types (ATT&CK, CAPEC, CWE) display ID + name
  - Consistent max-width (200px) with ellipsis truncation
  - Prevents layout overflow for long names

#### Detail Panel Enhancements
- **ATT&CK technique details** when clicked:
  - Full description (truncated to 800 chars)
  - Attributes table: Domain, Platforms, Tactics, Parent technique, Version
  - Detection information (when available)
  - Mitigations list (up to 8) with tooltip descriptions
  - Related CAPECs from mappings
  - External references (up to 3)
  - Direct link to MITRE ATT&CK page

#### UI/UX Improvements
- All layers (ATT&CK, CAPEC, CWE) now visible by default
- Layer checkboxes properly synced with initial state
- `getTechniqueName()` now uses loaded technique library first
- Navigator import shows count of existing vs new techniques

### Technical Context for Agents

#### File Rename
- `demo-editor.html` → `index.html` (now main application entry point)

#### New Files
```
config.js                         # Centralized configuration (colors, version, settings)
scripts/extract-attack.py         # STIX parser, run to regenerate technique data
resources/attack-techniques.json  # 898 techniques with full metadata
```

#### Configuration System
```javascript
// config.js structure
const CONFIG = {
    version: '2.3.0',
    phases: { in: '#10b981', through: '#06b6d4', out: '#ef4444' },
    frameworks: { attack: '#3b82f6', capec: '#8b5cf6', cwe: '#f59e0b' },
    ui: { ... },
    display: { maxTagWidth: '200px', ... }
};
```

#### STIX Bundle Processing
- Reads: `resources/enterprise-attack-18.1.json`, `mobile-attack-18.1.json`, `ics-attack-18.1.json`
- Single-pass extraction for efficiency
- Relationship resolution maps mitigation and parent technique IDs to data

#### Drag & Drop Implementation
```javascript
// Global drag state
let dragData = { type: null, id: null };

// Key functions
handleDragStart(event, type, id)  // Sets drag data, adds visual feedback
handleDragEnd(event)              // Cleans up drag state
handleDragOver(event)             // Enables drop, highlights target
handleDragLeave(event)            // Removes highlight
handleDrop(event, phaseKey)       // Performs assignment
```

#### Entity Item Attributes
```html
<div class="entity-item attack" 
     draggable="true"
     ondragstart="handleDragStart(event, 'attack', 'T1566')"
     ondragend="handleDragEnd(event)">
```

#### Phase Drop Handlers
```html
<div class="phase" data-phase="IN:reconnaissance"
     ondragover="handleDragOver(event)"
     ondragleave="handleDragLeave(event)"
     ondrop="handleDrop(event, 'IN:reconnaissance')">
```

---

## [2.2.0] - 2026-01-29

### Added
- **CAPEC Integration Demo** (`demo-capec-test.html`)
  - Full CAPEC (Common Attack Pattern Enumeration and Classification) visualization
  - 25+ CAPEC patterns mapped to UKC phases with ATT&CK technique relationships
  - CWE (Common Weakness Enumeration) layer support
  - Two view modes: Kill Chain View and Relationship View
  - CAPEC patterns grouped by category (Social Engineering, Injection, etc.)
  - Interactive detail panel showing pattern descriptions, techniques, CWEs
  - Toggle layers: Show/hide CAPEC overlay, CWE links, grouping mode
  - Pattern selection highlights related phases and techniques
  - Relationship chain visualization: CAPEC → CWE → ATT&CK → UKC Phase

### Technical Context for Agents
- CAPEC data stored in `CAPEC_DATA` object with structure:
  ```javascript
  'CAPEC-xxx': {
    id, name, description, category, severity, likelihood,
    techniques: ['T1xxx', ...],  // Related ATT&CK techniques
    cwes: ['CWE-xxx', ...],      // Related weaknesses
    ukc_phases: ['phase-id', ...]  // Mapped kill chain phases
  }
  ```
- CWE data in `CWE_DATA` with id, name, category
- Uses main visualizer's `getTechniqueName()` for technique lookups
- Grouping mode renders CAPEC patterns as parent containers in phases
- Relationship view shows CAPEC → CWE → Technique → Phase chain

---

## [2.1.0] - 2026-01-29

### Added
- **MITRE ATT&CK Navigator Layer Support**
  - New `parseNavigatorLayer(json)` method to import Navigator JSON exports
  - Supports all three domains: Enterprise, Mobile, ICS
  - Only imports techniques with `enabled: true`
  - Handles duplicate technique entries (same technique in multiple tactics)
  
- **Advanced Mode Demo** (`demo-advanced.html`)
  - Two-mode operation: Default (automatic mapping) and Advanced (manual assignment)
  - Granular technique-to-phase assignment UI
  - Techniques appear in exactly ONE phase when manually assigned
  - Import/Export custom mappings as JSON
  - Load Navigator layer files directly
  - Technique library sidebar for browsing available techniques

- **Documentation**
  - README.md with full API documentation
  - CHANGELOG.md (this file) for version history and agent context
  - TASKS.md for planned features and roadmap

### Technical Context for Agents
- Navigator layer JSON structure: `{ techniques: [{ techniqueID, tactic, enabled, ... }] }`
- Domain detection in `detectDomain()` uses technique ID patterns
- Manual mappings stored in `this.manualMappings` object
- Advanced mode bypasses `guessPhaseFromId()` fallback logic

---

## [2.0.0] - 2026-01-29

### Added
- **Multi-Domain ATT&CK Support**
  - Enterprise domain (T1xxx) - default
  - Mobile domain (T1xxx specific ranges: T1398-T1448, T1471-T1478, T1507-T1533, T1575-T1665)
  - ICS domain (T0xxx format)
  
- **Domain Detection**
  - `detectDomain(techId)` method to identify technique domain
  - `isEnterpriseTechnique(numId)` helper for overlapping ranges
  - Static `DOMAINS` constant: `{ ENTERPRISE, MOBILE, ICS }`

- **Domain-Specific URL Generation**
  - `getMitreAttackUrl(techId)` generates correct URLs per domain
  - Enterprise: `attack.mitre.org/techniques/T1566/`
  - Mobile: `attack.mitre.org/techniques/mobile/T1430/`
  - ICS: `attack.mitre.org/techniques/ics/T0800/`

- **Visual Domain Indicators**
  - CSS class `domain-mobile` with green left border
  - CSS class `domain-ics` with brown left border
  - Updated legend to show domain indicators

- **New Demo Scenarios**
  - ICS/SCADA Attack scenario with T0xxx techniques
  - Mobile Device Attack scenario with mobile-specific techniques

### Changed
- Updated all phase `techniquePatterns` arrays to include Mobile and ICS techniques
- Enhanced `guessPhaseFromId()` with domain-specific range mappings
- `createTechnique()` now adds domain class and tooltip info

### Technical Context for Agents
- Kill chain structure in `this.killChainStructure` object
- Three super-phases: IN, THROUGH, OUT
- Each super-phase contains multiple phases with `techniquePatterns` arrays
- Technique mapping happens in `mapTechniquesToPhases()`
- Fallback logic in `guessPhaseFromId()` when no pattern match

---

## [1.1.0] - 2026-01-29

### Added
- **Configurable Color Scheme**
  - `static defaultColors` object with muted gray palette
  - Constructor accepts `options.colors` parameter
  - `applyColors()` method sets CSS custom properties
  - `setColors(newColors)` for dynamic color updates

### Changed
- **Compact Styling**
  - Reduced padding (8-12px instead of 15-25px)
  - Smaller fonts (0.65-0.85rem instead of 0.8-1.3rem)
  - Reduced min-width (220px instead of 280px)
  - Smaller gaps between elements
  
- **Muted Color Palette**
  - Gray-based colors replacing cyan/red/orange/purple
  - Border-left indicators instead of gradient backgrounds
  - Subtle accent colors

### Technical Context for Agents
- CSS variables defined in `:root` and applied via `applyColors()`
- Color keys: `phaseIn`, `phaseThrough`, `phaseOut`, `bgDark`, `bgCard`, `bgPhase`, `textPrimary`, `textSecondary`, `borderColor`, `accent`

---

## [1.0.0] - 2026-01-29

### Initial Release
- **Core Visualization**
  - Unified Kill Chain framework with IN → THROUGH → OUT flow
  - 18 sub-phases mapped to MITRE ATT&CK tactics
  - Technique cards with ID and name display

- **Interactive Features**
  - Expand/collapse individual phases
  - Expand All / Collapse All buttons
  - Compact mode (show only technique IDs)
  - Show Only Active Phases toggle
  - Reset View functionality

- **Statistics Bar**
  - Total technique count
  - Per-super-phase counts (IN, THROUGH, OUT)
  - Active phase count

- **MITRE Integration**
  - Click technique to open ATT&CK page
  - Technique-to-phase mapping based on ATT&CK tactics

- **Demo Page**
  - Preset scenarios: Ransomware, APT, Insider Threat, Supply Chain
  - Custom JSON input
  - Full MITRE ATT&CK sample data

### Technical Context for Agents
- `KillChainVisualizer` class in `kill-chain-visualizer.js`
- Techniques stored as `{ technique_id: technique_name }` object
- Mapped techniques in `this.mappedTechniques[superPhase][phaseId]` arrays
- Rendering via DOM manipulation in `render()`, `createSuperPhase()`, `createPhase()`, `createTechnique()`

---

## Development Notes for AI Agents

### File Structure Understanding
```
kill-chain-visualizer.js   - Main class, all logic
index.html                 - Standalone visualizer with sample data
demo.html                  - Interactive demo, scenario presets
demo-advanced.html         - Advanced mode with manual mapping
resources/*.json           - Navigator layer files for import
```

### Key Data Structures

**Technique Input Format:**
```javascript
{ "T1566": "Phishing", "T1059": "Command and Scripting Interpreter" }
```

**Navigator Layer Format:**
```javascript
{
  "techniques": [
    { "techniqueID": "T1566", "tactic": "initial-access", "enabled": true }
  ]
}
```

**Kill Chain Structure:**
```javascript
this.killChainStructure = {
  'IN': { name: '...', phases: [{ id, name, techniquePatterns: [...] }] },
  'THROUGH': { ... },
  'OUT': { ... }
}
```

### Common Modification Points
1. **Add new phase**: Update `killChainStructure` in constructor
2. **Add technique mappings**: Update `techniquePatterns` arrays
3. **Change styling**: Modify CSS in HTML files and `applyColors()`
4. **Add new domain**: Update `detectDomain()`, `guessPhaseFromId()`, `getMitreAttackUrl()`

### Testing Checklist
- [ ] All three domains display correctly
- [ ] Navigator layer import works
- [ ] Manual mappings persist correctly
- [ ] Technique links open correct URLs
- [ ] Compact mode toggles properly
- [ ] Statistics update on technique changes
