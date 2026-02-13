# AttackFlow — Monolithic API Reference

> **Version:** 2.7.0  
> **Scope:** Documents the current inline JavaScript implementation in `index.html` and the companion `config.js` + `stix-config.js`.  
> **Purpose:** Serve as the definitive reference for the v3.0 modular refactoring (see `DETACH.md`).

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [File Map](#2-file-map)
3. [config.js — Configuration & Theme Engine](#3-configjs--configuration--theme-engine)
4. [stix-config.js — STIX 2.1 Object Definitions](#4-stix-configjs--stix-21-object-definitions)
5. [Inline JS Sections (index.html)](#5-inline-js-sections-indexhtml)
   - 5.1 [VERSION](#51-version)
   - 5.2 [INPUT SECURITY](#52-input-security)
   - 5.3 [METADATA HELPERS](#53-metadata-helpers)
   - 5.4 [TYPE MAPPING CONSTANTS](#54-type-mapping-constants)
   - 5.5 [ASSIGNMENT & PHASE LOGIC](#55-assignment--phase-logic)
   - 5.6 [GROUP MANAGEMENT](#56-group-management)
   - 5.7 [CONSTANTS & STATE](#57-constants--state)
   - 5.8 [DATA LOADING](#58-data-loading)
   - 5.9 [NAVIGATOR IMPORT](#59-navigator-import)
   - 5.10 [VIEW & LAYER CONTROLS](#510-view--layer-controls)
   - 5.11 [THEME RUNTIME](#511-theme-runtime)
   - 5.12 [COMPACT MODE](#512-compact-mode)
   - 5.13 [TAB & FILTER CONTROLS](#513-tab--filter-controls)
   - 5.14 [ENTITY LIST RENDERING](#514-entity-list-rendering)
   - 5.15 [STIX ITEM MANAGEMENT](#515-stix-item-management)
   - 5.16 [STIX EDITOR MODAL](#516-stix-editor-modal)
   - 5.17 [SELECTION & DETAIL PANEL](#517-selection--detail-panel)
   - 5.18 [DRAG & DROP](#518-drag--drop)
   - 5.19 [KILL CHAIN RENDERING](#519-kill-chain-rendering)
   - 5.20 [RELATIONSHIP VIEW](#520-relationship-view)
   - 5.21 [STATS & UTILITIES](#521-stats--utilities)
   - 5.22 [EXPORT (JSON / CSV / STIX Bundle)](#522-export-json--csv--stix-bundle)
   - 5.23 [IMPORT (Kill Chain)](#523-import-kill-chain)
   - 5.24 [DROPDOWN UTILS](#524-dropdown-utils)
   - 5.25 [METADATA EDITOR](#525-metadata-editor)
   - 5.26 [MODALS (Usage Guide / Changelog)](#526-modals-usage-guide--changelog)
   - 5.27 [TOAST NOTIFICATIONS](#527-toast-notifications)
   - 5.28 [INITIALIZATION](#528-initialization)
6. [Data Types & Shapes](#6-data-types--shapes)
7. [Global Event Listeners](#7-global-event-listeners)
8. [Security Model](#8-security-model)
9. [Module Mapping (Current → v3.0)](#9-module-mapping-current--v30)

---

## 1. Architecture Overview

AttackFlow is a **single-page application** with all JavaScript inlined inside `index.html` (≈ 4,800 lines, starting at line ~2625). Two companion scripts — `config.js` and `stix-config.js` — are loaded via `<script>` tags before the inline block. There is no build step, no bundler, and no module system — every function and variable lives in the global scope.

```
┌────────────────────────────────────────────────────────┐
│  Browser (index.html)                                  │
│                                                        │
│  <script src="config.js">                              │
│    CONFIG, resolveTheme(), applyConfigColors()          │
│                                                        │
│  <script src="stix-config.js">                         │
│    STIX_COMMON_PROPERTIES, STIX_VOCABULARIES,           │
│    STIX_OBJECTS, STIX_RELATIONSHIP_DEFAULTS,            │
│    getStixFieldsForType(), getStixTypeKeys(), etc.      │
│                                                        │
│  <script> (inline, lines ~2625-7415)                   │
│    VERSION → SECURITY → METADATA → TYPE-MAPPING →      │
│    ASSIGNMENTS → GROUPS → STATE → DATA →               │
│    NAVIGATOR → VIEWS → THEME → COMPACT → TABS →        │
│    ENTITIES → STIX-MANAGEMENT → STIX-EDITOR →          │
│    DETAIL → DND → RENDERING → RELATIONSHIPS →          │
│    STATS → EXPORT → IMPORT → DROPDOWN →                │
│    META-EDITOR → MODALS → TOAST → INIT                 │
│  </script>                                             │
│                                                        │
│  Static resources/ (6 JSON files)                      │
│  Static frameworks/ (ATTCK JSON, CAPEC/CWE XML)        │
└────────────────────────────────────────────────────────┘
```

**Key characteristics:**

- All state is held in a single mutable `state` object.
- All DOM manipulation uses `innerHTML` string building and direct `classList` toggling.
- Security is enforced by a front-loaded `InputSecurity` object and event-level input guards.
- Drag & drop uses HTML5 native API with a global `dragData` object.
- Persistence is limited to `localStorage` for theme mode and compact mode.
- STIX 2.1 SDO types and field definitions are externalized in `stix-config.js` (19 types, 20+ vocabularies).
- Four entity types are supported: ATT&CK techniques, CAPEC patterns, CWE weaknesses, and STIX objects.

---

## 2. File Map

| File | Role | Lines |
|------|------|-------|
| `config.js` | CONFIG object, `resolveTheme()`, `applyConfigColors()` | 254 |
| `stix-config.js` | STIX 2.1 SDO definitions, vocabularies, helpers | 576 |
| `index.html` | HTML structure (1–~2624), CSS (embedded), inline JS (~2625–7415) | 7,415 |
| `resources/attack-techniques.json` | ATT&CK technique library | Fetched at runtime |
| `resources/capec-full.json` | CAPEC pattern library | Fetched at runtime |
| `resources/cwe-full.json` | CWE weakness library | Fetched at runtime |
| `resources/technique-to-capec.json` | ATT&CK → CAPEC mapping | Fetched at runtime |
| `resources/capec-to-technique.json` | CAPEC → ATT&CK mapping | Fetched at runtime |
| `resources/cwe-to-capec.json` | CWE → CAPEC mapping | Fetched at runtime |
| `resources/Nav_Layer_*.json` | ATT&CK Navigator layers (ENTERPRISE, ICS, MOBILE) | Loaded on demand |
| `examples/stix-demo.json` | Full-featured STIX demo (all 19 SDO types) | Example |
| `examples/Operation-Midnight-Eclipse-stix-bundle.json` | Exported STIX 2.1 bundle (25 SDOs + 18 SROs) | Example |

---

## 3. config.js — Configuration & Theme Engine

**Source:** `config.js` (254 lines)

### 3.1 `CONFIG` Object

Top-level configuration constant. Properties:

| Property | Type | Description |
|----------|------|-------------|
| `version` | `string` | Application version (`'2.7.0'`) |
| `changelogUrl` | `string` | Path to CHANGELOG.md |
| `sources.capec` | `{domains, mechanisms}` | Paths to CAPEC XML source files |
| `sources.cwe` | `{hardware, software, all}` | Paths to CWE XML source files |
| `sources.attack` | `{version, enterprise, mobile, ics}` | ATT&CK STIX bundle paths & version |
| `sanitize.paths` | `string[]` | Glob patterns for JSON sanitization |
| `stixTypes` | `Array<{value, label}>` | 19 STIX 2.1 SDO type definitions for UI dropdowns |
| `phases` | `{in, through, out}` | Hex colors for kill chain super-phases |
| `frameworks` | `{attack, capec, cwe}` | Hex colors for framework entity types |
| `ui` | `object` | UI fallback colors (bg, text, border, accent) |
| `metaIcons` | `object` | Metadata icon colors (CVE, observable, link, comment, confidence) |
| `themes` | `{dark: {default: ...}, light: {default: ...}}` | Theme presets with ui + metaIcons overrides |
| `themeDefaults` | `{mode, scheme}` | Default theme mode (`'light'`) and scheme (`'default'`) |
| `themeMode` | `string` | Initial mode: `'light'`, `'dark'`, or `'auto'` |
| `display` | `object` | Max lengths for names, descriptions, mitigations, references, custom items, kill chain description |
| `navigation` | `{confirmOnLeave}` | Whether to show leave-site confirmation |

#### `CONFIG.stixTypes`

19 entries mapping STIX 2.1 SDO type names to human-readable labels:

`attack-pattern`, `campaign`, `course-of-action`, `grouping`, `identity`, `indicator`, `infrastructure`, `intrusion-set`, `location`, `malware`, `malware-analysis`, `note`, `observed-data`, `opinion`, `report`, `threat-actor`, `tool`, `vulnerability`, `x-custom`.

Used by `populateStixTypeDropdown()` and `VALID_STIX_TYPES` to constrain type selection.

### 3.2 Functions

#### `resolveTheme(mode?, scheme?) → ThemeObject`

**Line:** config.js:187  
Merges the selected theme scheme's overrides with global CONFIG defaults.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | `string` | `CONFIG.themeDefaults.mode` | `'light'` or `'dark'` |
| `scheme` | `string` | `CONFIG.themeDefaults.scheme` | Scheme name within the mode |

**Returns:** `{ phases, frameworks, ui, metaIcons }` — fully resolved theme.

#### `applyConfigColors(theme?) → void`

**Line:** config.js:198  
Sets CSS custom properties on `document.documentElement` from the resolved theme.

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `theme` | `ThemeObject` | `resolveTheme()` | Pre-resolved theme, or auto-resolves |

**Side effects:** Sets 20+ CSS custom properties (e.g. `--phase-in`, `--attack-color`, `--bg-dark`, `--meta-cve-bg`).

---

## 4. stix-config.js — STIX 2.1 Object Definitions

**Source:** `stix-config.js` (576 lines)

Externalizes all STIX 2.1 specification knowledge. Loaded via `<script src="stix-config.js">` before the inline block.

### 4.1 `STIX_COMMON_PROPERTIES` — Object

Defines fields present on **every** SDO per STIX 2.1 §3.1:

**Required:** `type`, `spec_version`, `id`, `created`, `modified`  
**Optional:** `created_by_ref`, `revoked`, `labels`, `confidence`, `lang`, `external_references`, `object_marking_refs`, `granular_markings`

Each field is a descriptor: `{ key, label, type, description }`.

### 4.2 `STIX_VOCABULARIES` — Object

20+ Open Vocabulary definitions from STIX 2.1 §10. Keys include:

| Vocabulary Key | Used By |
|---------------|---------|
| `attack-motivation-ov` | Threat Actor, Intrusion Set |
| `attack-resource-level-ov` | Threat Actor, Intrusion Set |
| `identity-class-ov` | Identity |
| `indicator-type-ov` | Indicator |
| `infrastructure-type-ov` | Infrastructure |
| `malware-type-ov` | Malware |
| `malware-capabilities-ov` | Malware |
| `malware-result-ov` | Malware Analysis |
| `opinion-enum` | Opinion |
| `pattern-type-ov` | Indicator |
| `report-type-ov` | Report |
| `threat-actor-type-ov` | Threat Actor |
| `threat-actor-role-ov` | Threat Actor |
| `threat-actor-sophistication-ov` | Threat Actor |
| `tool-type-ov` | Tool |
| `region-ov` | Location |
| `sectors-ov` | Identity |
| `implementation-language-ov` | Malware |
| `processor-architecture-ov` | Malware |
| `grouping-context-ov` | Grouping |

### 4.3 `STIX_OBJECTS` — Object

19 SDO type definitions, each with:

```js
{
  label: 'Human Name',
  description: 'Short summary',
  stixSpec: 'https://docs.oasis-open.org/cti/stix/v2.1/...',
  required: [{ key, label, type, description, vocabulary?, placeholder? }],
  optional: [{ key, label, type, description, vocabulary?, placeholder? }]
}
```

**SDO types defined:** `attack-pattern`, `campaign`, `course-of-action`, `grouping`, `identity`, `indicator`, `infrastructure`, `intrusion-set`, `location`, `malware`, `malware-analysis`, `note`, `observed-data`, `opinion`, `report`, `threat-actor`, `tool`, `vulnerability`, `x-custom`.

**Field types:** `string`, `text`, `identifier`, `timestamp`, `enum`, `open-vocab`, `list`, `list:open-vocab`, `integer`, `boolean`, `kill-chain-phases`, `external-references`, `dictionary`.

### 4.4 `STIX_RELATIONSHIP_DEFAULTS` — Object

Maps each SDO type to its default SRO relationship verb (e.g. `'malware' → 'uses'`, `'indicator' → 'indicates'`, `'course-of-action' → 'mitigates'`).

### 4.5 Helper Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `getStixFieldsForType(stixType)` | `string → { required, optional }` | Returns field descriptors for a type |
| `getStixTypeKeys()` | `→ string[]` | Returns all SDO type keys |
| `getStixTypeLabel(stixType)` | `string → string` | Returns human-readable label |
| `getStixVocabulary(vocabKey)` | `string → string[]` | Returns vocabulary values |

---

## 5. Inline JS Sections (index.html)

All line numbers below refer to `index.html`.

---

### 5.1 VERSION

**Lines:** ~2625–2643

#### `APP_VERSION`

**Type:** `let string`  
Fallback `'2.4.2'`. Overwritten by `loadVersion()`.

#### `loadVersion() → Promise<void>`

Fetches `CHANGELOG.md`, extracts the first `## [x.y.z]` match via regex, and sets both `APP_VERSION` and the `#app-version` element's text.

---

### 5.2 INPUT SECURITY

**Lines:** ~2647–3430

#### `InputSecurity` — Object

Central security module. All methods are pure functions (no side effects).

| Method | Signature | Description |
|--------|-----------|-------------|
| `escapeHtml(str)` | `string → string` | Escapes `& < > " '` to HTML entities |
| `encodeHtmlEntities(str)` | `string → string` | Encodes to `&#xHH;` for all non-alphanumeric chars |
| `normalize(str, maxLen?)` | `string, number? → string` | Strips control chars, NUL bytes, trims, truncates to `maxLen` (default 10000) |
| `sanitize(str, maxLen?)` | `string, number? → string` | `normalize()` + `escapeHtml()` |
| `sanitizeAttr(str, maxLen?)` | `string, number? → string` | `normalize()` + `encodeHtmlEntities()` for safe attribute values |

#### `InputSecurity.validators` — Object

Each validator returns `{ valid: boolean, error?: string }`.

| Validator | Pattern / Logic |
|-----------|----------------|
| `ipv4(v)` | `/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/` + octet 0–255 check |
| `ipv6(v)` | `/^[0-9a-fA-F:]+$/` + length ≤ 45 |
| `md5(v)` | `/^[a-fA-F0-9]{32}$/` |
| `sha1(v)` | `/^[a-fA-F0-9]{40}$/` |
| `sha256(v)` | `/^[a-fA-F0-9]{64}$/` |
| `domain(v)` | `/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/` + length ≤ 253 |
| `url(v)` | `/^https?:\/\//` + `new URL()` check |
| `cveId(v)` | `/^CVE-\d{4}-\d{4,}$/` |
| `cvssVector(v)` | CVSS 3.0/3.1 vector pattern |
| `filename(v)` | `/^[a-zA-Z0-9._-]+$/` + no `..` |
| `text(v)` | Always valid (passthrough) |

#### `validateObservable(type, value) → ValidationResult`

**Line:** ~2790  
Dispatches to the correct validator based on observable type string. Maps `'ipv4-addr'` → `ipv4`, `'file-hash-md5'` → `md5`, etc. Falls back to `text` for `'threat-actor'`, `'other'`, and `'email-addr'`.

#### Helper Aliases

| Name | Line | Value |
|------|------|-------|
| `esc(str)` | 2795 | Alias for `InputSecurity.escapeHtml` |
| `escAttr(str)` | 2796 | Alias for `InputSecurity.sanitizeAttr` |
| `BLOCKED_INPUT_CHARS` | 2797 | `Set` of 10 chars: `< > { } [ ] ; \` " '` |

#### Input Guard Functions

| Function | Line | Description |
|----------|------|-------------|
| `isTextInputElement(el)` | 2799 | Returns `true` if `el` is `<input>`, `<textarea>`, or `contentEditable` |
| `sanitizeUserInputText(str, maxLen?)` | 2801 | Strips blocked chars, trims, truncates |
| `sanitizeForStorage(str, maxLen?)` | 2808 | `sanitizeUserInputText` + `InputSecurity.normalize` |
| `truncateAtBoundary(str, maxLen)` | 2814 | Truncates at word boundary if possible |
| `applyInputGuards()` | 2818 | Attaches 5 event listeners to `document` (keydown, beforeinput, paste, drop, input) |

#### `stripAngleBracketsFromJson(obj) → object`

**Line:** 2908  
Recursively walks a parsed JSON object and replaces `<` → `&lt;`, `>` → `&gt;` in all string values. Used on every external data load.

---

### 5.3 METADATA HELPERS

**Lines:** ~3432–3545

#### `createDefaultMetadata() → Metadata`

**Line:** 2928  
Returns a fresh metadata object:

```js
{ score: 'unclassified', confidence: null, comments: '',
  cveEntries: [], cveId: '', cveIds: [], hyperlinks: [], observables: [] }
```

#### `getCveEntries(metadata) → CveEntry[]`

**Line:** 2946  
Returns `metadata.cveEntries` if present, otherwise builds entries from legacy `cveIds`/`cveId` fields.

#### `getCveList(metadata) → string[]`

**Line:** 2960  
Convenience wrapper: `getCveEntries(metadata).map(e => e.id)`.

#### `normalizeCveMetadata(metadata) → void`

**Line:** 2964  
Mutates metadata to ensure `cveEntries`, `cveIds`, and `cveId` are all in sync (idempotent).

#### `getConfidenceLabel(value) → string`

**Line:** 2984  
Maps a 0–100 integer to a label: `'Low'` (1–25), `'Medium'` (26–50), `'High'` (51–75), `'Very High'` (76–100), `'Unknown'` (0 or null).

#### `getConfidenceClass(value) → string`

**Line:** 2992  
Maps a 0–100 integer to a CSS class: `'confidence-low'`, `'confidence-medium'`, `'confidence-high'`, `'confidence-very-high'`, or `''`.

#### `assignmentInstanceCounter`

**Line:** 3000  
`let` counter, starts at 0. Monotonically incrementing.

#### `createAssignmentInstanceId() → string`

**Line:** 3001  
Returns `'inst-' + Date.now() + '-' + (++counter)`.

#### `migrateAssignment(a) → Assignment`

**Line:** 3003  
Normalizes legacy (bare-string) assignments to `{ id, metadata, instanceId }` objects. Idempotent.

---

### 5.4 TYPE MAPPING CONSTANTS

**Lines:** ~3547–3620

#### `TYPE_KEYS` — Object

Canonical mapping from entity type string to assignment array key:

```js
{ attack: 'techniques', capec: 'capecs', cwe: 'cwes', custom: 'customItems' }
```

#### `TAG_CLASSES` — Object

CSS class mapping: `{ attack: 'technique-tag', capec: 'capec-tag', cwe: 'cwe-tag', custom: 'custom-tag' }`.

#### `TYPE_LABELS` — Object

Display labels: `{ attack: 'ATT&CK', capec: 'CAPEC', cwe: 'CWE', custom: 'STIX' }`.

#### `ALL_ENTITY_TYPES` — Array

Computed: `['attack', 'capec', 'cwe', 'custom']`.

#### `STIX_ID_PATTERN` — RegExp

`/^[a-z][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/`

Validates STIX 2.1 identifier format: `{type}--{UUIDv4}`.

#### `VALID_STIX_TYPES` — Set

Built from `CONFIG.stixTypes`: `Set(['attack-pattern', 'campaign', ..., 'x-custom'])` (19 entries).

#### `STIX_RELATIONSHIP_MAP` — Object

Maps SDO type → default SRO relationship verb. Used by `buildSTIXBundle()` for auto-generating SROs.

#### `generateUUID() → string`

Returns a UUIDv4 string using `Math.random()`.

#### `generateStixId(stixType) → string`

Returns `"{stixType}--{uuid}"` — a spec-compliant STIX identifier.

---

### 5.5 ASSIGNMENT & PHASE LOGIC

**Lines:** ~3620–3830

#### `getAssignmentId(a) → string`

Returns `a.id || a.entityId || a` (supports both new-format objects and legacy string IDs).

#### `getAssignmentMetadata(a) → Metadata`

Returns `a.metadata` if present, otherwise `createDefaultMetadata()`.

#### `getAssignmentInstanceId(a) → string|null`

Returns `a.instanceId` or `null`.

#### Phase Item Accessors

| Function | Description |
|----------|-------------|
| `getPhaseUngroupedItems(phaseData, type)` | Returns `phaseData[key]` array (techniques/capecs/cwes) |
| `getPhaseGroupedItems(phaseData, type)` | Returns items from `phaseData.groups[*].items` matching `type` |
| `getAllPhaseItemsByType(phaseData, type)` | Union of ungrouped + grouped items for the given type |

#### `ensurePhaseLayout(phaseKey, phaseData) → void`

**Line:** ~3060  
Synchronizes `phaseData.layout` with the actual items and groups. Adds missing layout entries, removes orphaned ones. Layout entries are `{ kind: 'item', type, instanceId }` or `{ kind: 'group', groupId }`.

---

### 5.6 GROUP MANAGEMENT

**Lines:** ~3640–3830

| Function | Signature | Description |
|----------|-----------|-------------|
| `generateGroupId()` | `→ string` | Returns `'grp-' + Date.now() + '-' + random` |
| `createGroup(phaseKey)` | `string → void` | Creates an empty group in the phase, adds to layout, re-renders |
| `toggleGroupCollapse(phaseKey, groupId)` | `string, string → void` | Toggles `group.collapsed`, re-renders |
| `startRenameGroup(phaseKey, groupId)` | `string, string → void` | Sets `group.editing = true`, re-renders, auto-focuses input |
| `commitRenameGroup(phaseKey, groupId, newLabel, cancelled?)` | `string, string, string, boolean? → void` | Sanitizes label, sets `group.editing = false`, re-renders |
| `removeGroup(phaseKey, groupId)` | `string, string → void` | Confirms via `window.confirm`, moves group items back to ungrouped, removes group, re-renders |
| `extractAssignmentInstance(phaseKey, type, instanceId)` | `string, string, string → Assignment\|null` | Removes an assignment from ungrouped or grouped items, cleans layout, returns removed item |
| `moveGroupBetweenPhases(fromPhase, toPhase, groupId)` | `string, string, string → void` | Moves an entire group from one phase to another, updates layout in both |

---

### 5.7 CONSTANTS & STATE

**Lines:** ~3830–3980

#### `SCORE_LEVELS` — Object

```js
{
  unclassified: { label: 'Unclassified', color: '#71717a', bgColor: 'rgba(113,113,122,0.15)' },
  low:          { label: 'Low',          color: '#22c55e', bgColor: 'rgba(34,197,94,0.15)' },
  medium:       { label: 'Medium',       color: '#eab308', bgColor: 'rgba(234,179,8,0.15)' },
  high:         { label: 'High',         color: '#f97316', bgColor: 'rgba(249,115,22,0.15)' },
  critical:     { label: 'Critical',     color: '#ef4444', bgColor: 'rgba(239,68,68,0.15)' }
}
```

#### `OBSERVABLE_TYPES` — Array

10 entries with `{ value, label }`:
`ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `file-hash-md5`, `file-hash-sha1`, `file-hash-sha256`, `file-name`, `email-addr`, `threat-actor`.

#### `state` — Object (Mutable Global State)

| Property | Type | Initial Value | Description |
|----------|------|---------------|-------------|
| `view` | `string` | `'killchain'` | Active view: `'killchain'`, `'relationship'`, `'explorer'` |
| `layers` | `object` | `{attack:true, capec:true, cwe:true, custom:true}` | Visibility toggles per entity type |
| `hideEmpty` | `boolean` | `false` | Whether to hide empty phases |
| `compactMode` | `boolean` | `false` | Whether compact layout is active |
| `activeTab` | `string` | `'attack'` | Active sidebar tab |
| `filters` | `object` | `{attack:'all', capec:'all', cwe:'all', custom:'all'}` | Filter selections per tab |
| `library` | `object` | `{techniques:{}, capecs:{}, cwes:{}, custom:{}}` | Loaded entity libraries (keyed by ID) |
| `techniqueToCapec` | `object` | `{}` | `T1234 → ['CAPEC-123', ...]` mapping |
| `cweToCapec` | `object` | `{}` | `CWE-79 → ['CAPEC-86', ...]` mapping |
| `capecToTechnique` | `object` | `{}` | `CAPEC-123 → ['T1234', ...]` mapping |
| `assignments` | `object` | `{}` | Phase → PhaseData mapping (18 phases) |
| `title` | `string` | `''` | Editable kill chain title (max 200 chars) |
| `description` | `string` | `''` | Editable kill chain description (max 2000 chars, configurable) |
| `selection` | `object` | `{type:null, id:null}` | Currently selected entity |

`state.library.custom` stores STIX objects keyed by their STIX ID (e.g. `malware--uuid`). Each value is a `StixLibraryEntry`.

#### `KILL_CHAIN` — Object

Defines the Unified Kill Chain structure with 3 super-phases and 18 phases:

| Super-Phase | Phases (8 + 6 + 4) |
|-------------|---------------------|
| `IN` | reconnaissance, weaponization, delivery, social-engineering, exploitation, persistence, defense-evasion, command-and-control |
| `THROUGH` | pivoting, discovery, privilege-escalation, execution, credential-access, lateral-movement |
| `OUT` | collection, exfiltration, impact, objectives |

#### `ALL_PHASES` — Array

**Line:** ~3356  
Computed: `['IN:reconnaissance', 'IN:weaponization', ..., 'OUT:objectives']` — 18 entries.

#### `formatPhaseName(phaseId) → string`

Converts `'social-engineering'` → `'Social Engineering'`.

#### `initAssignments() → void`

Initializes `state.assignments` with empty `PhaseData` for each of the 18 phases. Each phase gets `{ techniques: [], capecs: [], cwes: [], customItems: [], groups: [], layout: [] }`. Also resets `state.title` and `state.description` to `''` and syncs the DOM.

#### `commitKillChainTitle(el) → void`

Sanitizes the title input value via `sanitizeForStorage()`, caps at `CONFIG.display.maxTitleLength`, and stores in `state.title`.

#### `syncTitleToDOM() → void`

Sets the `#kill-chain-title` input's value from `state.title`.

#### `commitKillChainDescription(el) → void`

Sanitizes the description textarea value via `sanitizeForStorage()`, caps at `CONFIG.display.maxKillChainDescLength` (default 2000), stores in `state.description`, and updates the hint + counter.

#### `syncDescriptionToDOM() → void`

Sets the `#kc-desc-textarea` value from `state.description`, updates the collapsed hint text and character counter, and collapses the panel.

#### `toggleDescriptionPanel() → void`

Toggles the `.open` class on `#kc-desc-bar`, triggering the CSS `max-height` transition.

#### `updateDescriptionHint() → void`

Updates the `#kc-desc-hint` element with a truncated preview (first 80 chars + ellipsis) or "— none" when empty. Only visible when the panel is collapsed.

#### `updateDescriptionCounter() → void`

Updates the `#kc-desc-counter` element with `{current} / {max}` character count.

---

### 5.8 DATA LOADING

**Lines:** ~3980–4000

#### `loadData() → Promise<void>`

Fetches 6 JSON resources in parallel:
1. `resources/attack-techniques.json` → `state.library.techniques`
2. `resources/capec-full.json` → `state.library.capecs`
3. `resources/cwe-full.json` → `state.library.cwes`
4. `resources/technique-to-capec.json` → `state.techniqueToCapec`
5. `resources/capec-to-technique.json` → `state.capecToTechnique`
6. `resources/cwe-to-capec.json` → `state.cweToCapec`

All responses are passed through `stripAngleBracketsFromJson()` before assignment. Calls `renderAll()` on success. Shows toast on error.

#### `loadNavigator(domain) → Promise<void>`

**Line:** ~3397  
Fetches `resources/Nav_Layer_${DOMAIN}.json`, adds techniques not already in library. Shows toast with counts.

---

### 5.9 NAVIGATOR IMPORT

**Lines:** ~4055–4160

#### `IMPORT_LIMITS` — Object

```js
{ maxFileSize: 25*1024*1024, maxTechniques: 5000,
  maxStringLength: 500, techniqueIdPattern: /^T\d{4}(\.\d{3})?$/ }
```

#### `importNavigator(event) → void`

File input handler. Validates file size, parses JSON, validates each technique ID, adds valid techniques to library. Shows toast with stats. Tagged `KCE-SEC-003`.

#### `detectDomain(techId) → string`

Returns `'ics'` if starts with `T0`, `'mobile'` if numeric part 1398–1665, else `'enterprise'`.

#### `getTechniqueName(techId) → string`

Looks up name in `state.library.techniques`, falls back to `'Technique Txxxx'`.

---

### 5.10 VIEW & LAYER CONTROLS

**Lines:** ~4162–4210

#### `setView(view) → void`

Switches between `'killchain'`, `'relationship'`, and `'explorer'` views. Toggles visibility of containers, buttons, stats bar, legend. Calls `renderRelationshipView()` if entering relationship view. Updates compact/hide-empty controls.

#### `toggleSidebar() → void`

Toggles `sidebar-collapsed` class on `.app`.

#### `toggleLayer(layer) → void`

Toggles `state.layers[layer]` from checkbox state, re-renders kill chain and relationship view. Supports four layers: `attack`, `capec`, `cwe`, `custom` (STIX).

---

### 5.11 THEME RUNTIME

**Lines:** ~4210–4300

#### Storage Constants

| Name | Value |
|------|-------|
| `THEME_STORAGE_KEYS.mode` | `'af-theme-mode'` |
| `COMPACT_STORAGE_KEY` | `'af-compact-mode'` |

#### `currentTheme` — Object

`{ mode: string, scheme: string }` — tracks the active theme state.

| Function | Signature | Description |
|----------|-----------|-------------|
| `getPreferredThemeMode()` | `→ string` | Returns configured mode, or OS preference if `'auto'` |
| `normalizeThemeMode(mode)` | `string → string` | Clamps to `'light'` or `'dark'` |
| `normalizeThemeScheme(mode, scheme)` | `string, string → string` | Falls back to `'default'` if scheme doesn't exist |
| `applyTheme(mode, scheme, persist?)` | `string, string, boolean → void` | Resolves theme, calls `applyConfigColors()`, sets `data-theme`, persists to localStorage |
| `updateThemeControls()` | `→ void` | Updates toggle button text |
| `toggleThemeMode()` | `→ void` | Flips light ↔ dark |
| `initThemeControls()` | `→ void` | Reads localStorage, applies initial theme |
| `syncThemeFromStorage()` | `→ void` | Syncs theme if another tab changed localStorage |

---

### 5.12 COMPACT MODE

**Lines:** ~4300–4410

| Function | Signature | Description |
|----------|-----------|-------------|
| `updateHideEmptyControl()` | `→ void` | Toggles `.active` on btn, disables if compact |
| `updateCompactControls()` | `→ void` | Toggles `.active`, updates button text |
| `setCompactMode(enabled, persist?)` | `boolean, boolean? → void` | Sets state, forces `hideEmpty`, toggles classes, persists, re-renders |
| `toggleCompactMode()` | `→ void` | Inverts `state.compactMode` |
| `initCompactMode()` | `→ void` | Reads localStorage, sets initial state |
| `applyCompactLayout()` | `→ void` | Adds `compact-scroll` class if kill chain overflows |
| `toggleHideEmpty()` | `→ void` | Blocked if compact mode, else toggles `state.hideEmpty` and re-renders |

---

### 5.13 TAB & FILTER CONTROLS

**Lines:** ~4412–4430

#### `switchTab(tab) → void`

Sets `state.activeTab`, toggles `.active` on sidebar tabs and panels. Supports tabs: `attack`, `capec`, `cwe`, `custom`.

#### `setFilter(type, filter) → void`

Sets `state.filters[type]`, toggles `.active` on filter buttons, calls `filterEntities(type)`.

---

### 5.14 ENTITY LIST RENDERING

**Lines:** ~4431–4573

#### `filterEntities(type) → void`

Reads search input and filter state, filters the entity library (`techniques`, `capecs`, `cwes`, or `custom`), builds HTML for up to 100 results, sets `listEl.innerHTML`. Each entity item is `draggable` with inline `ondragstart` / `ondragend` / `onclick` handlers.

**Filters by type:**
- `attack`: search by id/name, filter by domain
- `capec`: search by id/name, filter by abstraction level
- `cwe`: search by id/name, filter by abstraction level
- `custom` (STIX): search by id/name, filter by STIX SDO type dropdown

#### `isEntityAssigned(type, id) → boolean`

Iterates all phases checking whether entity is assigned anywhere. Supports all four entity types.

---

### 5.15 STIX ITEM MANAGEMENT

**Lines:** ~4573–4890

Manages STIX 2.1 Domain Object (SDO) lifecycle: creation, deletion, bundle import.

#### `STIX_BUNDLE_IMPORT_LIMITS` — Object

```js
{ maxFileSize: 25*1024*1024, maxObjects: 5000,
  maxStringLength: 5000, maxListItems: 100,
  maxNameLength: 200, maxDescLength: 10000 }
```

#### `importStixBundle(event) → void`

File input handler for STIX 2.1 bundle JSON. Pipeline:
1. Validate file size (≤25 MB)
2. Parse JSON, pass through `stripAngleBracketsFromJson()`
3. Validate top-level bundle structure (`type: 'bundle'`, `objects` array)
4. Enforce object count limit (5,000)
5. For each object: validate type is SDO (skip `relationship`, `sighting`, `marking-definition`), validate STIX ID format, verify ID prefix matches type, check for duplicates
6. Sanitize via `sanitizeStixBundleObject()`
7. Store in `state.library.custom`, show toast with import stats

#### `sanitizeStixBundleObject(obj, stixType, stixId) → StixLibraryEntry|null`

Sanitizes a single STIX bundle object:
- Sanitizes `name`, `description`, `labels` (core fields)
- Imports spec-defined fields by consulting `STIX_OBJECTS[stixType]` from `stix-config.js`
- Field-type-aware sanitization: booleans, integers, lists, strings/text/timestamps
- All strings pass through `sanitizeImportedString()`

#### `populateStixTypeDropdown() → void`

Populates `#custom-stix-type` select and `#filter-custom-type` filter from `CONFIG.stixTypes`.

#### `toggleCustomTypeName() → void`

Shows/hides the custom type name input when `x-custom` type is selected.

#### `openCreateCustomModal() → void`

Opens the Create STIX Item modal, initializes all form fields.

#### `closeCreateCustomModal(event?) → void`

Closes the modal (only if click is on overlay itself).

#### `createCustomItem() → void`

Creates a new STIX object. Validates STIX type against `VALID_STIX_TYPES`, sanitizes name/description/labels via `sanitizeForStorage()`, generates a STIX ID via `generateStixId()`, stores in `state.library.custom`.

#### `deleteCustomItem(id) → void`

Confirms via `window.confirm`, removes from `state.library.custom` and all phase assignments (ungrouped `customItems` + group items), re-renders.

---

### 5.16 STIX EDITOR MODAL

**Lines:** ~4890–5165

Full-featured modal editor for STIX object properties, driven by `stix-config.js` type definitions.

#### `currentStixEdit` — Object (Mutable)

`{ id, phaseKey, instanceId }` — tracks which STIX item is being edited.

#### `openStixEditor(id, phaseKey?, instanceId?) → void`

Opens the Edit STIX Item modal. Dynamically builds form fields:
1. **Identity section** (read-only): ID, Type, Created, Modified
2. **Core Properties**: Name, Description, Labels, Custom Type Name (x-custom only)
3. **Required Fields**: From `STIX_OBJECTS[type].required` (excluding core)
4. **Optional Fields**: From `STIX_OBJECTS[type].optional` (excluding core)

Field rendering is delegated to `buildStixFieldFromSpec()` which handles all STIX field types.

#### `closeStixEditor(event?) → void`

Closes modal, clears `currentStixEdit`.

#### `saveStixEditor() → void`

Reads all form fields, validates name (required), sanitizes all values with `sanitizeForStorage()`, updates `item.modified` timestamp, re-renders.

Field types are handled per spec:
- `boolean` → checkbox state
- `integer` → `parseInt`, `NaN` → `undefined`
- `list` / `list:open-vocab` → comma-split, sanitize each entry
- All others → `sanitizeForStorage(rawVal, 2000)`

#### STIX Editor Field Builders

| Function | Description |
|----------|-------------|
| `buildStixReadonlyField(label, value)` | Read-only input with label |
| `buildStixTextField(id, label, value, required, maxLen, placeholder)` | Text input |
| `buildStixTextareaField(id, label, value, required, maxLen, placeholder)` | Textarea |
| `buildStixFieldFromSpec(field, item, required)` | Dynamic field builder — handles all STIX field types: `string`, `text`, `enum`, `open-vocab`, `list`, `list:open-vocab`, `integer`, `boolean`, `timestamp`, `identifier`, `kill-chain-phases`, `external-references`, `dictionary` |

#### `getEntityName(type, id) → string`

Returns display name for any entity type. For `custom`, returns `state.library.custom[id]?.name`.

#### `buildStixPropertySummary(id) → string`

Builds HTML summary of STIX spec-defined properties (non-core) that have values. Used in the entity detail modal to display STIX-specific fields below the standard metadata.

---

### 5.17 SELECTION & DETAIL PANEL

**Lines:** ~5166–5540

#### `selectEntity(type, id) → void`

Sets `state.selection`, refreshes entity list, shows detail panel.

#### `buildEntityDetail(type, id) → { id, name, html }`

Builds HTML detail view for ATT&CK technique, CAPEC pattern, CWE weakness, or STIX object. Includes:
- Description, attributes, related entities
- Mitigations (ATT&CK only, max 8 shown)
- References with safe URL validation (`https?://`)
- Cross-entity navigation (`onclick` → `selectEntity`)
- External links to MITRE websites

#### `buildMetadataSummary(type, id, phaseKey?, instanceId?) → string`

Builds HTML for metadata display: score, confidence, CVE entries, comments, hyperlinks, observables. For STIX items, also calls `buildStixPropertySummary()` to display spec-defined fields. Used inside entity modal.

#### `openEntityModal(type, id, phaseKey?, instanceId?) → void`

Populates and shows the entity detail modal. Combines `buildEntityDetail` + `buildMetadataSummary`.

#### `closeEntityModal(event?) → void`

Hides modal. Only closes if click is on overlay itself (not children).

#### `showDetail(type, id) → void`

Shows the side detail panel (not modal) with entity detail HTML.

#### `closeDetail() → void`

Hides detail panel, clears selection.

#### `findEntityPhase(type, id) → string|null`

Searches all phases to find which phase an entity is assigned to. Returns the phase key or `null`.

#### `openMitigationExplorer(mitigationId) → void`

**Line:** ~3760  
Validates mitigation ID format, loads `explorer.html?mitigation=...` in the explorer iframe, switches to explorer view.

#### `openEntityExplorer(type, id) → void`

**Line:** ~3773  
Similar to above but for `entity=type:id`.

---

### 5.18 DRAG & DROP

**Lines:** ~5538–5690

#### `dragData` — Object (Mutable)

```js
{ kind: null, type: null, id: null, fromPhase: null,
  instanceId: null, groupId: null, sourceGroupId: null }
```

| Function | Signature | Description |
|----------|-----------|-------------|
| `handleDragStart(event, type, id)` | Sidebar entity drag start. Sets `dragData.kind='item'`, highlights phases. Works for all 4 types including `custom`. |
| `handleDragEnd(event)` | Removes drag styling and clears `dragData`. |
| `handleDragOver(event)` | Prevents default, sets drop effect, adds background highlight. |
| `handleDragLeave(event)` | Removes background highlight. |
| `handleDrop(event, phaseKey)` | Phase drop handler. Routes to `moveGroupBetweenPhases` for groups, else adds/moves assignment. Creates new assignment with `createDefaultMetadata()` or preserves metadata from source. Re-renders. |
| `handleAssignmentDragStart(event, type, id, phaseKey, instanceId, sourceGroupId)` | Drag start for already-assigned entities. Sets `dragData.fromPhase`. |
| `handleGroupDragStart(event, phaseKey, groupId)` | Group drag start. Sets `dragData.kind='group'`. |
| `handleGroupDrop(event, phaseKey, groupId)` | Drop into a group. Extracts from source, adds to target group. |

---

### 5.19 KILL CHAIN RENDERING

**Lines:** ~5687–5915

#### `renderKillChain() → void`

The main rendering function. Iterates `KILL_CHAIN` → super-phases → phases, builds the full HTML string for the kill chain view. For each phase:

1. Counts visible items per layer
2. Applies hide-empty / compact logic
3. Iterates `phaseData.layout` for ordered rendering
4. Calls `renderEntityTag()` for ungrouped items
5. Builds group containers with drag/rename/delete controls
6. Calls `renderEntityTag()` for grouped items
7. Sets `container.innerHTML`, then calls `renderStats()` and `applyCompactLayout()`

#### `renderEntityTag(type, id, name, metadata, phaseKey, instanceId, sourceGroupId?) → string`

**Line:** ~4558  
Builds HTML for a single entity tag (technique, CAPEC, CWE, or STIX object). Features:
- Score-based `data-score` attribute for CSS styling
- STIX type badge for custom items (e.g. `malware`, `threat-actor`)
- Domain badge (ENT/MOB/ICS) for ATT&CK techniques
- Metadata icons: CVE, observables, links, comments, confidence
- Compact mode: hides name, shows metadata icons in header
- Action buttons: remove, explore, edit metadata (or edit STIX for custom items)
- Drag handlers for reassignment

---

### 5.20 RELATIONSHIP VIEW

**Lines:** ~5915–6097

#### `renderRelationshipView() → void`

Builds relationship chains from assigned CAPECs. For each phase:
1. Finds assigned CAPECs and their related CWEs + techniques
2. Finds assigned techniques without CAPECs (partial chains)
3. Renders 4-column rows: CAPEC → CWE → ATT&CK → Phase

---

### 5.21 STATS & UTILITIES

**Lines:** ~6097–6170

#### `renderStats() → void`

Counts unique techniques, CAPECs, CWEs, STIX items, and phases used across all assignments. Updates `#stats-bar` innerHTML.

#### `togglePhase(header) → void`

Toggles `.minimized` class on the phase element (collapse/expand).

#### `removeAssignment(type, id, phaseKey, instanceId) → void`

Confirms via `window.confirm`, removes from ungrouped array or group items, cleans layout, re-renders.

#### `expandAll() / collapseAll() → void`

Expands/collapses all `.phase` elements.

#### `clearAssignments() → void`

Calls `initAssignments()`, re-renders everything.

---

### 5.22 EXPORT (JSON / CSV / STIX Bundle)

**Lines:** ~6110–6260 (JSON/STIX), ~6790–6980 (CSV)

#### `exportJSON() → void`

Creates a JSON blob with: `version`, `schema: 'killchain-export-lite'`, `exportedAt`, `title`, `view`, `activeTab`, `filters`, `layers`, `hideEmpty`, `assignments`, `selection`, `customLibrary`. If STIX items exist, also embeds a `stixBundle` via `buildSTIXBundle()`. Downloads as `{title}-slug.json`.

#### `buildSTIXBundle() → StixBundle`

Generates a STIX 2.1 bundle object from the current state:
1. Adds SDOs from `state.library.custom` (type, spec_version, id, created, modified, name, description, labels)
2. Generates SRO relationships for co-located STIX items in the same phase or group
3. Uses `STIX_RELATIONSHIP_MAP` for relationship type selection
4. Deduplicates relationships via Set

Returns: `{ type: 'bundle', id: 'bundle--uuid', spec_version: '2.1', objects: [...] }`

#### `addRelationship(objects, seen, sourceId, targetId, phaseKey, timestamp) → void`

Helper for `buildSTIXBundle()`. Creates an SRO relationship object between two SDOs, with deduplication.

#### `exportSTIXBundle() → void`

Standalone STIX bundle export (no kill chain state). Calls `buildSTIXBundle()`, downloads as `{title}-stix-bundle.json`.

#### `exportCSV() → void`

Builds a CSV with columns: Type, ID, Name, Score, Confidence, CVE(s), Comments, + one column per phase (X/blank). Includes STIX items. Applies CSV formula injection protection (prefixes `=+-@\t\r` with `'`). Downloads as `attack-chain-export.csv`.

---

### 5.23 IMPORT (Kill Chain)

**Lines:** ~6260–6980

#### `triggerImportKillChain() → void`

Clicks the hidden `#import-killchain-input` file input.

#### `ensureAssignmentShape(assignments) → void`

Post-import normalization. Ensures all phases have `groups`, `layout`, `customItems`, and migrated assignments. Calls `migrateAssignment()`, `ensurePhaseLayout()` for each phase.

#### `ensureLibraryFallbacks(assignments) → void`

For all assigned entity IDs not in the library, creates placeholder entries. Covers techniques, CAPECs, CWEs, and STIX custom items (creates `StixLibraryEntry` placeholders with type inferred from STIX ID prefix).

#### `KILLCHAIN_IMPORT_LIMITS` — Object

```js
{ maxFileSize: 5*1024*1024, maxAssignmentsPerPhase: 500,
  maxHyperlinks: 50, maxObservables: 100, maxStringLength: 5000 }
```

#### `validateKillChainImport(data) → { valid, error? }`

Structural validation: checks object shape, `assignments` object, schema version format, phase key format, array types, count limits.

#### `sanitizeImportedString(str, maxLength?) → string`

Strips control chars, `<script>` tags, event handlers (`onX=`), blocked chars, SQL comments. Encodes angle brackets. Truncates.

#### `sanitizeImportedAssignment(assignment) → Assignment|null`

Deep sanitization of a single assignment. Validates ID format (`T\d{4}`, `CAPEC-\d+`, `CWE-\d+`). Sanitizes score (enum), confidence (0–100), CVE entries (format + CVSS vector validation), comments, hyperlinks (URL protocol check), observables (type whitelist). Returns `null` for invalid.

#### `sanitizeImportedCustomAssignment(assignment) → Assignment|null`

Deep sanitization of a STIX custom item assignment. Validates STIX ID format via `STIX_ID_PATTERN`, verifies STIX type prefix against `VALID_STIX_TYPES`. Sanitizes metadata via shared `sanitizeAssignmentMetadata()`. Returns `null` for invalid.

#### `sanitizeAssignmentMetadata(assignment) → Metadata`

Shared metadata sanitization for both standard and STIX assignments. Validates score enum, confidence range, CVE entries (format + CVSS vectors), comments, hyperlinks (URL protocol), observables (type whitelist).

#### `sanitizeImportedData(data) → SanitizedData`

Orchestrates full sanitization of imported JSON. Processes assignments (techniques, capecs, cwes, customItems), groups, custom library, and optional view state (layers including `custom`, hideEmpty, view, activeTab including `custom`).

For `customLibrary`, validates each entry:
- STIX ID format validation
- STIX type against `VALID_STIX_TYPES`
- Name, description, labels sanitized
- Spec-defined properties preserved from `STIX_OBJECTS` definitions (boolean, integer, list, string types)
- Max 500 custom items

#### `importKillChain(event) → void`

File input handler. Pipeline: parse JSON → `stripAngleBracketsFromJson` → `validateKillChainImport` → `sanitizeImportedData` → `initAssignments` → merge → restore custom library → `ensureAssignmentShape` → `ensureLibraryFallbacks` → restore UI state → `renderAll`.

---

### 5.24 DROPDOWN UTILS

**Lines:** ~6981–7003

#### `toggleDropdown(id) → void`

Closes all dropdowns, then opens the targeted one (toggle).

#### `closeDropdowns() → void`

Removes `.open` from all `.dropdown` elements.

**Global listener:** `document.addEventListener('click', ...)` — closes dropdowns on outside click.

---

### 5.25 METADATA EDITOR

**Lines:** ~7004–7313

#### `currentMetadataEdit` — Object (Mutable)

`{ type, id, phaseKey, instanceId }` — tracks which assignment is being edited.

| Function | Signature | Description |
|----------|-----------|-------------|
| `openMetadataEditor(type, id, phaseKey, instanceId)` | Opens the metadata editor modal, populates all fields from current metadata |
| `closeMetadataEditor(event?)` | Hides modal, clears `currentMetadataEdit` |
| `selectScore(value)` | Toggles `.selected` on score option buttons |
| `updateConfidenceLabel(value)` | Updates confidence slider label text and CSS class |
| `addCveRow(id?, score?, vector?)` | Appends a CVE input row to `#cve-list` |
| `addHyperlinkRow(label?, url?)` | Appends a hyperlink input row to `#hyperlink-list` |
| `addObservableRow(type?, value?)` | Appends an observable input row with type dropdown to `#observable-list` |
| `saveMetadata()` | Reads all form fields, validates (CVEs, observables), calls `updateAssignmentMetadata()`, re-renders |

**Validation in `saveMetadata()`:**
- CVE IDs: validated via `InputSecurity.validators.cveId`
- CVSS scores: 0–10 range check
- CVSS vectors: validated via `InputSecurity.validators.cvssVector`
- URLs: validated via `InputSecurity.validators.url`
- Observables: validated via `InputSecurity.validateObservable`
- All text fields sanitized via `sanitizeForStorage()`

---

### 5.26 MODALS (Usage Guide / Changelog)

**Lines:** ~7313–7374

| Function | Description |
|----------|-------------|
| `showUsageGuide()` | Shows `#usage-guide-modal` |
| `closeUsageGuide(event?)` | Hides if click is on overlay |
| `showChangelog()` | Fetches `CHANGELOG.md`, shows content in `#changelog-modal` |
| `closeChangelog(event?)` | Hides if click is on overlay |

**Global listener:** `document.addEventListener('keydown', ...)` — Escape closes all modals.

---

### 5.27 TOAST NOTIFICATIONS

**Line:** ~7365

#### `showToast(message) → void`

Sets `#toast` text, adds `.show` class, removes after 2500ms via `setTimeout`.

---

### 5.28 INITIALIZATION

**Lines:** ~7385–7415

Executed immediately (no DOMContentLoaded wrapper — script is at end of `<body>`):

1. `initThemeControls()` — apply saved/default theme
2. `window.addEventListener('storage', ...)` — cross-tab theme sync
3. `enableLeaveSiteConfirmation()` — unless `CONFIG.navigation.confirmOnLeave === false`
4. `initAssignments()` — create empty phase data for all 18 phases
5. `initCompactMode()` — restore compact mode from localStorage
6. `window.addEventListener('resize', ...)` — reapply compact layout on resize
7. `applyInputGuards()` — attach security event listeners
8. `populateStixTypeDropdown()` — populate STIX type selects from CONFIG
9. `loadVersion()` — fetch version from CHANGELOG.md
10. `loadData()` — fetch all 6 JSON resources, render UI

---

## 6. Data Types & Shapes

### Assignment (new format)

```js
{
  id: 'T1566',                    // Entity ID
  metadata: Metadata,             // See below
  instanceId: 'inst-1706...-1'    // Unique per-assignment instance
}
```

### Assignment (legacy format — handled by migrateAssignment)

```js
'T1566'   // Bare string, auto-migrated on load
```

### Metadata

```js
{
  score: 'unclassified',          // 'unclassified' | 'low' | 'medium' | 'high' | 'critical'
  confidence: null,               // null | 0-100
  comments: '',                   // Free text
  cveEntries: [                   // Primary CVE storage (v2.5+)
    { id: 'CVE-2024-12345', score: 7.8, vector: 'CVSS:3.1/...' }
  ],
  cveId: 'CVE-2024-12345',       // Legacy: first CVE ID
  cveIds: ['CVE-2024-12345'],    // Legacy: all CVE IDs
  hyperlinks: [                   // External links
    { label: 'Advisory', url: 'https://...' }
  ],
  observables: [                  // IOCs / observables
    { type: 'ipv4-addr', value: '10.0.0.1' }
  ]
}
```

### PhaseData

```js
{
  techniques: [Assignment, ...],  // ATT&CK assignments
  capecs: [Assignment, ...],      // CAPEC assignments
  cwes: [Assignment, ...],        // CWE assignments
  customItems: [Assignment, ...], // STIX object assignments
  groups: [Group, ...],           // Named groups
  layout: [LayoutEntry, ...]      // Render order
}
```

### Group

```js
{
  groupId: 'grp-1706...-abc',
  label: 'Initial Access',
  collapsed: false,
  editing: false,                 // Transient: true during rename
  items: [GroupItem, ...]         // Assignments with type
}
```

### GroupItem (extends Assignment)

```js
{
  id: 'T1566',
  metadata: Metadata,
  instanceId: 'inst-...',
  type: 'attack'                  // 'attack' | 'capec' | 'cwe' | 'custom'
}
```

### LayoutEntry

```js
// Item entry
{ kind: 'item', type: 'attack', instanceId: 'inst-...' }

// Group entry
{ kind: 'group', groupId: 'grp-...' }
```

### CveEntry

```js
{ id: 'CVE-2024-12345', score: 7.8, vector: 'CVSS:3.1/AV:N/AC:L/...' }
```

### Library Entities

```js
// ATT&CK Technique
{
  id: 'T1566', name: 'Phishing', domain: 'enterprise',
  description: '...', tactics: ['initial-access'],
  platforms: ['Windows', 'macOS'], isSubtechnique: false,
  parentTechnique: null, version: '1.0',
  mitigations: [{ id: 'M1054', name: '...', description: '...' }],
  references: [{ name: '...', url: '...' }],
  detection: '...'
}

// CAPEC Pattern
{
  id: 'CAPEC-98', name: 'Phishing', description: '...',
  severity: 'High', likelihood: 'Medium', abstraction: 'Meta',
  techniques: ['T1566'], cwes: ['CWE-451']
}

// CWE Weakness
{
  id: 'CWE-79', name: 'Cross-site Scripting', description: '...',
  abstraction: 'Base', capecs: ['CAPEC-86']
}
```

### StixLibraryEntry (STIX Domain Object)

```js
{
  id: 'malware--a1b2c3d4-...',       // STIX 2.1 ID
  stixType: 'malware',                // SDO type
  name: 'Emotet',                     // Display name
  description: 'Banking trojan...',   // Optional description
  labels: ['trojan', 'botnet'],       // Optional labels
  customTypeName: '',                 // Only for x-custom type
  created: '2026-01-15T12:00:00Z',   // ISO 8601
  modified: '2026-02-09T10:30:00Z',  // ISO 8601
  // ... additional spec-defined fields per STIX_OBJECTS[stixType]
  is_family: true,                    // Example: malware-specific field
  malware_types: ['trojan'],          // Example: list:open-vocab field
  first_seen: '2014-01-01T00:00:00Z' // Example: timestamp field
}
```

Spec-defined fields are dynamic — the set depends on `stixType` and is determined by `STIX_OBJECTS` in `stix-config.js`.

### STIX Bundle (Export)

```js
{
  type: 'bundle',
  id: 'bundle--uuid',
  spec_version: '2.1',
  objects: [
    { type: 'malware', spec_version: '2.1', id: 'malware--...', ... },
    { type: 'threat-actor', spec_version: '2.1', id: 'threat-actor--...', ... },
    { type: 'relationship', spec_version: '2.1', id: 'relationship--...',
      relationship_type: 'uses', source_ref: '...', target_ref: '...',
      description: 'Co-located in phase IN:exploitation' }
  ]
}
```

### Export Schema (`killchain-export-lite`)

```js
{
  version: '2.7.0',
  schema: 'killchain-export-lite',
  exportedAt: '2026-02-09T12:00:00.000Z',
  title: 'APT29 Analysis',
  description: 'Analysis of APT29 intrusion...',  // Optional, defaults to ''
  view: 'killchain',
  activeTab: 'attack',
  filters: { attack: 'all', capec: 'all', cwe: 'all', custom: 'all' },
  layers: { attack: true, capec: true, cwe: true, custom: true },
  hideEmpty: false,
  assignments: { 'IN:reconnaissance': PhaseData, ... },
  selection: { type: null, id: null },
  customLibrary: { 'malware--uuid': StixLibraryEntry, ... },
  stixBundle: { type: 'bundle', id: 'bundle--...', ... }  // Embedded if custom items exist
}
```

---

## 7. Global Event Listeners

| Event | Target | Handler | Description |
|-------|--------|---------|-------------|
| `click` | `document` | Inline closure | Closes dropdowns when clicking outside |
| `keydown` | `document` | Inline closure | Escape key closes all modals (including STIX editor, create-custom) |
| `storage` | `window` | Inline closure | Syncs theme from localStorage across tabs |
| `resize` | `window` | Inline closure | Reapplies compact layout |
| `beforeunload` | `window` | `enableLeaveSiteConfirmation` inner | Leave-site confirmation |
| `keydown` | `document` | `applyInputGuards` inner | Blocks chars in `BLOCKED_INPUT_CHARS` for text inputs |
| `beforeinput` | `document` | `applyInputGuards` inner | Secondary blocker for `insertText` events |
| `paste` | `document` | `applyInputGuards` inner | Sanitizes pasted text, replacing blocked chars |
| `drop` | `document` | `applyInputGuards` inner | Sanitizes dropped text |
| `input` | `document` | `applyInputGuards` inner | Post-hoc enforcement, strips blocked chars from value |

**Inline HTML event handlers** (used in rendered HTML strings):
- `onclick` — entity selection, modal open, group toggle, score select, STIX editor open, custom item create/delete, etc.
- `ondragstart` / `ondragend` / `ondragover` / `ondragleave` / `ondrop` — drag & drop (all 4 entity types)
- `onblur` / `onkeydown` — group rename input
- `oninput` — confidence slider
- `onchange` — STIX type dropdown, custom type toggle

---

## 8. Security Model

### Defense-in-Depth Layers

1. **Output Encoding** (`InputSecurity.escapeHtml`, `InputSecurity.sanitizeAttr`)  
   All dynamic values rendered into HTML pass through `esc()` or `escAttr()` before insertion into `innerHTML` strings. This includes STIX object names, descriptions, labels, and all spec-defined fields.

2. **Input Guards** (`applyInputGuards`)  
   5 document-level event listeners block dangerous characters at keystroke, paste, and drop time for all text inputs, including STIX editor fields.

3. **Storage Sanitization** (`sanitizeForStorage`, `sanitizeUserInputText`)  
   Text entering metadata is stripped of blocked chars and normalized before being stored in `state`.

4. **Import Sanitization** (`sanitizeImportedAssignment`, `sanitizeImportedData`, `sanitizeImportedString`)  
   All imported JSON data is recursively sanitized: ID format validation, score enum validation, URL protocol checks, string sanitization, count limits.

5. **STIX Bundle Import Sanitization** (`sanitizeStixBundleObject`, `importStixBundle`)  
   Dedicated defense layer for STIX 2.1 bundle imports:
   - `STIX_BUNDLE_IMPORT_LIMITS`: max 500 objects per bundle, max 50 000 char string length.
   - STIX ID format validation via `STIX_ID_PATTERN` regex.
   - Type validation against `VALID_STIX_TYPES` (19 SDO types).
   - Per-object sanitization: all string values escaped, nested objects recursively cleaned.
   - Relationship objects are silently skipped (only SDOs accepted).
   - Custom assignment metadata (`sanitizeImportedCustomAssignment`) validates score, confidence, and sub-arrays.

6. **Data Load Sanitization** (`stripAngleBracketsFromJson`)  
   All fetched JSON resources have `<>` replaced with entities recursively.

7. **File Size Limits** (`IMPORT_LIMITS`, `KILLCHAIN_IMPORT_LIMITS`)  
   Navigator imports: 25 MB max. Kill chain imports: 5 MB max.

8. **URL Validation**  
   External links only render if they match `^https?:\/\/`. No `javascript:` or `data:` URLs.

9. **CSV Formula Injection** (`sanitizeForCsv` in `exportCSV`)  
   Cells starting with `=+-@\t\r` are prefixed with `'`.

### Security Tags

Functions tagged with `KCE-SEC-XXX` comments:
- `KCE-SEC-003` — Navigator import validation
- `KCE-SEC-004` — CSV formula injection prevention

---

## 9. Module Mapping (Current → v3.0)

This table maps the current monolithic code to the planned 5-module structure defined in `DETACH.md`. Includes STIX additions.

| Planned Module | Current Code (index.html lines) | Key Functions |
|----------------|--------------------------------|---------------|
| **stix-config.js** | Standalone file (576 lines) | `STIX_COMMON_PROPERTIES`, `STIX_VOCABULARIES`, `STIX_OBJECTS`, `STIX_RELATIONSHIP_DEFAULTS`, `getStixFieldsForType()`, `getStixTypeKeys()`, `getStixTypeLabel()`, `getStixVocabulary()` |
| **af-security.js** | ~2647–2924 | `InputSecurity`, `esc()`, `escAttr()`, `BLOCKED_INPUT_CHARS`, `isTextInputElement()`, `sanitizeUserInputText()`, `sanitizeForStorage()`, `truncateAtBoundary()`, `applyInputGuards()`, `stripAngleBracketsFromJson()` |
| **af-core.js** | ~2624–2643, ~2928–3620 | `APP_VERSION`, `loadVersion()`, `createDefaultMetadata()`, `getCveEntries()`, `getCveList()`, `normalizeCveMetadata()`, `getConfidenceLabel()`, `getConfidenceClass()`, `createAssignmentInstanceId()`, `migrateAssignment()`, `getAssignmentId()`, `getAssignmentMetadata()`, `getAssignmentInstanceId()`, phase item accessors, `ensurePhaseLayout()`, group management, `findAssignment()`, `updateAssignmentMetadata()`, `SCORE_LEVELS`, `OBSERVABLE_TYPES`, `state`, `KILL_CHAIN`, `ALL_PHASES`, `formatPhaseName()`, `initAssignments()`, `loadData()`, `loadNavigator()`, `detectDomain()`, `getTechniqueName()`, `TYPE_KEYS`, `TAG_CLASSES`, `TYPE_LABELS`, `ALL_ENTITY_TYPES`, `STIX_ID_PATTERN`, `VALID_STIX_TYPES`, `STIX_RELATIONSHIP_MAP`, `generateUUID()`, `generateStixId()` |
| **af-ui.js** | ~3625–5165 | `setView()`, `toggleSidebar()`, `toggleLayer()`, theme functions, compact mode functions, `switchTab()`, `setFilter()`, `filterEntities()`, `selectEntity()`, `buildEntityDetail()`, `buildMetadataSummary()`, `buildStixPropertySummary()`, `openEntityModal()`, `showDetail()`, `closeDetail()`, `findEntityPhase()`, `openMitigationExplorer()`, `openEntityExplorer()`, all drag handlers, `renderKillChain()`, `renderEntityTag()`, `renderRelationshipView()`, `renderStats()`, `togglePhase()`, `removeAssignment()`, `expandAll()`, `collapseAll()`, `clearAssignments()`, `openStixEditor()`, `closeStixEditor()`, `saveStixEditor()`, `buildStixFieldFromSpec()`, `buildStixTextField()`, `buildStixTextareaField()`, `buildStixReadonlyField()`, `getEntityName()`, `populateStixTypeDropdown()`, `toggleCustomTypeName()`, `openCreateCustomModal()`, `closeCreateCustomModal()`, `createCustomItem()`, `deleteCustomItem()` |
| **af-io.js** | ~5165–5600 | `exportJSON()`, `exportCSV()`, `buildSTIXBundle()`, `addRelationship()`, `exportSTIXBundle()`, `triggerImportKillChain()`, `ensureAssignmentShape()`, `ensureLibraryFallbacks()`, `KILLCHAIN_IMPORT_LIMITS`, `validateKillChainImport()`, `sanitizeImportedString()`, `sanitizeImportedAssignment()`, `sanitizeImportedCustomAssignment()`, `sanitizeAssignmentMetadata()`, `sanitizeImportedData()`, `importKillChain()`, `importStixBundle()`, `sanitizeStixBundleObject()`, `STIX_BUNDLE_IMPORT_LIMITS`, `IMPORT_LIMITS`, `importNavigator()` |
| **af-app.js** | ~5600–7415 | `toggleDropdown()`, `closeDropdowns()`, `currentMetadataEdit`, `currentStixEdit`, `openMetadataEditor()`, `closeMetadataEditor()`, `selectScore()`, `updateConfidenceLabel()`, `addCveRow()`, `addHyperlinkRow()`, `addObservableRow()`, `saveMetadata()`, `showUsageGuide()`, `closeUsageGuide()`, `showChangelog()`, `closeChangelog()`, `showToast()`, `renderAll()`, `enableLeaveSiteConfirmation()`, initialization block |

---

## Function Index (Alphabetical)

| Function | Section | Line (approx.) |
|----------|---------|-----------------|
| `addCveRow` | Metadata Editor | ~5465 |
| `addHyperlinkRow` | Metadata Editor | ~5500 |
| `addObservableRow` | Metadata Editor | ~5520 |
| `addRelationship` | Export (STIX Bundle) | ~5250 |
| `applyCompactLayout` | Compact Mode | ~3740 |
| `applyConfigColors` | config.js | 198 |
| `applyInputGuards` | Input Security | ~2818 |
| `applyTheme` | Theme Runtime | ~3570 |
| `buildEntityDetail` | Selection & Detail | ~3955 |
| `buildMetadataSummary` | Selection & Detail | ~4100 |
| `buildSTIXBundle` | Export (STIX Bundle) | ~5200 |
| `buildStixFieldFromSpec` | STIX Editor Modal | ~4950 |
| `buildStixPropertySummary` | STIX Editor Modal | ~5140 |
| `buildStixReadonlyField` | STIX Editor Modal | ~5020 |
| `buildStixTextareaField` | STIX Editor Modal | ~5000 |
| `buildStixTextField` | STIX Editor Modal | ~4980 |
| `clearAssignments` | Utilities | ~4780 |
| `closeChangelog` | Modals | ~5738 |
| `closeCreateCustomModal` | STIX Item Management | ~4650 |
| `closeDetail` | Selection & Detail | ~4185 |
| `closeDropdowns` | Dropdown Utils | ~5400 |
| `closeEntityModal` | Selection & Detail | ~4150 |
| `closeMetadataEditor` | Metadata Editor | ~5435 |
| `closeStixEditor` | STIX Editor Modal | ~4920 |
| `closeUsageGuide` | Modals | ~5715 |
| `collapseAll` | Utilities | ~4776 |
| `commitKillChainDescription` | State | ~4100 |
| `commitKillChainTitle` | State | ~3985 |
| `commitRenameGroup` | Group Management | ~3155 |
| `createAssignmentInstanceId` | Metadata Helpers | ~3001 |
| `createCustomItem` | STIX Item Management | ~4670 |
| `createDefaultMetadata` | Metadata Helpers | ~2928 |
| `createGroup` | Group Management | ~3110 |
| `deleteCustomItem` | STIX Item Management | ~4850 |
| `detectDomain` | Navigator | ~3518 |
| `enableLeaveSiteConfirmation` | Initialization | ~5753 |
| `ensureAssignmentShape` | Import | ~4820 |
| `ensureLibraryFallbacks` | Import | ~4850 |
| `ensurePhaseLayout` | Assignment Logic | ~3060 |
| `esc` | Helper Alias | ~2795 |
| `escAttr` | Helper Alias | ~2796 |
| `expandAll` | Utilities | ~4772 |
| `exportCSV` | Export | ~5350 |
| `exportJSON` | Export | ~5165 |
| `exportSTIXBundle` | Export (STIX Bundle) | ~5300 |
| `extractAssignmentInstance` | Group Management | ~3185 |
| `filterEntities` | Entity Rendering | ~3800 |
| `findAssignment` | Assignment Logic | ~3210 |
| `findEntityPhase` | Selection & Detail | ~4190 |
| `formatPhaseName` | State | ~3370 |
| `generateGroupId` | Group Management | ~3100 |
| `generateStixId` | Type Mapping Constants | ~3610 |
| `generateUUID` | Type Mapping Constants | ~3600 |
| `getAllPhaseItemsByType` | Assignment Logic | ~3050 |
| `getAssignmentId` | Assignment Logic | ~3010 |
| `getAssignmentInstanceId` | Assignment Logic | ~3030 |
| `getAssignmentMetadata` | Assignment Logic | ~3020 |
| `getConfidenceClass` | Metadata Helpers | ~2992 |
| `getConfidenceLabel` | Metadata Helpers | ~2984 |
| `getCveEntries` | Metadata Helpers | ~2946 |
| `getCveList` | Metadata Helpers | ~2960 |
| `getEntityName` | STIX Editor Modal | ~5110 |
| `getPhaseGroupedItems` | Assignment Logic | ~3045 |
| `getPhaseUngroupedItems` | Assignment Logic | ~3040 |
| `getPreferredThemeMode` | Theme Runtime | ~3548 |
| `getStixFieldsForType` | stix-config.js | — |
| `getStixTypeKeys` | stix-config.js | — |
| `getStixTypeLabel` | stix-config.js | — |
| `getStixVocabulary` | stix-config.js | — |
| `getTechniqueName` | Navigator | ~3525 |
| `handleAssignmentDragStart` | Drag & Drop | ~4310 |
| `handleDragEnd` | Drag & Drop | ~4225 |
| `handleDragLeave` | Drag & Drop | ~4238 |
| `handleDragOver` | Drag & Drop | ~4233 |
| `handleDragStart` | Drag & Drop | ~4210 |
| `handleDrop` | Drag & Drop | ~4242 |
| `handleGroupDragStart` | Drag & Drop | ~4325 |
| `handleGroupDrop` | Drag & Drop | ~4340 |
| `importKillChain` | Import | ~5155 |
| `importNavigator` | Navigator | ~3440 |
| `importStixBundle` | STIX Item Management | ~4580 |
| `initAssignments` | State | ~3375 |
| `initCompactMode` | Compact Mode | ~3720 |
| `initThemeControls` | Theme Runtime | ~3598 |
| `isEntityAssigned` | Entity Rendering | ~3920 |
| `isTextInputElement` | Input Security | ~2799 |
| `loadData` | Data Loading | ~3380 |
| `loadNavigator` | Data Loading | ~3397 |
| `loadVersion` | Version | ~2630 |
| `migrateAssignment` | Metadata Helpers | ~3003 |
| `moveGroupBetweenPhases` | Group Management | ~3200 |
| `normalizeCveMetadata` | Metadata Helpers | ~2964 |
| `normalizeThemeMode` | Theme Runtime | ~3558 |
| `normalizeThemeScheme` | Theme Runtime | ~3563 |
| `openCreateCustomModal` | STIX Item Management | ~4640 |
| `openEntityExplorer` | Selection & Detail | ~3773 |
| `openEntityModal` | Selection & Detail | ~4140 |
| `openMetadataEditor` | Metadata Editor | ~5420 |
| `openMitigationExplorer` | Selection & Detail | ~3760 |
| `openStixEditor` | STIX Editor Modal | ~4895 |
| `populateStixTypeDropdown` | STIX Item Management | ~4610 |
| `removeAssignment` | Utilities | ~4745 |
| `removeGroup` | Group Management | ~3170 |
| `renderAll` | Initialization | ~5750 |
| `renderEntityTag` | Kill Chain Rendering | ~4558 |
| `renderKillChain` | Kill Chain Rendering | ~4383 |
| `renderRelationshipView` | Relationship View | ~4590 |
| `renderStats` | Stats | ~4720 |
| `resolveTheme` | config.js | 187 |
| `sanitizeAssignmentMetadata` | Import | ~5050 |
| `sanitizeForCsv` | Export (inline) | ~5370 |
| `sanitizeForStorage` | Input Security | ~2808 |
| `sanitizeImportedAssignment` | Import | ~4920 |
| `sanitizeImportedCustomAssignment` | Import | ~5030 |
| `sanitizeImportedData` | Import | ~5065 |
| `sanitizeImportedString` | Import | ~4895 |
| `sanitizeStixBundleObject` | STIX Item Management | ~4590 |
| `sanitizeUserInputText` | Input Security | ~2801 |
| `saveMetadata` | Metadata Editor | ~5555 |
| `saveStixEditor` | STIX Editor Modal | ~4935 |
| `selectEntity` | Selection & Detail | ~3935 |
| `selectScore` | Metadata Editor | ~5440 |
| `setCompactMode` | Compact Mode | ~3690 |
| `setFilter` | Tab & Filter | ~3795 |
| `setView` | View Controls | ~3625 |
| `showChangelog` | Modals | ~5725 |
| `showDetail` | Selection & Detail | ~4160 |
| `showToast` | Toast | ~5748 |
| `showUsageGuide` | Modals | ~5710 |
| `startRenameGroup` | Group Management | ~3145 |
| `syncDescriptionToDOM` | State | ~4110 |
| `syncTitleToDOM` | State | ~3995 |
| `toggleCustomTypeName` | STIX Item Management | ~4625 |
| `toggleDescriptionPanel` | State | ~4128 |
| `toggleDropdown` | Dropdown Utils | ~5395 |
| `toggleLayer` | Layer Toggle | ~3660 |
| `togglePhase` | Kill Chain Rendering | ~4500 |
| `toggleSidebar` | View Controls | ~3640 |
| `stripAngleBracketsFromJson` | Input Security | 2908 |
| `switchTab` | Tab & Filter | 3785 |
| `syncThemeFromStorage` | Theme Runtime | 3610 |
| `toggleCompactMode` | Compact Mode | 3715 |
| `toggleDropdown` | Dropdown Utils | 5395 |
| `toggleGroupCollapse` | Group Management | 3135 |
| `toggleHideEmpty` | Compact Mode | 3755 |
| `toggleLayer` | View Controls | 3660 |
| `togglePhase` | Utilities | 4740 |
| `toggleSidebar` | View Controls | 3650 |
| `toggleThemeMode` | Theme Runtime | 3593 |
| `triggerImportKillChain` | Import | 4815 |
| `truncateAtBoundary` | Input Security | 2814 |
| `updateAssignmentMetadata` | Assignment Logic | 3240 |
| `updateCompactControls` | Compact Mode | 3680 |
| `updateConfidenceLabel` | Metadata Editor | 5450 |
| `updateDescriptionCounter` | State | ~4148 |
| `updateDescriptionHint` | State | ~4135 |
| `updateHideEmptyControl` | Compact Mode | 3670 |
| `updateThemeControls` | Theme Runtime | 3588 |
| `validateKillChainImport` | Import | 4880 |
| `validateObservable` | Input Security | 2790 |

---

*Generated for AttackFlow v2.7.0. This document describes the monolithic implementation as it exists today, including STIX 2.1 support. For the planned v3.0 modular architecture, see [DETACH.md](DETACH.md), [API_DOCS.md](API_DOCS.md), and [tests/TEST_PLAN.md](tests/TEST_PLAN.md).*
