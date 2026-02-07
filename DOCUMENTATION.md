# AttackFlow — Monolithic API Reference

> **Version:** 2.5.3  
> **Scope:** Documents the current inline JavaScript implementation in `index.html` and the companion `config.js`.  
> **Purpose:** Serve as the definitive reference for the v3.0 modular refactoring (see `DETACH.md`).

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [File Map](#2-file-map)
3. [config.js — Configuration & Theme Engine](#3-configjs--configuration--theme-engine)
4. [Inline JS Sections (index.html)](#4-inline-js-sections-indexhtml)
   - 4.1 [VERSION](#41-version)
   - 4.2 [INPUT SECURITY](#42-input-security)
   - 4.3 [METADATA HELPERS](#43-metadata-helpers)
   - 4.4 [ASSIGNMENT & PHASE LOGIC](#44-assignment--phase-logic)
   - 4.5 [GROUP MANAGEMENT](#45-group-management)
   - 4.6 [CONSTANTS & STATE](#46-constants--state)
   - 4.7 [DATA LOADING](#47-data-loading)
   - 4.8 [NAVIGATOR IMPORT](#48-navigator-import)
   - 4.9 [VIEW & LAYER CONTROLS](#49-view--layer-controls)
   - 4.10 [THEME RUNTIME](#410-theme-runtime)
   - 4.11 [COMPACT MODE](#411-compact-mode)
   - 4.12 [TAB & FILTER CONTROLS](#412-tab--filter-controls)
   - 4.13 [ENTITY LIST RENDERING](#413-entity-list-rendering)
   - 4.14 [SELECTION & DETAIL PANEL](#414-selection--detail-panel)
   - 4.15 [DRAG & DROP](#415-drag--drop)
   - 4.16 [KILL CHAIN RENDERING](#416-kill-chain-rendering)
   - 4.17 [RELATIONSHIP VIEW](#417-relationship-view)
   - 4.18 [STATS & UTILITIES](#418-stats--utilities)
   - 4.19 [EXPORT (JSON / CSV)](#419-export-json--csv)
   - 4.20 [IMPORT (Kill Chain)](#420-import-kill-chain)
   - 4.21 [DROPDOWN UTILS](#421-dropdown-utils)
   - 4.22 [METADATA EDITOR](#422-metadata-editor)
   - 4.23 [MODALS (Usage Guide / Changelog)](#423-modals-usage-guide--changelog)
   - 4.24 [TOAST NOTIFICATIONS](#424-toast-notifications)
   - 4.25 [INITIALIZATION](#425-initialization)
5. [Data Types & Shapes](#5-data-types--shapes)
6. [Global Event Listeners](#6-global-event-listeners)
7. [Security Model](#7-security-model)
8. [Module Mapping (Current → v3.0)](#8-module-mapping-current--v30)

---

## 1. Architecture Overview

AttackFlow is a **single-page application** with all JavaScript inlined inside `index.html` (≈ 3,150 lines, starting at line 2624). A companion `config.js` is loaded via a `<script>` tag before the inline block. There is no build step, no bundler, and no module system — every function and variable lives in the global scope.

```
┌────────────────────────────────────────────────────────┐
│  Browser (index.html)                                  │
│                                                        │
│  <script src="config.js">                              │
│    CONFIG, resolveTheme(), applyConfigColors()          │
│                                                        │
│  <script> (inline, lines 2624-5775)                    │
│    VERSION → SECURITY → METADATA → ASSIGNMENTS →       │
│    GROUPS → STATE → DATA → NAVIGATOR → VIEWS →         │
│    THEME → COMPACT → TABS → ENTITIES → DETAIL →        │
│    DND → RENDERING → RELATIONSHIPS → STATS →           │
│    EXPORT → IMPORT → DROPDOWN → META-EDITOR →          │
│    MODALS → TOAST → INIT                               │
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

---

## 2. File Map

| File | Role | Lines |
|------|------|-------|
| `config.js` | CONFIG object, `resolveTheme()`, `applyConfigColors()` | 226 |
| `index.html` | HTML structure (1–2623), CSS (embedded), inline JS (2624–5775) | 5,778 |
| `resources/attack-techniques.json` | ATT&CK technique library | Fetched at runtime |
| `resources/capec-full.json` | CAPEC pattern library | Fetched at runtime |
| `resources/cwe-full.json` | CWE weakness library | Fetched at runtime |
| `resources/technique-to-capec.json` | ATT&CK → CAPEC mapping | Fetched at runtime |
| `resources/capec-to-technique.json` | CAPEC → ATT&CK mapping | Fetched at runtime |
| `resources/cwe-to-capec.json` | CWE → CAPEC mapping | Fetched at runtime |
| `resources/Nav_Layer_*.json` | ATT&CK Navigator layers (ENTERPRISE, ICS, MOBILE) | Loaded on demand |

---

## 3. config.js — Configuration & Theme Engine

**Source:** `config.js` (226 lines)

### 3.1 `CONFIG` Object

Top-level configuration constant. Properties:

| Property | Type | Description |
|----------|------|-------------|
| `version` | `string` | Application version (`'2.5.3'`) |
| `changelogUrl` | `string` | Path to CHANGELOG.md |
| `sources.capec` | `{domains, mechanisms}` | Paths to CAPEC XML source files |
| `sources.cwe` | `{hardware, software, all}` | Paths to CWE XML source files |
| `sources.attack` | `{version, enterprise, mobile, ics}` | ATT&CK STIX bundle paths & version |
| `sanitize.paths` | `string[]` | Glob patterns for JSON sanitization |
| `phases` | `{in, through, out}` | Hex colors for kill chain super-phases |
| `frameworks` | `{attack, capec, cwe}` | Hex colors for framework entity types |
| `ui` | `object` | UI fallback colors (bg, text, border, accent) |
| `metaIcons` | `object` | Metadata icon colors (CVE, observable, link, comment, confidence) |
| `themes` | `{dark: {default: ...}, light: {default: ...}}` | Theme presets with ui + metaIcons overrides |
| `themeDefaults` | `{mode, scheme}` | Default theme mode (`'light'`) and scheme (`'default'`) |
| `themeMode` | `string` | Initial mode: `'light'`, `'dark'`, or `'auto'` |
| `display` | `object` | Max lengths for names, descriptions, mitigations, references |
| `navigation` | `{confirmOnLeave}` | Whether to show leave-site confirmation |

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

## 4. Inline JS Sections (index.html)

All line numbers below refer to `index.html`.

---

### 4.1 VERSION

**Lines:** 2624–2643

#### `APP_VERSION`

**Type:** `let string`  
Fallback `'2.4.2'`. Overwritten by `loadVersion()`.

#### `loadVersion() → Promise<void>`

Fetches `CHANGELOG.md`, extracts the first `## [x.y.z]` match via regex, and sets both `APP_VERSION` and the `#app-version` element's text.

---

### 4.2 INPUT SECURITY

**Lines:** 2647–2924

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

### 4.3 METADATA HELPERS

**Lines:** 2928–3010

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

### 4.4 ASSIGNMENT & PHASE LOGIC

**Lines:** 3010–3100

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

### 4.5 GROUP MANAGEMENT

**Lines:** 3100–3210

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

### 4.6 CONSTANTS & STATE

**Lines:** 3270–3390

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
| `layers` | `object` | `{attack:true, capec:true, cwe:true}` | Visibility toggles per framework |
| `hideEmpty` | `boolean` | `false` | Whether to hide empty phases |
| `compactMode` | `boolean` | `false` | Whether compact layout is active |
| `activeTab` | `string` | `'attack'` | Active sidebar tab |
| `filters` | `object` | `{attack:'all', capec:'all', cwe:'all'}` | Filter selections per tab |
| `library` | `object` | `{techniques:{}, capecs:{}, cwes:{}}` | Loaded entity libraries (keyed by ID) |
| `techniqueToCapec` | `object` | `{}` | `T1234 → ['CAPEC-123', ...]` mapping |
| `cweToCapec` | `object` | `{}` | `CWE-79 → ['CAPEC-86', ...]` mapping |
| `capecToTechnique` | `object` | `{}` | `CAPEC-123 → ['T1234', ...]` mapping |
| `assignments` | `object` | `{}` | Phase → PhaseData mapping (18 phases) |
| `title` | `string` | `''` | Editable kill chain title (max 200 chars) |
| `selection` | `object` | `{type:null, id:null}` | Currently selected entity |

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

Initializes `state.assignments` with empty `PhaseData` for each of the 18 phases. Also resets `state.title` to `''` and syncs the DOM.

#### `commitKillChainTitle(el) → void`

Sanitizes the title input value via `sanitizeForStorage()`, caps at `CONFIG.display.maxTitleLength`, and stores in `state.title`.

#### `syncTitleToDOM() → void`

Sets the `#kill-chain-title` input's value from `state.title`.

---

### 4.7 DATA LOADING

**Lines:** 3380–3400

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

### 4.8 NAVIGATOR IMPORT

**Lines:** 3427–3530

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

### 4.9 VIEW & LAYER CONTROLS

**Lines:** 3533–3580

#### `setView(view) → void`

Switches between `'killchain'`, `'relationship'`, and `'explorer'` views. Toggles visibility of containers, buttons, stats bar, legend. Calls `renderRelationshipView()` if entering relationship view. Updates compact/hide-empty controls.

#### `toggleSidebar() → void`

Toggles `sidebar-collapsed` class on `.app`.

#### `toggleLayer(layer) → void`

Toggles `state.layers[layer]` from checkbox state, re-renders kill chain and relationship view.

---

### 4.10 THEME RUNTIME

**Lines:** 3536–3620

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

### 4.11 COMPACT MODE

**Lines:** 3670–3760

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

### 4.12 TAB & FILTER CONTROLS

**Lines:** 3780–3800

#### `switchTab(tab) → void`

Sets `state.activeTab`, toggles `.active` on sidebar tabs and panels.

#### `setFilter(type, filter) → void`

Sets `state.filters[type]`, toggles `.active` on filter buttons, calls `filterEntities(type)`.

---

### 4.13 ENTITY LIST RENDERING

**Lines:** 3800–3920

#### `filterEntities(type) → void`

Reads search input and filter state, filters the entity library (`techniques`, `capecs`, or `cwes`), builds HTML for up to 100 results, sets `listEl.innerHTML`. Each entity item is `draggable` with inline `ondragstart` / `ondragend` / `onclick` handlers.

**Filters by type:**
- `attack`: search by id/name, filter by domain
- `capec`: search by id/name, filter by abstraction level
- `cwe`: search by id/name, filter by abstraction level

#### `isEntityAssigned(type, id) → boolean`

Iterates all phases checking whether entity is assigned anywhere.

---

### 4.14 SELECTION & DETAIL PANEL

**Lines:** 3930–4200

#### `selectEntity(type, id) → void`

Sets `state.selection`, refreshes entity list, shows detail panel.

#### `buildEntityDetail(type, id) → { id, name, html }`

Builds HTML detail view for ATT&CK technique, CAPEC pattern, or CWE weakness. Includes:
- Description, attributes, related entities
- Mitigations (ATT&CK only, max 8 shown)
- References with safe URL validation (`https?://`)
- Cross-entity navigation (`onclick` → `selectEntity`)
- External links to MITRE websites

#### `buildMetadataSummary(type, id, phaseKey?, instanceId?) → string`

Builds HTML for metadata display: score, confidence, CVE entries, comments, hyperlinks, observables. Used inside entity modal.

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

### 4.15 DRAG & DROP

**Lines:** 4205–4380

#### `dragData` — Object (Mutable)

```js
{ kind: null, type: null, id: null, fromPhase: null,
  instanceId: null, groupId: null, sourceGroupId: null }
```

| Function | Signature | Description |
|----------|-----------|-------------|
| `handleDragStart(event, type, id)` | Sidebar entity drag start. Sets `dragData.kind='item'`, highlights phases. |
| `handleDragEnd(event)` | Removes drag styling and clears `dragData`. |
| `handleDragOver(event)` | Prevents default, sets drop effect, adds background highlight. |
| `handleDragLeave(event)` | Removes background highlight. |
| `handleDrop(event, phaseKey)` | Phase drop handler. Routes to `moveGroupBetweenPhases` for groups, else adds/moves assignment. Creates new assignment with `createDefaultMetadata()` or preserves metadata from source. Re-renders. |
| `handleAssignmentDragStart(event, type, id, phaseKey, instanceId, sourceGroupId)` | Drag start for already-assigned entities. Sets `dragData.fromPhase`. |
| `handleGroupDragStart(event, phaseKey, groupId)` | Group drag start. Sets `dragData.kind='group'`. |
| `handleGroupDrop(event, phaseKey, groupId)` | Drop into a group. Extracts from source, adds to target group. |

---

### 4.16 KILL CHAIN RENDERING

**Lines:** 4383–4555

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
Builds HTML for a single entity tag (technique, CAPEC, or CWE). Features:
- Score-based `data-score` attribute for CSS styling
- Domain badge (ENT/MOB/ICS) for ATT&CK techniques
- Metadata icons: CVE, observables, links, comments, confidence
- Compact mode: hides name, shows metadata icons in header
- Action buttons: remove, explore, edit metadata
- Drag handlers for reassignment

---

### 4.17 RELATIONSHIP VIEW

**Lines:** 4590–4720

#### `renderRelationshipView() → void`

Builds relationship chains from assigned CAPECs. For each phase:
1. Finds assigned CAPECs and their related CWEs + techniques
2. Finds assigned techniques without CAPECs (partial chains)
3. Renders 4-column rows: CAPEC → CWE → ATT&CK → Phase

---

### 4.18 STATS & UTILITIES

**Lines:** 4720–4790

#### `renderStats() → void`

Counts unique techniques, CAPECs, CWEs, and phases used across all assignments. Updates `#stats-bar` innerHTML.

#### `togglePhase(header) → void`

Toggles `.minimized` class on the phase element (collapse/expand).

#### `removeAssignment(type, id, phaseKey, instanceId) → void`

Confirms via `window.confirm`, removes from ungrouped array or group items, cleans layout, re-renders.

#### `expandAll() / collapseAll() → void`

Expands/collapses all `.phase` elements.

#### `clearAssignments() → void`

Calls `initAssignments()`, re-renders everything.

---

### 4.19 EXPORT (JSON / CSV)

**Lines:** 4790–4815 (JSON), 5202–5390 (CSV)

#### `exportJSON() → void`

Creates a JSON blob with: `version`, `schema: 'killchain-export-lite'`, `exportedAt`, `view`, `activeTab`, `filters`, `layers`, `hideEmpty`, `assignments`, `selection`. Downloads as `attack-chain-export.json`.

#### `exportCSV() → void`

Builds a CSV with columns: Type, ID, Name, Score, Confidence, CVE(s), Comments, + one column per phase (X/blank). Applies CSV formula injection protection (prefixes `=+-@\t\r` with `'`). Downloads as `attack-chain-export.csv`.

---

### 4.20 IMPORT (Kill Chain)

**Lines:** 4815–5200

#### `triggerImportKillChain() → void`

Clicks the hidden `#import-killchain-input` file input.

#### `ensureAssignmentShape(assignments) → void`

Post-import normalization. Ensures all phases have `groups`, `layout`, and migrated assignments. Calls `migrateAssignment()`, `ensurePhaseLayout()` for each phase.

#### `ensureLibraryFallbacks(assignments) → void`

For all assigned entity IDs not in the library, creates placeholder entries.

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

#### `sanitizeImportedData(data) → SanitizedData`

Orchestrates full sanitization of imported JSON. Processes assignments, groups, and optional view state (layers, hideEmpty, view, activeTab).

#### `importKillChain(event) → void`

File input handler. Pipeline: parse JSON → `stripAngleBracketsFromJson` → `validateKillChainImport` → `sanitizeImportedData` → `initAssignments` → merge → `ensureAssignmentShape` → `ensureLibraryFallbacks` → restore UI state → `renderAll`.

---

### 4.21 DROPDOWN UTILS

**Lines:** 5392–5410

#### `toggleDropdown(id) → void`

Closes all dropdowns, then opens the targeted one (toggle).

#### `closeDropdowns() → void`

Removes `.open` from all `.dropdown` elements.

**Global listener:** `document.addEventListener('click', ...)` — closes dropdowns on outside click.

---

### 4.22 METADATA EDITOR

**Lines:** 5415–5620

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

### 4.23 MODALS (Usage Guide / Changelog)

**Lines:** 5700–5740

| Function | Description |
|----------|-------------|
| `showUsageGuide()` | Shows `#usage-guide-modal` |
| `closeUsageGuide(event?)` | Hides if click is on overlay |
| `showChangelog()` | Fetches `CHANGELOG.md`, shows content in `#changelog-modal` |
| `closeChangelog(event?)` | Hides if click is on overlay |

**Global listener:** `document.addEventListener('keydown', ...)` — Escape closes all modals.

---

### 4.24 TOAST NOTIFICATIONS

**Line:** 5748

#### `showToast(message) → void`

Sets `#toast` text, adds `.show` class, removes after 2500ms via `setTimeout`.

---

### 4.25 INITIALIZATION

**Lines:** 5756–5775

Executed immediately (no DOMContentLoaded wrapper — script is at end of `<body>`):

1. `initThemeControls()` — apply saved/default theme
2. `window.addEventListener('storage', ...)` — cross-tab theme sync
3. `enableLeaveSiteConfirmation()` — unless `CONFIG.navigation.confirmOnLeave === false`
4. `initAssignments()` — create empty phase data for all 18 phases
5. `initCompactMode()` — restore compact mode from localStorage
6. `window.addEventListener('resize', ...)` — reapply compact layout on resize
7. `applyInputGuards()` — attach security event listeners
8. `loadVersion()` — fetch version from CHANGELOG.md
9. `loadData()` — fetch all 6 JSON resources, render UI

---

## 5. Data Types & Shapes

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
  type: 'attack'                  // 'attack' | 'capec' | 'cwe'
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

### Export Schema (`killchain-export-lite`)

```js
{
  version: '2.5.3',
  schema: 'killchain-export-lite',
  exportedAt: '2026-01-30T12:00:00.000Z',
  view: 'killchain',
  activeTab: 'attack',
  filters: { attack: 'all', capec: 'all', cwe: 'all' },
  layers: { attack: true, capec: true, cwe: true },
  hideEmpty: false,
  assignments: { 'IN:reconnaissance': PhaseData, ... },
  selection: { type: null, id: null }
}
```

---

## 6. Global Event Listeners

| Event | Target | Handler | Description |
|-------|--------|---------|-------------|
| `click` | `document` | Inline closure | Closes dropdowns when clicking outside |
| `keydown` | `document` | Inline closure | Escape key closes all modals |
| `storage` | `window` | Inline closure | Syncs theme from localStorage across tabs |
| `resize` | `window` | Inline closure | Reapplies compact layout |
| `beforeunload` | `window` | `enableLeaveSiteConfirmation` inner | Leave-site confirmation |
| `keydown` | `document` | `applyInputGuards` inner | Blocks chars in `BLOCKED_INPUT_CHARS` for text inputs |
| `beforeinput` | `document` | `applyInputGuards` inner | Secondary blocker for `insertText` events |
| `paste` | `document` | `applyInputGuards` inner | Sanitizes pasted text, replacing blocked chars |
| `drop` | `document` | `applyInputGuards` inner | Sanitizes dropped text |
| `input` | `document` | `applyInputGuards` inner | Post-hoc enforcement, strips blocked chars from value |

**Inline HTML event handlers** (used in rendered HTML strings):
- `onclick` — entity selection, modal open, group toggle, score select, etc.
- `ondragstart` / `ondragend` / `ondragover` / `ondragleave` / `ondrop` — drag & drop
- `onblur` / `onkeydown` — group rename input
- `oninput` — confidence slider

---

## 7. Security Model

### Defense-in-Depth Layers

1. **Output Encoding** (`InputSecurity.escapeHtml`, `InputSecurity.sanitizeAttr`)  
   All dynamic values rendered into HTML pass through `esc()` or `escAttr()` before insertion into `innerHTML` strings.

2. **Input Guards** (`applyInputGuards`)  
   5 document-level event listeners block dangerous characters at keystroke, paste, and drop time for all text inputs.

3. **Storage Sanitization** (`sanitizeForStorage`, `sanitizeUserInputText`)  
   Text entering metadata is stripped of blocked chars and normalized before being stored in `state`.

4. **Import Sanitization** (`sanitizeImportedAssignment`, `sanitizeImportedData`, `sanitizeImportedString`)  
   All imported JSON data is recursively sanitized: ID format validation, score enum validation, URL protocol checks, string sanitization, count limits.

5. **Data Load Sanitization** (`stripAngleBracketsFromJson`)  
   All fetched JSON resources have `<>` replaced with entities recursively.

6. **File Size Limits** (`IMPORT_LIMITS`, `KILLCHAIN_IMPORT_LIMITS`)  
   Navigator imports: 25 MB max. Kill chain imports: 5 MB max.

7. **URL Validation**  
   External links only render if they match `^https?:\/\/`. No `javascript:` or `data:` URLs.

8. **CSV Formula Injection** (`sanitizeForCsv` in `exportCSV`)  
   Cells starting with `=+-@\t\r` are prefixed with `'`.

### Security Tags

Functions tagged with `KCE-SEC-XXX` comments:
- `KCE-SEC-003` — Navigator import validation
- `KCE-SEC-004` — CSV formula injection prevention

---

## 8. Module Mapping (Current → v3.0)

This table maps the current monolithic code to the planned 5-module structure defined in `DETACH.md`.

| Planned Module | Current Code (index.html lines) | Key Functions |
|----------------|--------------------------------|---------------|
| **af-security.js** | 2647–2924 | `InputSecurity`, `esc()`, `escAttr()`, `BLOCKED_INPUT_CHARS`, `isTextInputElement()`, `sanitizeUserInputText()`, `sanitizeForStorage()`, `truncateAtBoundary()`, `applyInputGuards()`, `stripAngleBracketsFromJson()` |
| **af-core.js** | 2624–2643, 2928–3400 | `APP_VERSION`, `loadVersion()`, `createDefaultMetadata()`, `getCveEntries()`, `getCveList()`, `normalizeCveMetadata()`, `getConfidenceLabel()`, `getConfidenceClass()`, `createAssignmentInstanceId()`, `migrateAssignment()`, `getAssignmentId()`, `getAssignmentMetadata()`, `getAssignmentInstanceId()`, phase item accessors, `ensurePhaseLayout()`, group management, `findAssignment()`, `updateAssignmentMetadata()`, `SCORE_LEVELS`, `OBSERVABLE_TYPES`, `state`, `KILL_CHAIN`, `ALL_PHASES`, `formatPhaseName()`, `initAssignments()`, `loadData()`, `loadNavigator()`, `detectDomain()`, `getTechniqueName()` |
| **af-ui.js** | 3533–4790 | `setView()`, `toggleSidebar()`, `toggleLayer()`, theme functions, compact mode functions, `switchTab()`, `setFilter()`, `filterEntities()`, `selectEntity()`, `buildEntityDetail()`, `buildMetadataSummary()`, `openEntityModal()`, `showDetail()`, `closeDetail()`, `findEntityPhase()`, `openMitigationExplorer()`, `openEntityExplorer()`, all drag handlers, `renderKillChain()`, `renderEntityTag()`, `renderRelationshipView()`, `renderStats()`, `togglePhase()`, `removeAssignment()`, `expandAll()`, `collapseAll()`, `clearAssignments()` |
| **af-io.js** | 4790–5200 | `exportJSON()`, `exportCSV()`, `triggerImportKillChain()`, `ensureAssignmentShape()`, `ensureLibraryFallbacks()`, `KILLCHAIN_IMPORT_LIMITS`, `validateKillChainImport()`, `sanitizeImportedString()`, `sanitizeImportedAssignment()`, `sanitizeImportedData()`, `importKillChain()`, `IMPORT_LIMITS`, `importNavigator()` |
| **af-app.js** | 5392–5775 | `toggleDropdown()`, `closeDropdowns()`, `currentMetadataEdit`, `openMetadataEditor()`, `closeMetadataEditor()`, `selectScore()`, `updateConfidenceLabel()`, `addCveRow()`, `addHyperlinkRow()`, `addObservableRow()`, `saveMetadata()`, `showUsageGuide()`, `closeUsageGuide()`, `showChangelog()`, `closeChangelog()`, `showToast()`, `renderAll()`, `enableLeaveSiteConfirmation()`, initialization block |

---

## Function Index (Alphabetical)

| Function | Section | Line (approx.) |
|----------|---------|-----------------|
| `addCveRow` | Metadata Editor | 5465 |
| `addHyperlinkRow` | Metadata Editor | 5500 |
| `addObservableRow` | Metadata Editor | 5520 |
| `applyCompactLayout` | Compact Mode | 3740 |
| `applyConfigColors` | config.js | 198 |
| `applyInputGuards` | Input Security | 2818 |
| `applyTheme` | Theme Runtime | 3570 |
| `buildEntityDetail` | Selection & Detail | 3955 |
| `buildMetadataSummary` | Selection & Detail | 4100 |
| `clearAssignments` | Utilities | 4780 |
| `closeChangelog` | Modals | 5738 |
| `closeDetail` | Selection & Detail | 4185 |
| `closeDropdowns` | Dropdown Utils | 5400 |
| `closeEntityModal` | Selection & Detail | 4150 |
| `closeMetadataEditor` | Metadata Editor | 5435 |
| `closeUsageGuide` | Modals | 5715 |
| `collapseAll` | Utilities | 4776 |
| `commitRenameGroup` | Group Management | 3155 |
| `createAssignmentInstanceId` | Metadata Helpers | 3001 |
| `createDefaultMetadata` | Metadata Helpers | 2928 |
| `createGroup` | Group Management | 3110 |
| `detectDomain` | Navigator | 3518 |
| `enableLeaveSiteConfirmation` | Initialization | 5753 |
| `ensureAssignmentShape` | Import | 4820 |
| `ensureLibraryFallbacks` | Import | 4850 |
| `ensurePhaseLayout` | Assignment Logic | 3060 |
| `esc` | Helper Alias | 2795 |
| `escAttr` | Helper Alias | 2796 |
| `expandAll` | Utilities | 4772 |
| `exportCSV` | Export | 5202 |
| `exportJSON` | Export | 4790 |
| `extractAssignmentInstance` | Group Management | 3185 |
| `filterEntities` | Entity Rendering | 3800 |
| `findAssignment` | Assignment Logic | 3210 |
| `findEntityPhase` | Selection & Detail | 4190 |
| `formatPhaseName` | State | 3370 |
| `generateGroupId` | Group Management | 3100 |
| `getAllPhaseItemsByType` | Assignment Logic | 3050 |
| `getAssignmentId` | Assignment Logic | 3010 |
| `getAssignmentInstanceId` | Assignment Logic | 3030 |
| `getAssignmentMetadata` | Assignment Logic | 3020 |
| `getConfidenceClass` | Metadata Helpers | 2992 |
| `getConfidenceLabel` | Metadata Helpers | 2984 |
| `getCveEntries` | Metadata Helpers | 2946 |
| `getCveList` | Metadata Helpers | 2960 |
| `getPhaseGroupedItems` | Assignment Logic | 3045 |
| `getPhaseUngroupedItems` | Assignment Logic | 3040 |
| `getPreferredThemeMode` | Theme Runtime | 3548 |
| `getTechniqueName` | Navigator | 3525 |
| `handleAssignmentDragStart` | Drag & Drop | 4310 |
| `handleDragEnd` | Drag & Drop | 4225 |
| `handleDragLeave` | Drag & Drop | 4238 |
| `handleDragOver` | Drag & Drop | 4233 |
| `handleDragStart` | Drag & Drop | 4210 |
| `handleDrop` | Drag & Drop | 4242 |
| `handleGroupDragStart` | Drag & Drop | 4325 |
| `handleGroupDrop` | Drag & Drop | 4340 |
| `importKillChain` | Import | 5155 |
| `importNavigator` | Navigator | 3440 |
| `initAssignments` | State | 3375 |
| `initCompactMode` | Compact Mode | 3720 |
| `initThemeControls` | Theme Runtime | 3598 |
| `isEntityAssigned` | Entity Rendering | 3920 |
| `isTextInputElement` | Input Security | 2799 |
| `loadData` | Data Loading | 3380 |
| `loadNavigator` | Data Loading | 3397 |
| `loadVersion` | Version | 2630 |
| `migrateAssignment` | Metadata Helpers | 3003 |
| `moveGroupBetweenPhases` | Group Management | 3200 |
| `normalizeCveMetadata` | Metadata Helpers | 2964 |
| `normalizeThemeMode` | Theme Runtime | 3558 |
| `normalizeThemeScheme` | Theme Runtime | 3563 |
| `openEntityExplorer` | Selection & Detail | 3773 |
| `openEntityModal` | Selection & Detail | 4140 |
| `openMetadataEditor` | Metadata Editor | 5420 |
| `openMitigationExplorer` | Selection & Detail | 3760 |
| `removeAssignment` | Utilities | 4745 |
| `removeGroup` | Group Management | 3170 |
| `renderAll` | Initialization | 5750 |
| `renderEntityTag` | Kill Chain Rendering | 4558 |
| `renderKillChain` | Kill Chain Rendering | 4383 |
| `renderRelationshipView` | Relationship View | 4590 |
| `renderStats` | Stats | 4720 |
| `resolveTheme` | config.js | 187 |
| `sanitizeForCsv` | Export (inline) | 5370 |
| `sanitizeForStorage` | Input Security | 2808 |
| `sanitizeImportedAssignment` | Import | 4920 |
| `sanitizeImportedData` | Import | 5065 |
| `sanitizeImportedString` | Import | 4895 |
| `sanitizeUserInputText` | Input Security | 2801 |
| `saveMetadata` | Metadata Editor | 5555 |
| `selectEntity` | Selection & Detail | 3935 |
| `selectScore` | Metadata Editor | 5440 |
| `setCompactMode` | Compact Mode | 3690 |
| `setFilter` | Tab & Filter | 3795 |
| `setView` | View Controls | 3625 |
| `showChangelog` | Modals | 5725 |
| `showDetail` | Selection & Detail | 4160 |
| `showToast` | Toast | 5748 |
| `showUsageGuide` | Modals | 5710 |
| `startRenameGroup` | Group Management | 3145 |
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
| `updateHideEmptyControl` | Compact Mode | 3670 |
| `updateThemeControls` | Theme Runtime | 3588 |
| `validateKillChainImport` | Import | 4880 |
| `validateObservable` | Input Security | 2790 |

---

*Generated for AttackFlow v2.5.3. This document describes the monolithic implementation as it exists today. For the planned v3.0 modular architecture, see [DETACH.md](DETACH.md), [API_DOCS.md](API_DOCS.md), and [tests/TEST_PLAN.md](tests/TEST_PLAN.md).*
