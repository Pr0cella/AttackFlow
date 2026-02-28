# AttackFlow — Monolithic API Reference

> **Version:** 2.9.0  
> **Scope:** Documents the current inline JavaScript implementation in `index.html` and companion `config.js` + `stix-config.js` (plus embedded iframe IPC surface used by `explorer.html` and `stix-builder.html`).  
> **Purpose:** Definitive implementation reference for ongoing hardening and v3 modularization planning.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [File Map](#2-file-map)
3. [What Changed Since v2.7.0](#3-what-changed-since-v270)
4. [config.js — Configuration & Theme Engine](#4-configjs--configuration--theme-engine)
5. [stix-config.js — STIX 2.1 Object Definitions](#5-stix-configjs--stix-21-object-definitions)
6. [Inline JS Sections (index.html)](#6-inline-js-sections-indexhtml)
   - 6.1 [VERSION + INPUT SECURITY](#61-version--input-security)
   - 6.2 [METADATA + TYPE MAPPING + ASSIGNMENT/GROUP LOGIC](#62-metadata--type-mapping--assignmentgroup-logic)
   - 6.3 [STATE + PHASE MODEL + CORE HELPERS](#63-state--phase-model--core-helpers)
   - 6.4 [DATA LOADING (SHARED CACHE + OFFLINE MODE)](#64-data-loading-shared-cache--offline-mode)
   - 6.5 [LOCAL IFRAME IPC BRIDGE](#65-local-iframe-ipc-bridge)
   - 6.6 [NAVIGATOR / TECHNIQUE IMPORTS](#66-navigator--technique-imports)
   - 6.7 [VIEWS + THEME + COMPACT + COMMENTS](#67-views--theme--compact--comments)
   - 6.8 [GLOBAL SEARCH + TAB/FILTER CONTROLS](#68-global-search--tabfilter-controls)
   - 6.9 [ENTITY LIST, STIX LIBRARY, STIX EDITOR](#69-entity-list-stix-library-stix-editor)
   - 6.10 [DETAIL VIEWS, DND, KILL CHAIN, RELATIONSHIPS](#610-detail-views-dnd-kill-chain-relationships)
   - 6.11 [PHASE DETAILS MODAL + STATS](#611-phase-details-modal--stats)
   - 6.12 [EXPORT / IMPORT (JSON, CSV, STIX)](#612-export--import-json-csv-stix)
   - 6.13 [METADATA EDITOR + MODALS + INIT](#613-metadata-editor--modals--init)
7. [Data Types & Shapes](#7-data-types--shapes)
8. [Security Model](#8-security-model)
9. [Global Event Listeners](#9-global-event-listeners)
10. [Module Mapping (Current → v3.0)](#10-module-mapping-current--v30)

---

## 1. Architecture Overview

AttackFlow is a zero-build browser SPA with all core runtime logic inside inline JavaScript in `index.html`.

- No bundler, no module system, global-scope runtime.
- Mutable app state lives in a single `state` object.
- Rendering is template-string + `innerHTML` driven, protected by strict sanitization and validator guards.
- Companion scripts:
  - `config.js` (theme/config/import behavior/debug toggles)
  - `stix-config.js` (STIX SDO schemas + vocabularies + helpers)
- Embedded views:
  - `explorer.html`
  - `stix-builder.html`
- Local `file://` mode supports a hardened MessageChannel-based iframe bridge and shared-data broadcast path.

---

## 2. File Map

| File | Role |
|------|------|
| `index.html` | Main UI, CSS, and inline runtime (monolith, ~10.5k lines total) |
| `config.js` | App config, theme presets, feature flags, IPC debug/rate/bootstrap tuning |
| `stix-config.js` | STIX common fields, vocabularies, 19 SDO type definitions, helper APIs |
| `explorer.html` | Relationship Explorer iframe view |
| `stix-builder.html` | STIX Composer iframe view (theme + local IPC aware) |
| `resources/*.json` | Generated runtime datasets (ATT&CK/CAPEC/CWE + mappings + Navigator layers) |

---

## 3. What Changed Since v2.7.0

Major additions reflected in v2.9.0 runtime:

1. **Local iframe IPC hardening**
   - Channel-only bootstrap (`AF_IPC_PORT_INIT`) with per-frame nonce binding.
   - Allowlisted message types and payload keys.
   - Request rate-limiting (token bucket) and bounded bootstrap retry/backoff.
2. **Shared dataset runtime cache**
   - `window.getAttackFlowSharedData()` snapshot API with deep-frozen payload.
   - Dataset shape + count + byte-size enforcement before cross-frame sharing.
3. **Offline `file://` data path**
   - Local folder/file selector flow for required `resources/*.json` files.
   - Graceful bypass path if user continues without data.
4. **Prototype pollution defenses expanded**
   - `DANGEROUS_OBJECT_KEYS`, safe reviver parsing (`parseJsonSafe`), null-prototype object creation.
5. **UI/runtime features**
   - Global search subsystem with ranking and sticky/expanded modes.
   - Kill-chain comment visibility controls (`showComments`, toggles).
   - Rich phase details modal with averages/CVE rollups/mitigation aggregation.
   - Optional STIX Builder navigation toggle (`CONFIG.navigation.showStixBuilder`).
6. **STIX export evolution**
   - Deterministic UUIDv5 IDs for ATT&CK techniques and mitigations in STIX bundle export.

---

## 4. config.js — Configuration & Theme Engine

### 4.1 `CONFIG` Highlights (v2.9.0)

- `version: '2.9.0'`
- `sources.attack.version: '18.1'`
- `imports.clearStixOnBundleImport`, `imports.clearStixOnKillChainImport`
- `navigation.confirmOnLeave`, `navigation.showStixBuilder`
- `visualizer.enabled`
- `ConfigIframeIPC.enableLocalIframeIPC`
- `debugging.traceLocalIframeIPCLogs`
- `debugging.localIframeIPCRateLimit.{enabled,refillPerSecond,burst}`
- `debugging.localIframeIPCBootstrap.{timeoutMs,maxRetries,retryBaseDelayMs,retryBackoffMultiplier,maxRetryDelayMs,graceMs}`

### 4.2 Theme APIs

- `resolveTheme(mode?, scheme?)`
  - Merges scheme overrides into configured defaults (`phases`, `frameworks`, `ui`, `metaIcons`).
- `applyConfigColors(theme?)`
  - Applies resolved colors to CSS custom properties on `document.documentElement`.

---

## 5. stix-config.js — STIX 2.1 Object Definitions

### 5.1 Core exports

- `STIX_COMMON_PROPERTIES`
- `STIX_VOCABULARIES`
- `STIX_OBJECTS` (19 SDO types)
- `STIX_RELATIONSHIP_DEFAULTS`

### 5.2 Helper functions

- `getStixFieldsForType(stixType)`
- `getStixTypeKeys()`
- `getStixTypeLabel(stixType)`
- `getStixVocabulary(vocabKey)`

### 5.3 Notes

- Field descriptor model is used dynamically by the inline STIX editor.
- Supported field kinds include primitive, list/open-vocab, timestamp/identifier, and complex JSON-backed structures (`kill-chain-phases`, `external-references`, `dictionary`).

---

## 6. Inline JS Sections (index.html)

### 6.1 VERSION + INPUT SECURITY

- `APP_VERSION` initialized fallback, updated by `loadVersion()` from `CHANGELOG.md`.
- `InputSecurity` object provides:
  - output encoding (`escapeHtml`, `sanitizeAttr`)
  - normalization/sanitize helpers
  - validators (CVE/CVSS/hash/IP/domain/url/filename)
  - `validateObservable(type, value)` dispatch
- Input guard stack (`applyInputGuards`) covers:
  - `keydown`, `beforeinput`, `paste`, `drop`, `input`
- Added sanitizer primitives:
  - `normalizeUserInput(text, maxLength, allowNewlines)`
  - `sanitizeUserInputText(text, allowNewlines)`
  - `sanitizeForStorage(text, maxLength)`
- Prototype pollution defenses:
  - `DANGEROUS_OBJECT_KEYS`
  - `isDangerousObjectKey`, `createSafeObject`, `hasOwn`, `parseJsonSafe`
  - recursive loader sanitizer `stripAngleBracketsFromJson`

### 6.2 METADATA + TYPE MAPPING + ASSIGNMENT/GROUP LOGIC

- Metadata normalization now handles `cveEntries`, legacy `cveId`/`cveIds`, and optional `cves` payloads.
- Confidence buckets changed to:
  - labels: `Unknown / Low / Medium / High`
  - classes: `unknown / low / medium / high`
- Assignment instance IDs now use `itm-...` format (`createAssignmentInstanceId`).
- Type constants:
  - `TYPE_KEYS`, `TAG_CLASSES`, `TYPE_LABELS`, `ALL_ENTITY_TYPES`
  - `STIX_ID_PATTERN`, `VALID_STIX_TYPES`
- STIX ID helpers:
  - `generateUUID`, `generateStixId`
  - deterministic UUIDv5 stack: `uuidv5`, `sha1Bytes`, `mitigationStixId`, `techniqueStixId`
- Group/assignment utilities:
  - `ensurePhaseLayout`, `extractAssignmentInstance`, `moveGroupBetweenPhases`, `findAssignment`, `updateAssignmentMetadata`

### 6.3 STATE + PHASE MODEL + CORE HELPERS

`state` now includes:

- `showComments`
- `relationshipExpanded: Set`
- global search flags: `globalSearch`, `globalSearchOpen`, `globalSearchExpanded`, `globalSearchSticky`

Kill chain model updates:

- IN super-phase uses `resource-development` (not weaponization).
- IN command phase key is `command-control`.
- `KILL_CHAIN` totals remain 18 phases.

Title/description helpers:

- `commitKillChainTitle`, `syncTitleToDOM`
- `commitKillChainDescription`, `syncDescriptionToDOM`
- `toggleDescriptionPanel`, `updateDescriptionHint`, `updateDescriptionCounter`

### 6.4 DATA LOADING (SHARED CACHE + OFFLINE MODE)

Core datasets are centralized via `SHARED_DATA_ENDPOINTS` and `loadSharedLibraryData(forceReload?)`.

Key APIs:

- `getSharedDataCache()`
- `fetchJsonResource(resourcePath)`
- `promptOfflineResourceFiles(requiredFileNames)`
- `enableOfflineResourceSelectionUI(message)`
- `hideLoadingOverlay()`
- `window.getAttackFlowSharedData(options)`

Behavior:

- HTTP context: standard `fetch` path.
- `file://` context: local file selection and cloned JSON store.
- shared dataset validated for schema + limits before reuse/broadcast.

### 6.5 LOCAL IFRAME IPC BRIDGE

IPC constants and constraints:

- inbound request types: `AF_REQUEST_THEME`, `AF_REQUEST_SHARED_DATA`
- bootstrap type: `AF_IPC_PORT_INIT`
- response types: `AF_THEME_SYNC`, `AF_SHARED_DATA`
- allowlisted payload keys and per-frame nonce checks

Main bridge functions:

- enable/trace/config:
  - `isLocalIframeIPCEnabled`, `isLocalIframeIPCTraceEnabled`
  - `getLocalIframeIPCRateLimitConfig`, `getLocalIframeIPCBootstrapConfig`
- channel management:
  - `createLocalIPCNonce`, `setupIPCChannelForFrame`, `clearIPCFrameChannel`
  - `scheduleIPCChannelBootstrapRetry`, `sendIPCMessageViaChannel`
- data safety:
  - `buildImmutableSharedDataPayload`, `validateSharedDatasetShape`
  - `enforceSharedDatasetLimits`, `estimateJsonByteSize`, `deepFreeze`
- broadcasting:
  - `broadcastThemeToEmbeddedViews`
  - `broadcastSharedDataToExplorer`
  - `initEmbeddedMessageBridge`

### 6.6 NAVIGATOR / TECHNIQUE IMPORTS

- `IMPORT_LIMITS` (25MB max, max techniques, strict ATT&CK ID regex)
- Manual list and CSV-like quick import path:
  - `parseTechniqueIdInput`, `applyTechniqueList`, `submitCsvImport`
  - modal helpers `openCsvImportModal`, `closeCsvImportModal`
- Navigator file import:
  - `importNavigator(event)` with schema/ID validation
  - base-library restoration helpers: `ensureBaseTechniquesLoaded`, `resetAttackTechniques`

### 6.7 VIEWS + THEME + COMPACT + COMMENTS

- View switching supports: `killchain`, `relationship`, `explorer`, `stix-builder`
- STIX Builder visibility is config-gated via `isStixBuilderEnabled` + `applyNavigationConfig`.
- Theme runtime:
  - `getPreferredThemeMode`, `normalizeThemeMode`, `normalizeThemeScheme`
  - `applyTheme`, `updateThemeControls`, `toggleThemeMode`, `initThemeControls`, `syncThemeFromStorage`
- Compact/runtime controls:
  - `setCompactMode`, `toggleCompactMode`, `toggleHideEmpty`, `applyCompactLayout`
- Comment controls:
  - `updateCommentsControls`, `toggleItemComment`, `toggleAllComments`

### 6.8 GLOBAL SEARCH + TAB/FILTER CONTROLS

Global search subsystem:

- `setGlobalSearch`, `openGlobalSearch`, `closeGlobalSearch`
- `toggleGlobalSearchExpanded`, `setGlobalSearchSticky`, `updateGlobalSearchUI`, `initGlobalSearch`
- ranking and results:
  - `rankGlobalEntity`, `buildGlobalSearchResults`, `renderGlobalSearchResults`
  - `openGlobalSearchResult`, `matchesGlobalSearch`

Tab/filter helpers:

- `switchTab(tab)`
- `setFilter(type, filter)`
- `parseCommaIdList(raw, pattern, prefix)`

### 6.9 ENTITY LIST, STIX LIBRARY, STIX EDITOR

Entity listing:

- `filterEntities(type)` now integrates local search + global search + ID-list parsing.
- `isEntityAssigned(type, id)` scans grouped and ungrouped phase allocations.

STIX bundle import/library:

- `STIX_BUNDLE_IMPORT_LIMITS`
- `importStixBundle(event)`
- `sanitizeStixBundleObject(obj, stixType, stixId)`
- `clearStixLibrary()`

STIX create/edit flows:

- `populateStixTypeDropdown`, `toggleCustomTypeName`
- `openCreateCustomModal`, `closeCreateCustomModal`, `createCustomItem`, `deleteCustomItem`
- editor modal:
  - `openStixEditor`, `closeStixEditor`, `saveStixEditor`
  - field builders: `buildStixReadonlyField`, `buildStixTextField`, `buildStixTextareaField`, `buildStixFieldFromSpec`

### 6.10 DETAIL VIEWS, DND, KILL CHAIN, RELATIONSHIPS

Detail and explorer integration:

- `renderDescriptionWithBadges` converts ATT&CK markdown links to explorer badges.
- `selectEntity`, `buildEntityDetail`, `buildStixPropertySummary`, `buildMetadataSummary`
- `openEntityModal`, `closeEntityModal`, `showDetail`, `closeDetail`
- `openMitigationExplorer`, `openEntityExplorer`

DND:

- `dragData` tracks source/type/instance/group context.
- `handleDragStart`, `handleDragEnd`, `handleDragOver`, `handleDragLeave`, `handleDrop`
- `handleAssignmentDragStart`, `handleGroupDragStart`, `handleGroupDrop`

Kill chain renderer:

- `renderKillChain` uses `phaseData.layout` for stable ordering.
- `renderEntityTag` includes score + metadata icon cluster + optional inline comments panel.

Relationship renderer:

- `renderRelationshipView` builds CAPEC↔CWE↔ATT&CK↔Phase↔Mitigation rows.
- `expandRelationshipMitigations(chainId)` supports incremental expansion.

### 6.11 PHASE DETAILS MODAL + STATS

Phase details pipeline:

- `buildPhaseDetails(phaseKey)`
- `getPhaseItemRelationships(type, id)`
- `getPhaseAverages(itemsByType)`
- `buildPhaseCveEntries(itemsByType)`
- `buildPhaseMitigations(itemsByType)`
- rendering helpers:
  - `renderPhaseMitigationSection`
  - `renderPhaseCveSection`
  - `renderPhaseDetailsSection`
- modal controls:
  - `openPhaseDetails(phaseKey)`
  - `closePhaseDetails(event)`

Stats and utility:

- `renderStats`
- `togglePhase`
- `removeAssignment`
- `expandAll`, `collapseAll`, `clearAssignments`

### 6.12 EXPORT / IMPORT (JSON, CSV, STIX)

Export:

- `exportJSON()` emits `killchain-export-lite` + embedded `stixBundle` when present.
- `buildSTIXBundle()` now includes:
  - custom SDOs
  - deterministic ATT&CK `attack-pattern` SDOs
  - deterministic mitigation `course-of-action` SDOs
  - generated `relationship` SROs (`mitigates` + co-location relations)
- `addRelationship(...)`
- `exportSTIXBundle()`
- `exportCSV()` with formula-injection hardening (`sanitizeForCsv` prefix guard)

Import:

- `KILLCHAIN_IMPORT_LIMITS`
- `validateKillChainImport(data)`
- `sanitizeImportedString`, `sanitizeAssignmentMetadata`
- `sanitizeImportedAssignment`, `sanitizeImportedCustomAssignment`
- `sanitizeImportedData(data)`
- `ensureAssignmentShape`, `ensureLibraryFallbacks`
- `importKillChain(event)`

### 6.13 METADATA EDITOR + MODALS + INIT

Metadata editor:

- `openMetadataEditor`, `closeMetadataEditor`
- `selectScore`, `updateConfidenceLabel`
- `addCveRow`, `addHyperlinkRow`, `addObservableRow`
- `saveMetadata()` validates CVE/CVSS/URL/observable formats before update

Modals + app shell:

- usage/changelog: `showUsageGuide`, `closeUsageGuide`, `showChangelog`, `closeChangelog`
- dropdown helpers: `toggleDropdown`, `closeDropdowns`
- `showToast`, `renderAll`, `enableLeaveSiteConfirmation`

Initialization order:

1. `initThemeControls()`
2. `logLocalIframeIPCSplash('index')`
3. `updateLoadingContextInfo()`
4. storage listener for theme sync
5. leave-site confirmation (config-gated)
6. `initEmbeddedMessageBridge()`
7. `applyNavigationConfig()`
8. `initAssignments()`
9. `initCompactMode()`
10. resize listener for compact layout
11. `applyInputGuards()`
12. `initGlobalSearch()`
13. `populateStixTypeDropdown()`
14. `loadVersion()`
15. `loadData()`

---

## 7. Data Types & Shapes

### 7.1 Assignment

```js
{
  id: 'T1566',
  metadata: Metadata,
  instanceId: 'itm-lk5u0h-12'
}
```

### 7.2 Metadata

```js
{
  score: 'unclassified',            // unclassified|low|medium|high|critical
  confidence: null,                 // null or 1..100
  comments: '',
  cveEntries: [{ id, score, vector }],
  cveId: '',
  cveIds: [],
  hyperlinks: [{ label, url }],
  observables: [{ type, value }]
}
```

### 7.3 PhaseData

```js
{
  techniques: Assignment[],
  capecs: Assignment[],
  cwes: Assignment[],
  customItems: Assignment[],
  groups: Group[],
  layout: LayoutEntry[]
}
```

### 7.4 Group / GroupItem / LayoutEntry

```js
{
  groupId: 'grp-lk5u0h-abc12',
  label: 'Initial Access',
  collapsed: false,
  items: GroupItem[]
}

// GroupItem = Assignment + type
{ id, metadata, instanceId, type: 'attack'|'capec'|'cwe'|'custom' }

// Layout entries
{ kind: 'item', type: 'attack', instanceId: 'itm-...' }
{ kind: 'group', groupId: 'grp-...' }
```

### 7.5 Shared Data Payload (IPC)

```js
{
  attack: { [techId]: Technique },
  capecPatterns: { [capecId]: Capec },
  cweWeaknesses: { [cweId]: Cwe },
  techniqueToCapec: { [techId]: string[] },
  capecToTechnique: { [capecId]: string[] },
  cweToCapec: { [cweId]: string[] }
}
```

### 7.6 Export Schema (`killchain-export-lite`)

```js
{
  version: '2.9.0',
  schema: 'killchain-export-lite',
  exportedAt: 'ISO-8601',
  title: '',
  description: '',
  view: 'killchain'|'relationship'|'explorer'|'stix-builder',
  activeTab: 'attack'|'capec'|'cwe'|'custom',
  filters: { attack, capec, cwe, custom },
  layers: { attack, capec, cwe, custom },
  hideEmpty: boolean,
  assignments: { [phaseKey]: PhaseData },
  selection: { type, id },
  customLibrary: { [stixId]: StixLibraryEntry },
  stixBundle?: StixBundle
}
```

---

## 8. Security Model

Defense-in-depth implementation in v2.9.0:

1. **Input blocking + normalization** on all text-entry paths.
2. **Output encoding** before template insertion (`esc`, `escAttr`, entity encoding).
3. **Safe JSON parsing** using reviver to strip `__proto__` / `constructor` / `prototype`.
4. **Null-prototype object construction** for untrusted accumulator objects.
5. **Import validation + limit enforcement** (file size/count/shape/ID formats).
6. **IPC allowlisting + nonce checks + channel-only messaging + throttling**.
7. **Shared payload immutability** via deep clone + deep freeze before iframe handoff.
8. **URL protocol allowlist** (`http`/`https`) for rendered external links.
9. **CSV formula injection prevention** by prefixing risky leading characters.

---

## 9. Global Event Listeners

Primary listeners include:

- `window.storage` (theme sync)
- `window.beforeunload` (optional leave confirmation)
- `window.message` (channel bootstrap guard)
- `window.resize` (compact layout)
- `document.click` (dropdown close + global search close)
- `document.keydown` (escape handling + input guard)
- `document.beforeinput` / `paste` / `drop` / `input` (input hardening)
- iframe `load` handlers for explorer and STIX builder channel setup

---

## 10. Module Mapping (Current → v3.0)

Suggested split of current monolith:

- **`af-security.js`**
  - InputSecurity validators/sanitizers, parse-safe JSON, import sanitizer helpers.
- **`af-core.js`**
  - State model, phase model, assignment/group helpers, metadata helpers.
- **`af-data.js`**
  - Shared-data loader/cache, offline file-mode loader, dataset limit enforcement.
- **`af-ipc.js`**
  - Local iframe bridge, channel bootstrap, nonce/rate-limit logic, broadcast helpers.
- **`af-ui.js`**
  - Rendering pipelines (killchain/relationships/details), DnD, global search, modals.
- **`af-io.js`**
  - JSON/CSV/STIX export+import, schema migration and sanitization.

---

*Generated for AttackFlow v2.9.0 from current workspace sources (`index.html`, `config.js`, `stix-config.js`, `docs/IPC_API-DOCS.md`).*
