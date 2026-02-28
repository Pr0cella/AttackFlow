# AttackFlow — Function Index (Maintainer-Oriented)

## Purpose

This index is designed for fast onboarding by maintainers:

- Comprehensive function inventory across primary runtime files.
- Organized by file + subsystem

---

## Scope

Indexed files:

- `index.html`
- `explorer.html`
- `stix-builder.html`
- `config.js`
- `stix-config.js`

Out of scope for this index:

- Generated data in `resources/`
- Legacy snapshots in `old/`
- Python extraction scripts

---

## Fast Navigation Playbook

When implementing changes, use this order:

1. Read subsystem summary in `DOCUMENTATION.md`.
2. Jump to the relevant file section in this index.
3. Use function families (security, import/export, render, IPC) to scope edits.
4. Validate side effects (`renderAll()`, `renderKillChain()`, cache/IPC broadcasts) before finalizing.

---

## Maintenance Model (Low Rewrite Overhead)

This index intentionally avoids fixed line ranges. It is curated and should be kept in sync with the generated inventory.

Generate the machine index:

```bash
python3 scripts/generate-function-index.py
```

Generated output:

- `docs/FUNCTION_INDEX.generated.md`

To refresh function discovery manually after major refactors:

```bash
grep -nE "^[[:space:]]*function[[:space:]]+[A-Za-z0-9_]+[[:space:]]*\(" index.html
grep -nE "^[[:space:]]*function[[:space:]]+[A-Za-z0-9_]+[[:space:]]*\(" explorer.html
grep -nE "^[[:space:]]*function[[:space:]]+[A-Za-z0-9_]+[[:space:]]*\(" stix-builder.html
grep -nE "^[[:space:]]*function[[:space:]]+[A-Za-z0-9_]+[[:space:]]*\(" config.js
grep -nE "^[[:space:]]*function[[:space:]]+[A-Za-z0-9_]+[[:space:]]*\(" stix-config.js
```

Update strategy:

- Regenerate `docs/FUNCTION_INDEX.generated.md` first.
- Add/remove only changed function names in the relevant subsection.
- Keep subsystem grouping stable; avoid churn from small reordering.

---

## `config.js` Function Index

- Theme resolution and application:
  - `resolveTheme`, `applyConfigColors`

## `stix-config.js` Function Index

- STIX definition helpers:
  - `getStixFieldsForType`, `getStixTypeKeys`, `getStixTypeLabel`, `getStixVocabulary`

---

## `index.html` Function Index

### Version / Security / Sanitization

- `isTextInputElement`
- `normalizeUserInput`
- `sanitizeUserInputText`
- `sanitizeForStorage`
- `truncateAtBoundary`
- `applyInputGuards`
- `isDangerousObjectKey`
- `createSafeObject`
- `hasOwn`
- `parseJsonSafe`
- `stripAngleBracketsFromJson`

### Metadata / Assignment / Type Utilities

- `createDefaultMetadata`
- `getCveEntries`
- `getCveList`
- `normalizeCveMetadata`
- `getConfidenceLabel`
- `getConfidenceClass`
- `createAssignmentInstanceId`
- `migrateAssignment`
- `getAssignmentId`
- `getAssignmentMetadata`
- `getAssignmentInstanceId`
- `generateUUID`
- `generateStixId`
- `uuidv5`
- `sha1Bytes`
- `mitigationStixId`
- `techniqueStixId`
- `getPhaseUngroupedItems`
- `getPhaseGroupedItems`
- `getAllPhaseItemsByType`
- `ensurePhaseLayout`

### Group Management / Assignment Mutations

- `generateGroupId`
- `createGroup`
- `toggleGroupCollapse`
- `startRenameGroup`
- `commitRenameGroup`
- `removeGroup`
- `extractAssignmentInstance`
- `moveGroupBetweenPhases`
- `findAssignment`
- `updateAssignmentMetadata`

### State / Kill Chain / Description Helpers

- `formatPhaseName`
- `initAssignments`
- `commitKillChainTitle`
- `syncTitleToDOM`
- `commitKillChainDescription`
- `syncDescriptionToDOM`
- `toggleDescriptionPanel`
- `updateDescriptionHint`
- `updateDescriptionCounter`

### Data Loading / Offline Resource Flow

- `isFileProtocolRuntime`
- `getFileNameFromPath`
- `cloneJsonData`
- `readLocalFileText`
- `enableOfflineResourceSelectionUI`
- `hideLoadingOverlay`
- `getSharedDataCache`

### Local Iframe IPC / Shared Data Controls

- `isLocalIframeIPCEnabled`
- `updateLoadingContextInfo`
- `isLocalIframeIPCTraceEnabled`
- `logLocalIframeIPCSplash`
- `logLocalIframeIPCTrace`
- `getLocalIframeIPCRateLimitConfig`
- `getLocalIframeIPCBootstrapConfig`
- `isIPCRequestRateAllowed`
- `isPlainObject`
- `hasOnlyAllowedKeys`
- `deepFreeze`
- `createLocalIPCNonce`
- `isKnownIPCSourceWindow`
- `getIPCFrameState`
- `clearIPCFrameBootstrapTimer`
- `clearIPCFrameChannel`
- `scheduleIPCChannelBootstrapRetry`
- `sendIPCMessageViaChannel`
- `setupIPCChannelForFrame`
- `buildImmutableSharedDataPayload`
- `validateSharedDatasetShape`
- `estimateJsonByteSize`
- `enforceSharedDatasetLimits`
- `getExplorerFrameEl`
- `getStixBuilderFrameEl`
- `broadcastSharedDataToExplorer`
- `broadcastThemeToEmbeddedViews`
- `initEmbeddedMessageBridge`

### Navigator / Technique Import

- `parseTechniqueIdInput`
- `openCsvImportModal`
- `closeCsvImportModal`
- `importNavigator`
- `detectDomain`
- `getTechniqueName`

### Theme / View / Layout / Sidebar Controls

- `getPreferredThemeMode`
- `normalizeThemeMode`
- `normalizeThemeScheme`
- `applyTheme`
- `updateThemeControls`
- `toggleThemeMode`
- `initThemeControls`
- `syncThemeFromStorage`
- `isStixBuilderEnabled`
- `setView`
- `applyNavigationConfig`
- `toggleSidebar`
- `toggleLayer`
- `updateHideEmptyControl`
- `updateCompactControls`
- `setCompactMode`
- `toggleCompactMode`
- `updateCommentsControls`
- `toggleItemComment`
- `toggleAllComments`
- `initCompactMode`
- `applyCompactLayout`
- `toggleHideEmpty`
- `openMitigationExplorer`
- `openEntityExplorer`

### Search / Tabs / Filters

- `switchTab`
- `setFilter`
- `setGlobalSearch`
- `openGlobalSearch`
- `closeGlobalSearch`
- `toggleGlobalSearchExpanded`
- `setGlobalSearchSticky`
- `updateGlobalSearchUI`
- `initGlobalSearch`
- `rankGlobalEntity`
- `buildGlobalSearchResults`
- `renderGlobalSearchResults`
- `openGlobalSearchResult`
- `matchesGlobalSearch`
- `parseCommaIdList`
- `filterEntities`
- `isEntityAssigned`

### STIX Library / STIX Editing

- `importStixBundle`
- `clearStixLibrary`
- `sanitizeStixBundleObject`
- `populateStixTypeDropdown`
- `toggleCustomTypeName`
- `openCreateCustomModal`
- `closeCreateCustomModal`
- `createCustomItem`
- `deleteCustomItem`
- `openStixEditor`
- `closeStixEditor`
- `saveStixEditor`
- `buildStixReadonlyField`
- `buildStixTextField`
- `buildStixTextareaField`
- `buildStixFieldFromSpec`
- `getEntityName`

### Detail Views / Modals / Entity Validation

- `renderDescriptionWithBadges`
- `selectEntity`
- `isSafeHttpUrl`
- `isValidEntityId`
- `buildEntityDetail`
- `buildStixPropertySummary`
- `buildMetadataSummary`
- `openEntityModal`
- `closeEntityModal`
- `showDetail`
- `closeDetail`
- `findEntityPhase`

### Drag and Drop

- `handleDragStart`
- `handleDragEnd`
- `handleDragOver`
- `handleDragLeave`
- `handleDrop`
- `handleAssignmentDragStart`
- `handleGroupDragStart`
- `handleGroupDrop`

### Rendering / Relationships / Phase Detail Analytics

- `renderKillChain`
- `renderEntityTag`
- `getRelationshipChainId`
- `renderRelationshipView`
- `expandRelationshipMitigations`
- `getAverageScoreLabel`
- `buildPhaseDetails`
- `getPhaseItemRelationships`
- `getPhaseAverages`
- `buildPhaseCveEntries`
- `buildPhaseMitigations`
- `renderPhaseMitigationSection`
- `renderPhaseCveSection`
- `renderPhaseDetailsSection`
- `openPhaseDetails`
- `closePhaseDetails`
- `renderStats`
- `togglePhase`
- `removeAssignment`
- `expandAll`
- `collapseAll`
- `clearAssignments`

### Import / Export / Serialization / Validation

- `exportJSON`
- `buildSTIXBundle`
- `addRelationship`
- `exportSTIXBundle`
- `triggerImportKillChain`
- `ensureAssignmentShape`
- `ensureLibraryFallbacks`
- `validateKillChainImport`
- `sanitizeImportedString`
- `sanitizeImportedAssignment`
- `sanitizeImportedCustomAssignment`
- `sanitizeAssignmentMetadata`
- `sanitizeImportedData`
- `importKillChain`
- `exportCSV`

### Dropdowns / Metadata Editor / Utility Modals / Init

- `toggleDropdown`
- `closeDropdowns`
- `openMetadataEditor`
- `closeMetadataEditor`
- `selectScore`
- `updateConfidenceLabel`
- `addCveRow`
- `addHyperlinkRow`
- `addObservableRow`
- `saveMetadata`
- `showUsageGuide`
- `closeUsageGuide`
- `closeChangelog`
- `showToast`
- `renderAll`
- `enableLeaveSiteConfirmation`

---

## `explorer.html` Function Index

### Theme / IPC / Bootstrapping

- `getPreferredThemeMode`
- `normalizeThemeMode`
- `normalizeThemeScheme`
- `applyTheme`
- `updateThemeControls`
- `toggleThemeMode`
- `initThemeControls`
- `syncThemeFromStorage`
- `isLocalIframeIPCEnabled`
- `isLocalIframeIPCTraceEnabled`
- `logLocalIframeIPCSplash`
- `logLocalIframeIPCTrace`
- `isPlainObject`
- `hasOnlyAllowedKeys`
- `deepFreeze`
- `hasActiveParentIPCChannel`
- `setParentIPCChannel`
- `clearParentIPCWaitTimer`
- `getLocalIframeIPCBootstrapConfig`
- `estimateBootstrapFailureWindowMs`
- `scheduleParentIPCBootstrapFailureWatch`
- `sendParentIPCRequest`
- `validateAndFreezeSharedDataPayload`
- `requestParentBridgeData`
- `initParentBridgeHandlers`

### Offline / Data / Rendering

- `isFileProtocolRuntime`
- `cloneJsonData`
- `parseJsonSafe`
- `readLocalFileText`
- `enableOfflineSelectionUI`
- `setStatus`
- `normalize`
- `escapeHtml`
- `escapeAttr`
- `isSafeHttpUrl`
- `renderDescriptionWithBadges`
- `unique`
- `buildSearchIndex`
- `getBadgeClass`
- `renderSuggestions`
- `buildIndices`
- `createTabs`
- `renderTabs`
- `renderList`
- `selectEntity`
- `getMitreTechniqueUrl`
- `getCapecUrl`
- `getCweUrl`
- `getMitigationUrl`
- `buildRelatedForAttack`
- `buildRelatedForCapec`
- `buildRelatedForCwe`
- `buildRelatedForMitigation`
- `renderGraphColumn`
- `renderGraph`
- `renderDetails`
- `initEvents`
- `getParentSharedDataLoader`
- `enableLeaveSiteConfirmation`

---

## `stix-builder.html` Function Index

### Theme / IPC / Security Basics

- `showToast`
- `getPreferredThemeMode`
- `normalizeThemeMode`
- `normalizeThemeScheme`
- `applyTheme`
- `updateThemeControls`
- `toggleThemeMode`
- `initThemeControls`
- `syncThemeFromStorage`
- `isLocalIframeIPCEnabled`
- `isLocalIframeIPCTraceEnabled`
- `logLocalIframeIPCSplash`
- `logLocalIframeIPCTrace`
- `isPlainObject`
- `hasOnlyAllowedKeys`
- `hasActiveParentIPCChannel`
- `setParentIPCChannel`
- `clearParentIPCWaitTimer`
- `getLocalIframeIPCBootstrapConfig`
- `estimateBootstrapFailureWindowMs`
- `scheduleParentIPCBootstrapFailureWatch`
- `requestParentTheme`
- `initParentThemeBridge`
- `generateUUID`
- `isDangerousObjectKey`
- `createSafeObject`
- `hasOwn`
- `parseJsonSafe`
- `stripAngleBracketsFromJson`
- `sanitizeUserInputText`
- `sanitizeImportedString`
- `applyInputGuards`
- `isTextInputElement`
- `isSafeHttpUrl`

### Object Model / Editor / Renderers

- `getObjectCategory`
- `getObjectDisplayName`
- `buildAddTypeOptions`
- `setActiveTab`
- `renderTabs`
- `renderObjectList`
- `selectObject`
- `getActiveObject`
- `createDefaultObject`
- `getDefaultForField`
- `addObject`
- `deleteActiveObject`
- `renderEditor`
- `setCenterMode`
- `renderCenterMode`
- `isRequiredField`
- `renderField`
- `renderFieldInput`
- `renderEnumField`
- `renderOpenVocabField`
- `renderListField`
- `renderObjectRefsField`
- `renderKillChainField`
- `renderExternalReferencesField`
- `renderReferenceHashesField`
- `renderGranularMarkingsField`
- `renderDictionaryField`
- `renderHashesField`
- `renderExtensionsField`
- `renderMarkingDefinitionField`

### Bundle / Validation / Import-Export

- `updateBundlePreview`
- `renderBundleSummary`
- `renderBundlePreview`
- `setVisualizerButtonState`
- `updateStatus`
- `openBundleIssues`
- `closeBundleIssues`
- `clearBundle`
- `sanitizeDictionary`
- `sanitizeExtensions`
- `sanitizeImportedFieldValue`
- `sanitizeImportedObject`
- `sanitizeBundleForVisualizer`
- `renderVisualizer`
- `validateBundle`
- `hasValue`
- `validateObjectFields`
- `sanitizeValue`
- `handleEditorInput`
- `collectDictionary`
- `collectExtensions`
- `handleEditorClick`
- `exportBundle`
- `importBundle`
- `copyActiveJson`
- `initEvents`
- `enableLeaveSiteConfirmation`

---

*Last refreshed for v2.9.0 code layout. This file is intentionally line-agnostic to reduce churn while preserving maintainability.*