# Kill Chain Import Validation Test Suite

Test files for validating the security and resilience of kill chain JSON import functionality.

## Test Categories

### `valid-*` - Should Pass

Files that represent legitimate exports and should import successfully:

| File | Description |
|------|-------------|
| `valid-minimal.json` | Minimal valid structure with empty assignments |
| `valid-full-metadata.json` | Full metadata: score, confidence, CVE, CVSS, hyperlinks, observables |
| `valid-subtechniques.json` | Sub-technique IDs (T1566.001, T1059.003) |

### `bypass-*` - Potential Security Gaps

Files that contain malicious payloads which SHOULD be sanitized/blocked. Use these to verify:
- XSS payloads are stripped or encoded
- Dangerous URLs are rejected
- unsafe group/layout identifiers are regenerated or dropped
- CVSS vectors must match the full CVSS 3.0/3.1 base-vector grammar

| File | Payload | Expected Behavior |
|------|---------|-------------------|
| `bypass-xss-in-comments.json` | `<script>alert('XSS')</script>` in comments | Script tags stripped |
| `bypass-xss-in-observable.json` | Event handler in observable value | Quotes stripped, encoded |
| `bypass-javascript-url.json` | `javascript:alert()` URL | URL rejected (not http/https) |
| `bypass-data-url.json` | `data:text/html;base64,...` URL | URL rejected (not http/https) |
| `bypass-prototype-pollution.json` | `__proto__` key in assignments | Key ignored or rejected |
| `bypass-group-id-xss.json` | Attribute payload in `groupId` and layout reference | Group ID regenerated and layout remapped |
| `bypass-cvss-trailing-attribute.json` | Valid CVSS prefix followed by event-handler text | CVSS vector dropped |
| `bypass-sql-injection-markers.json` | `'; DROP TABLE; --` in comments | `--` and `;` stripped |
| `bypass-unicode-escapes.json` | `\u003c` Unicode escapes | Should remain harmless |
| `bypass-html-entities.json` | `&lt;img onerror=...&gt;` | Entities double-encoded or safe |

### `reject-*` - Must Be Rejected

Files with structural or format errors that must fail validation:

| File | Issue | Expected Error |
|------|-------|----------------|
| `reject-invalid-technique-id.json` | ID: "INVALID-ID" | Assignment silently dropped |
| `reject-missing-assignments.json` | No `assignments` object | "Missing or invalid assignments" |
| `reject-invalid-phase-key.json` | Phase key without `:` | "Invalid phase key format" |
| `reject-techniques-not-array.json` | `techniques: "string"` | "must be an array" |
| `reject-invalid-score.json` | Score: "super-critical" | Score not applied (default used) |
| `reject-invalid-cve.json` | CVE: "CVE-INVALID" | CVE not applied |
| `reject-invalid-cvss.json` | CVSS 2.0 vector | CVSS not applied |
| `reject-invalid-observable-type.json` | Unknown observable type | Observable dropped |
| `reject-not-object.json` | Plain string as root | JSON parse error or validation fail |
| `reject-null.json` | `null` as root | "Invalid export format" |
| `reject-array-root.json` | Array as root | "Invalid export format" |
| `reject-invalid-json.json` | Malformed JSON | JSON parse error |
| `reject-confidence-overflow.json` | Confidence: 999 | Clamped to 100 |
| `reject-invalid-view.json` | view: "malicious-view" | view not applied |
| `reject-xss-in-activeTab.json` | XSS in activeTab | activeTab not applied |

## Running Tests

1. Open AttackFlow in browser
2. Use browser DevTools Console to test validation functions directly:

```javascript
// Load and validate a test file
fetch('tests/import-validation/valid-minimal.json')
  .then(r => r.json())
  .then(data => {
    console.log('Validation:', validateKillChainImport(data));
    console.log('Sanitized:', sanitizeImportedData(data));
  });
```

3. Or use the Import button and observe toast messages

## Expected Validation Flow

1. **File size check** - Max 5 MB
2. **JSON parse** - Must be valid JSON
3. **Structure validation** - `validateKillChainImport()`:
   - Root must be object
   - Must have `assignments` object
   - Phase keys must normalize to the kill-chain phase allowlist
   - Arrays for techniques/capecs/cwes/custom items, groups, and layout
   - Count and nesting limits per import
4. **Deep sanitization** - `sanitizeImportedData()`:
   - ID pattern validation (T####, CAPEC-###, CWE-###, STIX IDs)
   - Assignment and group instance ID normalization
   - Score enum validation
   - Confidence clamping (0-100)
   - CVE/CVSS format validation
   - URL scheme validation (https?:// only)
   - Observable type validation
   - String sanitization (control chars, script tags, blocked chars)

## Adding New Tests

1. Create a new `.json` file with appropriate prefix:
   - `valid-` for legitimate files
   - `bypass-` for security edge cases
   - `reject-` for invalid structures
2. Add `_comment` field explaining the test case
3. Update this README with expected behavior
