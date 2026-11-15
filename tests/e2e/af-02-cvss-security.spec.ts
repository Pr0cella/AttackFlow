import fs from 'node:fs';
import { expect, test, type Page } from '@playwright/test';

const vector31 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const vector30 = 'CVSS:3.0/AV:P/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:N';
const vector40 = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
const fullVector40 = vector40 + '/E:A/CR:H/IR:M/AR:L/MAV:P/MAC:H/MAT:P/MPR:L/MUI:A/MVC:L/MVI:N/MVA:H/MSC:L/MSI:S/MSA:S/S:P/AU:Y/R:I/V:C/RE:H/U:Amber';
const validVectors = [
  vector31, vector30, vector40, fullVector40,
  vector31 + '/E:H',
  vector31.replace('/PR:N/UI:N', '/UI:N/PR:N'),
  'CVSS:3.1/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N/E:F/RL:X',
  'CVSS:3.0/S:U/AV:N/AC:L/PR:H/UI:N/C:L/I:L/A:N/E:F/RL:X',
  vector30 + '/E:F/RL:O/RC:R/CR:M/IR:H/AR:L/MAV:A/MAC:H/MPR:H/MUI:R/MS:C/MC:L/MI:N/MA:H',
  'CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/S:P/AU:Y/R:A/V:D/RE:L/U:Red',
  'CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/IR:X/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVC:X/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/S:N/AU:N/R:I/V:C/RE:H/U:Green',
];
const cveId = 'CVE-2024-12345';
const phaseKey = 'IN:reconnaissance';
const suffix = '" onmouseover="window.af02Executed=true';

const cases: { value: unknown; expected: string }[] = [
  ...validVectors.map(value => ({ value, expected: value })),
  { value: ` \t${vector31}\r\n`, expected: vector31 },
  ...['', ' \t\n', null, undefined, 0, 31, false, true, {}, [vector31],
    vector31 + suffix, vector31 + "'", vector31 + 'junk',
    vector31 + '\n' + suffix, vector31 + '&quot; onmouseover=alert(1)',
    vector31 + '/E:H/E:X', vector31 + '/A:H', vector31.slice(0, -4),
    vector31.replace('/AC:L', '/AC:X'), vector31.replace('3.1', '4.0'),
    vector31.replace('/I:H', '/I:H\n'), vector31.toLowerCase(),
    'CVSS:3.1/AV:N', 'CVSS:3.0/E:X',
    vector31.replace('/PR:N', '/PR:U'), vector31 + '/MPR:U',
    vector40 + suffix, vector40 + '/U:red', vector40 + '/E:A/E:X',
    vector40.replace('/AV:N/AC:L', '/AC:L/AV:N'),
    vector40 + '/U:Red/E:A', vector40 + '/SI:S',
    vector40 + '/MSC:S', vector40 + '/U:Green/UNKNOWN:X',
    vector40 + '/', vector40 + '\n' + suffix,
  ].map(value => ({ value, expected: '' })),
];

function payload(metadata: unknown) {
  return {
    schema: 'killchain-export-lite',
    assignments: {
      [phaseKey]: {
        techniques: [{ id: 'T1595', instanceId: 'itm-test-1', metadata }],
        capecs: [], cwes: [],
      },
    },
  };
}

async function importPayload(page: Page, data: unknown) {
  await page.locator('#toast').evaluate(el => { el.textContent = ''; });
  await page.locator('#import-killchain-input').setInputFiles({
    name: 'af-02.json', mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(data)),
  });
  await expect(page.locator('#toast')).toHaveText('Imported kill chain');
}

async function storedEntries(page: Page) {
  return page.evaluate(key => eval('state').assignments[key].techniques[0].metadata.cveEntries, phaseKey);
}

test.beforeEach(async ({ page }) => {
  await page.route('**/*', route => {
    const url = new URL(route.request().url());
    return url.hostname === '127.0.0.1' ? route.continue() : route.abort();
  });
  await page.goto('/index.html');
  await expect(page.locator('#loading')).toHaveClass(/hidden/, { timeout: 60_000 });
});

test('uses unchanged FIRST schema regexes for all three versions', async ({ page }) => {
  const sources = JSON.parse(fs.readFileSync('tests/import-validation/af-02-official-cvss-patterns.json', 'utf8'));
  const actual = await page.evaluate(() => eval('CVSS_VECTOR_PATTERNS').map((pattern: RegExp) => pattern.source));
  expect(actual).toEqual(Object.values(sources).map((source: any) => new RegExp(source.pattern).source));
});

test('normalizes official vectors and rejects invalid or non-string values', async ({ page }) => {
  for (const { value, expected } of cases) {
    const result = await page.evaluate(value => ({
      vector: (window as any).normalizeCvssVector(value),
      valid: eval('InputSecurity').validators.cvssVector(value).valid,
    }), value);
    expect(result).toEqual({ vector: expected, valid: expected !== '' });
  }
  const coerced = await page.evaluate(() => {
    let called = false;
    const value = { toString() { called = true; return 'unexpected'; } };
    return { vector: (window as any).normalizeCvssVector(value), called };
  });
  expect(coerced).toEqual({ vector: '', called: false });

  const scoreCoercion = await page.evaluate(cveId => {
    let called = false;
    const score = { toString() { called = true; return '9.8'; } };
    const entries = (window as any).sanitizeAssignmentMetadata({
      metadata: { cves: [{ id: cveId, score }] },
    }).cveEntries;
    return { entries, called };
  }, cveId);
  expect(scoreCoercion).toEqual({
    entries: [{ id: cveId, score: null, vector: '' }],
    called: false,
  });
});

test('requires every base metric and rejects repeated metrics', async ({ page }) => {
  const invalid = [];
  for (const vector of [vector30, vector31, vector40]) {
    const parts = vector.split('/');
    for (let index = 1; index < parts.length; index++) {
      invalid.push(parts.filter((_, i) => i !== index).join('/'));
      invalid.push(vector + '/' + parts[index]);
    }
  }
  const actual = await page.evaluate(vectors => vectors.map(vector => (window as any).normalizeCvssVector(vector)), invalid);
  expect(actual).toEqual(invalid.map(() => ''));
});

test('uses the same vector validation for current and legacy metadata paths', async ({ page }) => {
  for (const { value, expected } of cases) {
    const result = await page.evaluate(({ value, cveId }) => {
      const app = window as any;
      const formats = [
        { cveEntries: [{ id: cveId, vector: value }] },
        { cveEntries: [{ id: cveId, cvssVector: value }] },
        { cves: [{ id: cveId, vector: value }] },
        { cves: [{ id: cveId, cvssVector: value }] },
        { cveId, cvssVector: value },
        { cveIds: [cveId], cvss: value },
      ];
      return {
        imported: formats.flatMap(metadata => [metadata, { metadata }])
          .map(assignment => app.sanitizeAssignmentMetadata(assignment).cveEntries),
        displayed: formats.map(metadata => app.getCveEntries(metadata)),
      };
    }, { value, cveId });
    for (const entries of [...result.imported, ...result.displayed]) {
      expect(entries).toEqual([{ id: cveId, score: null, vector: expected }]);
    }
  }
});

test('drops the hostile fixture vector from actual imported CVE entries', async ({ page }) => {
  const fixture = JSON.parse(fs.readFileSync('tests/import-validation/bypass-cvss-trailing-attribute.json', 'utf8'));
  await importPayload(page, fixture);
  expect(await storedEntries(page)).toEqual([{ id: cveId, score: null, vector: '' }]);
  const icon = page.locator('.phase .meta-icon.has-cve');
  await expect(icon).toHaveAttribute('title', cveId);
  await expect(icon).not.toHaveAttribute('onclick');
});

test('imports valid current and legacy vectors without changing scores or optional empties', async ({ page }) => {
  for (const { metadata, expectedVector, expectedScore } of [
    { metadata: { cveEntries: [{ id: cveId, score: 9.8, vector: ` ${vector31} ` }] }, expectedVector: vector31, expectedScore: 9.8 },
    { metadata: { cveId, cvss: ` ${vector30} ` }, expectedVector: vector30, expectedScore: null },
    { metadata: { cveEntries: [{ id: cveId, vector: fullVector40 }] }, expectedVector: fullVector40, expectedScore: null },
    { metadata: { cveId, cvssVector: vector40 }, expectedVector: vector40, expectedScore: null },
    { metadata: { cveId }, expectedVector: '', expectedScore: null },
  ]) {
    await importPayload(page, payload(metadata));
    expect(await storedEntries(page)).toEqual([{ id: cveId, score: expectedScore, vector: expectedVector }]);
    const title = await page.locator('.phase .meta-icon.has-cve').getAttribute('title');
    expect(title).toContain(cveId);
    if (expectedVector) expect(title).toContain(expectedVector);
    else expect(title).toBe(cveId);
  }
});

test('encodes tooltip quotes and markup independently of vector validation', async ({ page }) => {
  const titleId = 'CVE-2024-12345" onmouseover="window.af02Executed=true\' <img src=x> & ` \\';
  const result = await page.evaluate(({ titleId, vector31, phaseKey }) => {
    const app = window as any;
    const holder = document.createElement('div');
    holder.innerHTML = app.renderEntityTag('attack', 'T1595', 'Test', {
      ...app.createDefaultMetadata(), cveEntries: [{ id: titleId, vector: vector31 }],
    }, phaseKey, 'itm-test-1');
    document.body.appendChild(holder);
    const icon = holder.querySelector('.meta-icon.has-cve') as HTMLElement;
    icon.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
    const result = {
      title: icon.title,
      handler: icon.getAttribute('onmouseover'),
      injectedImages: icon.querySelectorAll('img').length,
      executed: app.af02Executed === true,
    };
    holder.remove();
    return result;
  }, { titleId, vector31, phaseKey });
  expect(result).toEqual({ title: `${titleId.toUpperCase()} (${vector31})`, handler: null, injectedImages: 0, executed: false });
});

test('editor rejects trailing content, then saves full CVSS 4.0 and empty vectors', async ({ page }) => {
  await importPayload(page, payload({ cveEntries: [{ id: cveId, vector: vector31 }] }));
  await page.locator(`[data-phase="${phaseKey}"] .technique-tag`).hover();
  await page.locator(`[data-phase="${phaseKey}"] .tag-action-btn.edit`).click();
  const modal = page.locator('#metadata-editor-modal');
  await expect(modal).toHaveClass(/visible/);
  const input = page.locator('.cve-vector-input');
  // set the raw value to exercise save validation independently of live input guards.
  for (const trailing of [suffix, "'", ' '.repeat(210) + 'junk']) {
    await input.evaluate((el: HTMLInputElement, value) => { el.value = value; }, vector31 + trailing);
    await modal.locator('.metadata-btn-save').click();
    await expect(input).toHaveClass(/invalid/);
    await expect(modal).toHaveClass(/visible/);
    expect((await storedEntries(page))[0].vector).toBe(vector31);
  }
  await input.fill(` ${fullVector40} `);
  await modal.locator('.metadata-btn-save').click();
  await expect(modal).not.toHaveClass(/visible/);
  expect((await storedEntries(page))[0].vector).toBe(fullVector40);
  await page.locator(`[data-phase="${phaseKey}"] .technique-tag`).hover();
  await page.locator(`[data-phase="${phaseKey}"] .tag-action-btn.edit`).click();
  await expect(modal).toHaveClass(/visible/);
  await input.fill('');
  await expect(input).toHaveValue('');
  await modal.locator('.metadata-btn-save').click();
  await expect(page.locator('#toast')).toHaveText('Metadata saved');
  await expect(modal).not.toHaveClass(/visible/);
  expect((await storedEntries(page))[0].vector).toBe('');
});
