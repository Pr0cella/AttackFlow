import fs from 'node:fs';
import path from 'node:path';

import { expect, test, type Page } from '@playwright/test';

const BASE_URL = process.env.PLAYWRIGHT_BASE_URL || 'http://127.0.0.1:4173';

function fixturePath(name: string) {
  return path.join(process.cwd(), 'tests', 'import-validation', name);
}

async function openApp(page: Page) {
  await page.goto(new URL('/index.html', BASE_URL).toString());
  await expect(page.locator('#loading')).toHaveClass(/hidden/, { timeout: 60_000 });
}

async function importKillChainFile(page: Page, file: string | { name: string; mimeType: string; buffer: Buffer }) {
  await page.locator('#import-killchain-input').setInputFiles(file as any);
  await expect(page.locator('#toast')).toHaveClass(/show/, { timeout: 10_000 });
  return (await page.locator('#toast').textContent())?.trim() || '';
}

async function importKillChainPayload(page: Page, name: string, payload: unknown) {
  return importKillChainFile(page, {
    name,
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify(payload), 'utf8'),
  });
}

async function exportFormulaCsv(page: Page) {
  await importKillChainPayload(page, 'csv-formula-guard.json', {
    schema: 'killchain-export-lite',
    assignments: {
      'IN:reconnaissance': {
        techniques: [{ id: 'T1595', metadata: { comments: '=1+1' } }],
        capecs: [],
        cwes: [],
      },
    },
  });

  const downloadPromise = page.waitForEvent('download');
  await page.evaluate(() => (window as any).exportCSV());
  const filePath = await (await downloadPromise).path();
  expect(filePath).toBeTruthy();
  return fs.readFileSync(filePath!, 'utf8');
}

test.describe('Import hardening', () => {
  test('accepts valid minimal import fixture', async ({ page }) => {
    await openApp(page);

    const toast = await importKillChainFile(page, fixturePath('valid-minimal.json'));
    expect(toast).toContain('Imported kill chain');
  });

  test('rejects malformed phase-key fixture', async ({ page }) => {
    await openApp(page);

    const toast = await importKillChainFile(page, fixturePath('reject-invalid-phase-key.json'));
    expect(toast).toContain('Import failed');
    expect(toast).toContain('Invalid phase key format');
  });

  test('preserves bypass payload comments as untrusted state', async ({ page }) => {
    await openApp(page);

    const rawFixture = fs.readFileSync(fixturePath('bypass-xss-in-comments.json'), 'utf8');
    const sanitizedComment = await page.evaluate((raw) => {
      const parsed = (window as any).parseJsonSafe(raw);
      const sanitized = (window as any).sanitizeImportedData(parsed);
      // The fixture uses a lowercase phase key; read whichever phase entry it produced.
      const phase = Object.values(sanitized.assignments)[0] as any;
      return phase?.techniques?.[0]?.metadata?.comments || '';
    }, rawFixture);

    expect(sanitizedComment).toBe("<script>alert('XSS')</script>Malicious comment");
  });

  test('renders imported hostile-looking comments as inert text', async ({ page }) => {
    await openApp(page);

    await page.evaluate(() => {
      (window as any).__importCommentExecuted = false;
    });
    const comment = '<img data-import-comment-injected src=x onerror="window.__importCommentExecuted=true">Kept';

    const payload = {
      version: '2.9.1',
      schema: 'killchain-export-lite',
      assignments: {
        'IN:reconnaissance': {
          techniques: [
            {
              id: 'T1595',
              comments: comment,
              score: 'high',
            },
          ],
          capecs: [],
          cwes: [],
        },
      },
    };

    const toast = await importKillChainFile(page, {
      name: 'xss-valid-phase.json',
      mimeType: 'application/json',
      buffer: Buffer.from(JSON.stringify(payload), 'utf8'),
    });

    expect(toast).toContain('Imported kill chain');

    const storedComment = await page.evaluate(() => {
      return eval('state').assignments['IN:reconnaissance'].techniques[0]?.metadata?.comments || '';
    });

    expect(storedComment).toBe(comment);
    await expect(page.locator('.tag-comment-content').first()).toHaveText(comment);
    await expect(page.locator('[data-import-comment-injected]')).toHaveCount(0);
    expect(await page.evaluate(() => (window as any).__importCommentExecuted)).toBe(false);
  });

  test('drops CVSS vectors with trailing attribute payloads', async ({ page }) => {
    await openApp(page);

    const rawFixture = fs.readFileSync(fixturePath('bypass-cvss-trailing-attribute.json'), 'utf8');
    const cvssVector = await page.evaluate((raw) => {
      const parsed = (window as any).parseJsonSafe(raw);
      const sanitized = (window as any).sanitizeImportedData(parsed);
      return sanitized.assignments?.['IN:reconnaissance']?.techniques?.[0]?.metadata?.cvssVector || '';
    }, rawFixture);

    expect(cvssVector).toBe('');
  });

  test('regenerates hostile group ids and remaps layout entries', async ({ page }) => {
    await openApp(page);

    const rawFixture = fs.readFileSync(fixturePath('bypass-group-id-xss.json'), 'utf8');
    const result = await page.evaluate((raw) => {
      const parsed = (window as any).parseJsonSafe(raw);
      const sanitized = (window as any).sanitizeImportedData(parsed);
      const phase = sanitized.assignments?.['IN:reconnaissance'];
      return {
        groupId: phase?.groups?.[0]?.groupId || '',
        groupLabel: phase?.groups?.[0]?.label || '',
        layoutGroupId: phase?.layout?.[0]?.groupId || '',
      };
    }, rawFixture);

    expect(result.groupId).toMatch(/^grp-[a-z0-9]+-[a-z0-9]{1,24}$/);
    expect(result.layoutGroupId).toBe(result.groupId);
    expect(result.groupId).not.toContain('onclick');
    expect(result.groupLabel).toBe('Group <script>alert(1)</script>');
  });

  test('keeps delegated group controls scoped to sanitized imported ids', async ({ page }) => {
    await openApp(page);

    const toast = await importKillChainFile(page, fixturePath('bypass-group-id-xss.json'));
    expect(toast).toContain('Imported kill chain');

    await expect(page.locator('.phase-group')).toHaveCount(1);
    const group = page.locator('.phase-group').first();
    const groupId = await group.getAttribute('data-group-id');
    expect(groupId).toMatch(/^grp-[a-z0-9]+-[a-z0-9]{1,24}$/);
    await expect(group.locator('.phase-group-title')).toHaveText('Group <script>alert(1)</script>');
    await expect(group.locator('script')).toHaveCount(0);

    await group.locator('.phase-group-header').click();
    await expect(group).toHaveClass(/collapsed/);
    await group.locator('.phase-group-header').click();
    await expect(group).not.toHaveClass(/collapsed/);

    const originalTitle = ((await group.locator('.phase-group-title').textContent()) || '').trim();
    const renameInput = group.locator('input.metadata-input');
    await group.locator('.rename').click();
    await renameInput.fill('Should Not Save');
    await renameInput.press('Escape');
    await expect(group.locator('.phase-group-title')).toHaveText(originalTitle);

    await group.locator('.rename').click();
    await renameInput.fill('Renamed Group');
    await renameInput.press('Enter');
    await expect(group.locator('.phase-group-title')).toHaveText('Renamed Group');

    page.once('dialog', (dialog) => dialog.accept());
    await group.locator('.delete').click();
    await expect(page.locator('.phase-group')).toHaveCount(0);
  });

  test('relationship view only renders assigned technique links for assigned CAPECs', async ({ page }) => {
    test.fail(true, 'Known gap AF-RC-006: relationship view includes unassigned library techniques');
    await openApp(page);

    const mapping = await page.evaluate(() => {
      const appState = eval('state') as any;
      for (const [capecId, capec] of Object.entries(appState.library.capecs)) {
        const techniques = Array.isArray((capec as any).techniques)
          ? (capec as any).techniques.filter((id: string) => appState.library.techniques[id])
          : [];
        if (techniques.length > 1) {
          return {
            capecId,
            assignedTechnique: techniques[0],
            unassignedTechnique: techniques[1],
          };
        }
      }
      return null;
    });

    expect(mapping).not.toBeNull();

    await importKillChainPayload(page, 'assigned-capec-one-technique.json', {
      version: '2.9.2',
      schema: 'killchain-export-lite',
      assignments: {
        'IN:reconnaissance': {
          techniques: [{ id: mapping!.assignedTechnique }],
          capecs: [{ id: mapping!.capecId }],
          cwes: [],
        },
      },
    });

    await page.click('#view-relationship');
    const row = page.locator('.relationship-row').filter({ hasText: mapping!.capecId }).first();
    await expect(row).toBeVisible();

    const renderedTechniqueIds = await row.locator('.relationship-cell.attack .id.attack').allTextContents();
    expect(renderedTechniqueIds).toContain(mapping!.assignedTechnique);
    expect(renderedTechniqueIds).not.toContain(mapping!.unassignedTechnique);
  });

  test('rejects poisoned shared resource records before cache handoff', async ({ page }) => {
    await openApp(page);

    const accepted = await page.evaluate(() => {
      return (window as any).validateSharedDatasetShape({
        attack: {
          T1595: {
            id: 'T0000',
            name: 'Poisoned technique',
          },
        },
        capecPatterns: {},
        cweWeaknesses: {},
        techniqueToCapec: {},
        capecToTechnique: {},
        cweToCapec: {},
      });
    });

    expect(accepted).toBe(false);
  });

  test('preserves indicator STIX fields through kill chain import and bundle export', async ({ page }) => {
    test.fail(true, 'Known gap AF-RC-003: bundle export omits type-specific indicator fields');
    await openApp(page);

    const indicatorId = 'indicator--11111111-1111-4111-8111-111111111111';
    const payload = {
      version: '2.9.2',
      schema: 'killchain-export-lite',
      assignments: {
        'IN:reconnaissance': {
          techniques: [],
          capecs: [],
          cwes: [],
          customItems: [
            {
              id: indicatorId,
              instanceId: 'itm-test-1',
              metadata: { score: 'medium' },
            },
          ],
        },
      },
      customLibrary: {
        [indicatorId]: {
          id: indicatorId,
          stixType: 'indicator',
          name: 'Suspicious IP',
          labels: ['malicious-activity'],
          pattern: "[ipv4-addr:value = '192.0.2.1']",
          pattern_type: 'stix',
          valid_from: '2026-01-01T00:00:00.000Z',
          description: 'Preserve STIX pattern punctuation.',
        },
      },
    };

    const toast = await importKillChainPayload(page, 'valid-indicator-custom-library.json', payload);

    expect(toast).toContain('Imported kill chain');

    const indicator = await page.evaluate((id) => {
      const bundle = (window as any).buildSTIXBundle();
      return bundle.objects.find((object: any) => object.id === id);
    }, indicatorId);

    expect(indicator).toMatchObject({
      type: 'indicator',
      pattern: "[ipv4-addr:value = '192.0.2.1']",
      pattern_type: 'stix',
      valid_from: '2026-01-01T00:00:00.000Z',
    });
  });

  test('preserves STIX pattern syntax through the assignment editor UI', async ({ page }) => {
    test.fail(true, 'Known gap AF-RC-003: editor input guards and bundle export alter STIX patterns');
    await openApp(page);

    const indicatorId = 'indicator--77777777-7777-4777-8777-777777777777';
    await importKillChainPayload(page, 'editable-indicator-custom-library.json', {
      version: '2.9.2',
      schema: 'killchain-export-lite',
      assignments: {
        'IN:reconnaissance': {
          techniques: [],
          capecs: [],
          cwes: [],
          customItems: [
            {
              id: indicatorId,
              instanceId: 'itm-test-2',
              metadata: { score: 'medium' },
            },
          ],
        },
      },
      customLibrary: {
        [indicatorId]: {
          id: indicatorId,
          stixType: 'indicator',
          name: 'Editable Indicator',
          labels: ['malicious-activity'],
          pattern: "[ipv4-addr:value = '192.0.2.7']",
          pattern_type: 'stix',
          valid_from: '2026-01-01T00:00:00.000Z',
        },
      },
    });

    await page.evaluate((id) => (window as any).openStixEditor(id, 'IN:reconnaissance', 'itm-test-2'), indicatorId);
    await expect(page.locator('#edit-stix-modal')).toHaveClass(/visible/);
    await page.locator('#stix-edit-pattern').fill("[domain-name:value = 'example.com']");
    await page.locator('.btn-stix-save').click();
    await expect(page.locator('#edit-stix-modal')).not.toHaveClass(/visible/);

    const pattern = await page.evaluate((id) => {
      const bundle = (window as any).buildSTIXBundle();
      const indicator = bundle.objects.find((object: any) => object.id === id);
      return indicator?.pattern || '';
    }, indicatorId);

    expect(pattern).toBe("[domain-name:value = 'example.com']");
  });

  test('exports formula-leading CSV cells behind a tab guard', async ({ page }) => {
    await openApp(page);

    const csv = await exportFormulaCsv(page);
    expect(csv).toContain('\t=1+1');
    expect(csv).not.toMatch(/(^|,)=1\+1/m);
  });

  test('serializes guarded CSV cells with single RFC 4180 quoting and CRLF rows', async ({ page }) => {
    test.fail(true, 'Known gap AF-RC-008: guarded cells are quoted twice and rows use LF');
    await openApp(page);

    const csv = await exportFormulaCsv(page);
    expect(csv).toContain(',"\t=1+1",');
    expect(csv).not.toContain('"""');
    expect(csv).toContain('\r\n');
  });
});
