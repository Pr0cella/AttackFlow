// RT-16: restored data renders correctly in every current main view, opens in both
// editors, and reaches the embedded consumers without executing anything.
//
// Rendering coverage is deliberately separate from preservation coverage: a value can
// render safely and still be stored wrong, and vice versa. These tests assert that
// restored evidence appears as exact TEXT and never as markup.

import { expect, test } from '@playwright/test';
import { expectInertRender, importNative, openApp, readState } from './helpers/roundtrip';
import { EVIDENCE_STORED, FULL_PHASES, GROUPS, IDS, TITLE, nativeFull } from '../fixtures/roundtrip/native';

const bytes = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8');

test.describe('RT-16 restored view integration', () => {
  test('restored data renders as inert text in both views and in both editors', async ({ page }) => {
    test.setTimeout(120_000);
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await openApp(page);
    await importNative(page, bytes(nativeFull()), 'rt-16-views.json');

    await test.step('the kill chain view renders every restored card', async () => {
      await expect(page.locator('#view-killchain')).toHaveClass(/active/);
      const recon = page.locator(`[data-phase="${FULL_PHASES.recon}"]`);
      await expect(recon).toBeVisible();

      // Ungrouped cards plus the group and its members are all present.
      await expect(recon.locator(`.phase-group[data-group-id="${GROUPS.mixed}"]`)).toHaveCount(1);
      await expect(recon.locator(`.phase-group[data-group-id="${GROUPS.empty}"]`)).toHaveCount(1);
      // The restored layer state drives rendering: the fixture turns the CAPEC layer off,
      // so its assignment is hidden while the others render. The data is still in state.
      for (const instanceId of ['itm-rt-001', 'itm-rt-003', 'itm-rt-004', 'itm-rt-005']) {
        await expect(recon.locator(`.tag-action-btn.edit[onclick*="'${instanceId}'"]`)).toHaveCount(1);
      }
      await expect(recon.locator(`.tag-action-btn.edit[onclick*="'itm-rt-002'"]`)).toHaveCount(0);
      expect((await readState(page)).assignments[FULL_PHASES.recon].capecs[0].instanceId).toBe('itm-rt-002');

      // The restored title reaches the DOM as a value, not as parsed markup.
      await expect(page.locator('#kill-chain-title')).toHaveValue(TITLE);
    });

    await test.step('the relationship view renders without error', async () => {
      await page.locator('#view-relationship').click();
      await expect(page.locator('#relationship-container')).toHaveClass(/visible/);
      expect((await readState(page)).view).toBe('relationship');
      await expect(page.locator('#relationship-container')).toBeVisible();

      await page.locator('#view-killchain').click();
      await expect(page.locator('#relationship-container')).not.toHaveClass(/visible/);
    });

    await test.step('the metadata editor shows restored evidence verbatim', async () => {
      const card = page.locator(`[draggable="true"]:has(.tag-action-btn.edit[onclick*="'itm-rt-001'"])`);
      await card.hover();
      await card.locator('.tag-action-btn.edit').click();

      // Exact stored evidence, including quotes, brackets and the payload-shaped line.
      await expect(page.locator('#meta-comments')).toHaveValue(EVIDENCE_STORED);
      await expect(page.locator('#meta-confidence')).toHaveValue('100');
      await expect(page.locator('#score-selector .selected')).toHaveAttribute('data-value', 'critical');
      await expect(page.locator('#cve-list input').nth(0)).toHaveValue('CVE-2026-10001');
      await expect(page.locator('#observable-list .observable-item')).toHaveCount(11);
      await page.locator('.metadata-editor-close').click();
    });

    await test.step('the STIX editor shows restored library fields verbatim', async () => {
      await page.evaluate(id => (window as any).openStixEditor(id), IDS.indicator);
      await expect(page.locator('#edit-stix-modal')).toHaveClass(/visible/);
      await expect(page.locator('#stix-edit-name')).toHaveValue('RT Indicator');
      await expect(page.locator('#stix-edit-pattern'))
        .toHaveValue("[file:name = 'a\\\\b.exe' AND file:size > 10] OR [domain-name:value = 'a--b.test']");
      await page.evaluate(() => (window as any).closeStixEditor());
    });

    await test.step('nothing rendered anywhere became markup or executed', async () => {
      // The payload-shaped evidence appears as text somewhere, and as no element anywhere.
      await expect(page.locator('img[data-rt-injected]')).toHaveCount(0);
      await expect(page.locator('[onerror]')).toHaveCount(0);
      await expectInertRender(page, errors);
    });
  });

  test('every layer toggle re-renders the restored document safely', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await openApp(page);
    await importNative(page, bytes(nativeFull()), 'rt-16-layers.json');

    // The fixture restores capec off and the rest on. The checkboxes are visually styled
    // through a label, so force the real input and let its onchange handler run.
    for (const layer of ['attack', 'capec', 'cwe', 'custom']) {
      const control = page.locator(`#layer-${layer}`);
      const before = await control.isChecked();
      expect(before, `${layer} checkbox mirrors restored state`)
        .toBe(await page.evaluate(k => !!eval('state').layers[k], layer));

      // The real input is visually replaced by a styled span, so the user gesture is a
      // click on its label. That flips the checkbox and fires toggleLayer().
      const toggle = page.locator(`label.layer-toggle.${layer}`);
      await toggle.click();
      expect(await page.evaluate(k => eval('state').layers[k], layer)).toBe(!before);
      await expect(control).toBeChecked({ checked: !before });

      await toggle.click();
      expect(await page.evaluate(k => eval('state').layers[k], layer)).toBe(before);
      await expect(control).toBeChecked({ checked: before });
    }
    await expectInertRender(page, errors);
  });

  test('the embedded Explorer and Composer load with restored data present', async ({ page }) => {
    test.setTimeout(120_000);
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await openApp(page);
    await importNative(page, bytes(nativeFull()), 'rt-16-frames.json');

    // Both consumers are same-origin sandboxed iframes declared in index.html.
    const explorer = page.frameLocator('iframe.explorer-frame');
    const composer = page.frameLocator('iframe.stix-builder-frame');

    await expect(explorer.locator('body')).toBeAttached({ timeout: 60_000 });
    await expect(composer.locator('#add-object')).toBeAttached({ timeout: 60_000 });

    // Smoke level only: the frames come up and nothing in them executes the canary.
    // Composer-to-editor push does not exist, so no data handoff is asserted here.
    await expect(composer.locator('[data-rt-injected]')).toHaveCount(0);
    await expect(explorer.locator('[data-rt-injected]')).toHaveCount(0);
    await expectInertRender(page, errors);

    // The main document is unaffected by the frames having loaded.
    const state = await readState(page);
    expect(state.title).toBe(TITLE);
    expect(state.customLibrary[IDS.indicator]).toBeDefined();
  });
});
