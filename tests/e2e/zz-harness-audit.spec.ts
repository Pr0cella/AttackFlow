// Final gate: harness violations must never be absorbed by a known-gap marker.
//
// `test.fail(...)` tells Playwright that a test is expected to fail, and Playwright then
// accepts ANY failure of that test as the expected one -- including a failure the harness
// raised because the test itself misbehaved. Measured, not assumed: a probe that attempted
// an external navigation inside a `withFreshContext` body and then failed a deliberate
// `test.fail` assertion reported "1 passed" with exit code 0, whether the egress error was
// thrown from the body or from an afterAll hook in the same file.
//
// So the egress guard records violations to a file instead, and this spec -- which carries
// no marker of its own, so nothing can absorb its failure -- reads that file at the end of
// the run. The file name sorts last, which is when it must run.
import fs from 'node:fs';
import { expect, test } from '@playwright/test';
import { HARNESS_VIOLATION_LOG } from './helpers/roundtrip';

test('no test attempted a nonlocal request', () => {
  if (!fs.existsSync(HARNESS_VIOLATION_LOG)) return;

  const recorded = fs.readFileSync(HARNESS_VIOLATION_LOG, 'utf8').trim();
  // Consumed either way, so one run's violations cannot haunt the next.
  fs.rmSync(HARNESS_VIOLATION_LOG, { force: true });

  expect(recorded, 'nonlocal request attempts recorded during this run').toBe('');
});
