// Independent CSV decoding oracle backed by Python's stdlib `csv` reader.
//
// WHY A SUBPROCESS. The previous local parser was hand-written in this repo, which made
// it a second implementation of the thing under test rather than an independent oracle,
// and it was measurably wrong: it silently accepted `"x"y` and an unterminated quote, and
// dropped a lone `""` field entirely. Python's reader in strict mode rejects the first two
// and keeps the third, and nobody here wrote it.
//
// WHAT IT IS NOT. This decodes CSV; it does not judge policy. Record endings, BOM and the
// formula guard are asserted separately against the raw bytes, because a reader that
// accepts both LF and CRLF cannot tell you which one was written.
//
// TRUST BOUNDARY. Exported bytes are untrusted input. The script text is fixed and passed
// with `-c`; data travels only on stdin; `shell` is never used, so no fixture value is
// ever interpolated into a command line. Output, time and input size are bounded.

import { spawnSync } from 'node:child_process';
import { expect } from '@playwright/test';

const MAX_INPUT_BYTES = 2 * 1024 * 1024;
const MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
const TIMEOUT_MS = 20_000;

// Fixed program text. Reads bytes from stdin, decodes UTF-8 strictly, and prints rows as
// JSON. strict=True makes malformed quoting an error instead of a silent guess.
const READER = [
  'import sys, csv, json, io',
  'data = sys.stdin.buffer.read().decode("utf-8")',
  'rows = list(csv.reader(io.StringIO(data, newline=""), strict=True))',
  'json.dump(rows, sys.stdout)',
].join('\n');

export type CsvReadResult =
  | { ok: true; rows: string[][] }
  | { ok: false; error: string };

/** Decodes CSV bytes with the Python reader. Returns a result rather than throwing. */
export function readCsv(buffer: Buffer): CsvReadResult {
  expect(buffer.length, 'CSV input exceeds the bounded probe size').toBeLessThanOrEqual(MAX_INPUT_BYTES);

  const run = spawnSync('python3', ['-c', READER], {
    input: buffer,
    timeout: TIMEOUT_MS,
    maxBuffer: MAX_OUTPUT_BYTES,
    shell: false,
  });

  // A failure to RUN the oracle is infrastructure breakage, never a product finding.
  if (run.error) throw new Error(`CSV oracle could not run: ${run.error.message}`);
  if (run.signal) throw new Error(`CSV oracle killed by signal ${run.signal}`);

  if (run.status !== 0) {
    return { ok: false, error: (run.stderr?.toString('utf8') || '').trim().split('\n').pop() || 'reader failed' };
  }

  let rows: unknown;
  try {
    rows = JSON.parse(run.stdout.toString('utf8'));
  } catch (cause) {
    throw new Error(`CSV oracle returned unparseable JSON: ${String(cause)}`);
  }
  // Validate the shape before any caller indexes into it.
  expect(Array.isArray(rows), 'CSV oracle must return an array of rows').toBe(true);
  for (const row of rows as unknown[]) {
    expect(Array.isArray(row), 'CSV oracle must return an array per row').toBe(true);
    for (const cell of row as unknown[]) expect(typeof cell).toBe('string');
  }
  return { ok: true, rows: rows as string[][] };
}

/** Decodes and fails the test if the bytes are not valid CSV. */
export function parseCsvStrict(buffer: Buffer): string[][] {
  const result = readCsv(buffer);
  if (!result.ok) {
    throw new Error(`exported bytes are not valid CSV: ${result.error}`);
  }
  return result.rows;
}
