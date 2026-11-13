// Shared helpers for the SDK tests.

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

/** A fresh private state directory. Keep `prefix` short: Unix socket paths are limited to ~104 bytes. */
export function makeStateDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/** Permission bits of `p`. */
export function mode(p) {
  return fs.statSync(p).mode & 0o777;
}

/** Poll until `predicate()` is true; resolves false after `timeoutMs`. */
export async function waitFor(predicate, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return false;
}

/** Remove a state directory, even one a test made unreadable. */
export function cleanup(stateDir) {
  try {
    fs.chmodSync(stateDir, 0o700);
  } catch {
    // already gone
  }
  fs.rmSync(stateDir, { recursive: true, force: true });
}
