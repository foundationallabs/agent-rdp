/**
 * On-disk layout of the daemon's state, mirroring the Rust daemon's `paths` module.
 *
 * Layout: `<stateDir>/<session>/{socket,pid}`. The state directory is the `stateDir` option,
 * else `AGENT_RDP_STATE_DIR`, else `/tmp/agent-rdp` (`%TEMP%\agent-rdp` on Windows).
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { RdpError } from './types.js';

/** Environment variable that overrides the state directory. */
export const STATE_DIR_ENV = 'AGENT_RDP_STATE_DIR';

/** Longest Unix socket path in bytes (`sun_path` is 104 bytes on macOS including the NUL). */
export const MAX_SOCKET_PATH_BYTES = 103;

/** Options shared by the path helpers. */
export interface PathOptions {
  /** State directory; must be absolute. Overrides `AGENT_RDP_STATE_DIR`. */
  stateDir?: string;
}

const SESSION_NAME_PATTERN = /^[A-Za-z0-9._-]+$/;

/**
 * Validate a session name: non-empty, only `[A-Za-z0-9._-]`, and not `.` or `..`.
 *
 * @throws RdpError `invalid_request` when the name is rejected.
 */
export function validateSessionName(name: string): void {
  if (typeof name !== 'string' || !SESSION_NAME_PATTERN.test(name) || name === '.' || name === '..') {
    throw new RdpError(
      'invalid_request',
      `Invalid session name ${JSON.stringify(name)}: must be non-empty, not '.' or '..', and contain only A-Z a-z 0-9 . _ -`
    );
  }
}

/**
 * Remove trailing separators of the host platform (`/` on POSIX; `\` and `/` on Windows),
 * keeping a bare root such as `/` or `C:\`.
 */
function stripTrailingSeparators(p: string): string {
  const root = path.parse(p).root;
  const separators = process.platform === 'win32' ? /[\\/]+$/ : /\/+$/;
  const stripped = p.replace(separators, '');
  // Never strip into (or past) the root; keep the root itself
  return stripped.length < root.length ? root : stripped;
}

/**
 * Resolve the state directory: the `stateDir` argument, then a non-empty
 * `AGENT_RDP_STATE_DIR`, then the platform default.
 *
 * @throws RdpError `invalid_request` when the argument or the environment value is not absolute.
 */
export function getStateDir(stateDir?: string): string {
  const explicit = stateDir || undefined;
  const fromEnv = process.env[STATE_DIR_ENV] || undefined;
  const chosen = explicit ?? fromEnv;
  if (chosen !== undefined) {
    if (!path.isAbsolute(chosen)) {
      const source = explicit !== undefined ? 'stateDir' : STATE_DIR_ENV;
      throw new RdpError('invalid_request', `${source} must be an absolute path, got ${JSON.stringify(chosen)}`);
    }
    return stripTrailingSeparators(chosen);
  }
  if (process.platform === 'win32') {
    const temp = process.env.TEMP || process.env.TMP || 'C:\\Windows\\Temp';
    return `${temp}\\agent-rdp`;
  }
  return '/tmp/agent-rdp';
}

/**
 * Directory holding a session's socket and pid file.
 *
 * @throws RdpError `invalid_request` for an invalid session name or state directory.
 */
export function getSessionDir(session: string, opts: PathOptions = {}): string {
  validateSessionName(session);
  const base = getStateDir(opts.stateDir);
  return path.join(base, session);
}

/**
 * Path of a session's daemon pid file.
 *
 * @throws RdpError `invalid_request` for an invalid session name or state directory.
 */
export function getPidPath(session: string, opts: PathOptions = {}): string {
  const dir = getSessionDir(session, opts);
  return path.join(dir, 'pid');
}

/**
 * Where to reach a session's daemon: a Unix socket path, or a TCP port on Windows.
 *
 * On Windows the SDK derives the port from a SHA-256 of the session name, which does not match
 * the daemon's `DefaultHasher`-based derivation, so the SDK does not support Windows.
 *
 * @throws RdpError `invalid_request` for an invalid session name or state directory, or a
 *   Unix socket path longer than {@link MAX_SOCKET_PATH_BYTES}.
 */
export function getSocketPath(session: string, opts: PathOptions = {}): string | number {
  validateSessionName(session);
  if (process.platform === 'win32') {
    const hash = crypto.createHash('sha256').update(session).digest();
    return 49152 + (hash.readUInt16LE(0) % 16383); // Range: 49152-65535
  }
  const socketPath = path.join(getSessionDir(session, opts), 'socket');
  if (Buffer.byteLength(socketPath) > MAX_SOCKET_PATH_BYTES) {
    throw new RdpError(
      'invalid_request',
      `Socket path ${socketPath} is ${Buffer.byteLength(socketPath)} bytes, over the ${MAX_SOCKET_PATH_BYTES}-byte limit; use a shorter stateDir or session name`
    );
  }
  return socketPath;
}

/**
 * Read a daemon's pid from its pid file, without checking that the process is alive.
 *
 * @returns the pid, or null if the file is missing/unreadable or does not hold a positive integer.
 */
export function readDaemonPid(session: string, opts: PathOptions = {}): number | null {
  const pidPath = getPidPath(session, opts);
  let content: string;
  try {
    content = fs.readFileSync(pidPath, 'utf8').trim();
  } catch {
    return null;
  }
  if (!/^\d+$/.test(content)) return null;
  const pid = Number.parseInt(content, 10);
  return Number.isSafeInteger(pid) && pid > 0 ? pid : null;
}

/** Mode bits for group and other. */
const GROUP_OTHER_BITS = 0o077;
const GROUP_OTHER_WRITE_BITS = 0o022;
const STICKY_BIT = 0o1000;

function unsafeDir(dir: string, reason: string): RdpError {
  return new RdpError('invalid_request', `Unsafe state directory ${JSON.stringify(dir)}: ${reason} (remove it, or make it owned by you and not writable by others)`);
}

function lstatDir(dir: string): fs.Stats {
  let stats: fs.Stats;
  try {
    stats = fs.lstatSync(dir);
  } catch (err) {
    const error = unsafeDir(dir, `cannot be inspected (${err instanceof Error ? err.message : String(err)})`);
    error.cause = err;
    throw error;
  }
  if (stats.isSymbolicLink()) throw unsafeDir(dir, 'is a symlink');
  if (!stats.isDirectory()) throw unsafeDir(dir, 'is not a directory');
  return stats;
}

/** Whether `err` came from a verify call on a directory that does not exist. */
export function isMissingDirError(err: unknown): boolean {
  return err instanceof RdpError && (err.cause as NodeJS.ErrnoException | undefined)?.code === 'ENOENT';
}

/** Owner checks need POSIX ownership; they are skipped on Windows. */
function ownerChecksApply(): boolean {
  return process.platform !== 'win32' && typeof process.getuid === 'function';
}

/** Require `stats` to be owned by the current user, or also by root when `allowRoot`. */
function checkOwner(dir: string, stats: fs.Stats, allowRoot: boolean): void {
  const uid = process.getuid!();
  if (stats.uid === uid || (allowRoot && stats.uid === 0)) return;
  const orRoot = allowRoot ? ' or root' : '';
  throw unsafeDir(dir, `is owned by uid ${stats.uid}, not the current user (uid ${uid})${orRoot}`);
}

/**
 * Check, without changing anything, that the state directory is safe to put session directories
 * in: a real directory owned by the current user or root, and sticky if group/other-writable.
 * Skipped on Windows.
 *
 * The SDK calls this when a session has no directory yet, so an unsafe state directory is
 * reported instead of showing up as a daemon that never starts (the daemon refuses it too, but
 * its output is discarded).
 *
 * @throws RdpError `invalid_request` when the directory is missing, a symlink, owned by someone
 *   else, or writable by others without the sticky bit.
 */
export function verifyStateDir(opts: PathOptions = {}): void {
  if (!ownerChecksApply()) return;
  const base = getStateDir(opts.stateDir);
  const baseStats = lstatDir(base);
  checkOwner(base, baseStats, true);
  if (baseStats.mode & GROUP_OTHER_WRITE_BITS && !(baseStats.mode & STICKY_BIT)) {
    throw unsafeDir(
      base,
      'is writable by other users and has no sticky bit; other users could replace session directories in it'
    );
  }
}

/**
 * Check, without changing anything, that a session's state directories are safe to connect to,
 * mirroring the Rust daemon's `verify_session_dirs`. Skipped on Windows.
 *
 * The state directory must be a real directory owned by the current user or root (sticky if
 * group/other-writable), and the session directory a real directory owned by the current user
 * with no group/other permissions. The SDK calls this before it trusts a running daemon's pid
 * file or socket, so credentials are never sent to a daemon another user controls.
 *
 * This does not protect against other processes running as the same user, nor against a state
 * directory whose parent directories are controlled by another user; choose a state directory
 * under a directory you or root own.
 *
 * @throws RdpError `invalid_request` when a directory is missing, a symlink, owned by someone
 *   else, or writable by others.
 */
export function verifySessionDirs(session: string, opts: PathOptions = {}): void {
  if (!ownerChecksApply()) return;
  verifyStateDir(opts);

  const dir = getSessionDir(session, opts);
  const stats = lstatDir(dir);
  checkOwner(dir, stats, false);
  if (stats.mode & GROUP_OTHER_BITS) {
    throw unsafeDir(dir, 'is accessible by other users (expected mode 0700)');
  }
}
