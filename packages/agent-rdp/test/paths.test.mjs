// Tests for the state-directory and session-name helpers.
// Requires a prior `pnpm --filter ./packages/agent-rdp run build:ts` (imports from dist/).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  RdpError,
  RdpSession,
  getPidPath,
  getSessionDir,
  getSocketPath,
  getStateDir,
  readDaemonPid,
  validateSessionName,
  verifySessionDirs,
  verifyStateDir,
} from '../dist/index.js';
import { getSocketPath as clientGetSocketPath } from '../dist/client.js';
import { cleanup, makeStateDir } from './helpers.mjs';

/** Run `fn` with AGENT_RDP_STATE_DIR set (or unset when `value` is undefined). */
function withEnv(value, fn) {
  const previous = process.env.AGENT_RDP_STATE_DIR;
  if (value === undefined) delete process.env.AGENT_RDP_STATE_DIR;
  else process.env.AGENT_RDP_STATE_DIR = value;
  try {
    return fn();
  } finally {
    if (previous === undefined) delete process.env.AGENT_RDP_STATE_DIR;
    else process.env.AGENT_RDP_STATE_DIR = previous;
  }
}

test('getStateDir: option beats env beats default', () => {
  assert.equal(withEnv('/env/dir', () => getStateDir('/opt/dir')), '/opt/dir');
  assert.equal(withEnv('/env/dir', () => getStateDir()), '/env/dir');
  assert.equal(withEnv('', () => getStateDir()), '/tmp/agent-rdp');
  assert.equal(withEnv(undefined, () => getStateDir()), '/tmp/agent-rdp');
});

test('getStateDir rejects relative option and env values', () => {
  assert.throws(() => getStateDir('rel/dir'), RdpError);
  assert.throws(() => withEnv('rel/dir', () => getStateDir()), /AGENT_RDP_STATE_DIR/);
});

test('session dir, pid and socket paths compose with stateDir', () => {
  const opts = { stateDir: '/s/state' };
  assert.equal(getSessionDir('a', opts), '/s/state/a');
  assert.equal(getPidPath('a', opts), '/s/state/a/pid');
  assert.equal(getSocketPath('a', opts), '/s/state/a/socket');
  assert.equal(withEnv(undefined, () => getSocketPath('a')), '/tmp/agent-rdp/a/socket');
  assert.equal(clientGetSocketPath, getSocketPath);
});

test('invalid session names throw invalid_request everywhere', () => {
  for (const bad of ['', '.', '..', 'a/b', '../x', 'a b', 'a\\b']) {
    assert.throws(() => validateSessionName(bad), { code: 'invalid_request' });
    assert.throws(() => getSessionDir(bad), RdpError);
    assert.throws(() => getPidPath(bad), RdpError);
    assert.throws(() => getSocketPath(bad), RdpError);
    assert.throws(() => new RdpSession({ session: bad }), RdpError);
  }
  validateSessionName('default');
  validateSessionName('rdp-1.a_b');
});

test('a socket path over the sun_path limit throws', () => {
  const stateDir = `/tmp/${'x'.repeat(100)}`;
  assert.throws(() => getSocketPath('a', { stateDir }), /byte limit/);
});

test('readDaemonPid parses the pid file and ignores bad content', () => {
  const stateDir = makeStateDir('rdp-pid-');
  try {
    const opts = { stateDir };
    assert.equal(readDaemonPid('s', opts), null);
    fs.mkdirSync(getSessionDir('s', opts));
    const write = (content) => fs.writeFileSync(getPidPath('s', opts), content);
    write('123\n');
    assert.equal(readDaemonPid('s', opts), 123);
    for (const bad of ['12a', '-1', '0', '', '  \n', '99999999999999999999']) {
      write(bad);
      assert.equal(readDaemonPid('s', opts), null, JSON.stringify(bad));
    }
  } finally {
    fs.rmSync(stateDir, { recursive: true, force: true });
  }
});

test('getStateDir strips trailing separators but keeps a bare root', () => {
  assert.equal(getStateDir('/opt/dir/'), '/opt/dir');
  assert.equal(getStateDir('/opt/dir///'), '/opt/dir');
  assert.equal(getStateDir('/'), '/');
  assert.equal(withEnv('/env/dir/', () => getStateDir()), '/env/dir');
});

test('getStateDir uses the host platform rules: only host-absolute paths, only host separators', () => {
  if (process.platform === 'win32') {
    assert.equal(getStateDir('C:\\x\\'), 'C:\\x');
    assert.equal(getStateDir('C:\\'), 'C:\\');
    assert.throws(() => getStateDir('/x'), RdpError);
  } else {
    assert.throws(() => getStateDir('C:\\x'), { code: 'invalid_request' });
    assert.throws(() => withEnv('C:\\x', () => getStateDir()), /AGENT_RDP_STATE_DIR/);
    // A trailing backslash is part of a POSIX directory name
    assert.equal(getStateDir('/tmp/a\\'), '/tmp/a\\');
    assert.equal(getStateDir('/tmp/a\\/'), '/tmp/a\\');
  }
});

const posixOnly = { skip: process.platform === 'win32' && 'POSIX permissions' };

/** Make `<stateDir>/s` with the given modes; returns the state dir. */
function makeDirs({ baseMode, sessionMode }) {
  const stateDir = makeStateDir('rdp-v-');
  fs.chmodSync(stateDir, baseMode);
  const dir = getSessionDir('s', { stateDir });
  fs.mkdirSync(dir);
  fs.chmodSync(dir, sessionMode);
  return stateDir;
}

test('verifySessionDirs accepts a private session dir in an owned base', posixOnly, () => {
  const stateDir = makeDirs({ baseMode: 0o700, sessionMode: 0o700 });
  try {
    verifySessionDirs('s', { stateDir });
  } finally {
    cleanup(stateDir);
  }
});

test('verifySessionDirs accepts a sticky world-writable base', posixOnly, () => {
  const stateDir = makeDirs({ baseMode: 0o1777, sessionMode: 0o700 });
  try {
    verifySessionDirs('s', { stateDir });
  } finally {
    cleanup(stateDir);
  }
});

test('verifySessionDirs refuses a group-writable session dir', posixOnly, () => {
  const stateDir = makeDirs({ baseMode: 0o700, sessionMode: 0o770 });
  try {
    assert.throws(() => verifySessionDirs('s', { stateDir }), { code: 'invalid_request' });
  } finally {
    cleanup(stateDir);
  }
});

test('verifySessionDirs refuses a group-writable base without the sticky bit', posixOnly, () => {
  const stateDir = makeDirs({ baseMode: 0o770, sessionMode: 0o700 });
  try {
    assert.throws(() => verifySessionDirs('s', { stateDir }), /sticky/);
  } finally {
    cleanup(stateDir);
  }
});

test('verifySessionDirs refuses a symlinked session dir and a missing one', posixOnly, () => {
  const stateDir = makeDirs({ baseMode: 0o700, sessionMode: 0o700 });
  try {
    const real = path.join(stateDir, 'real');
    fs.mkdirSync(real, { mode: 0o700 });
    fs.symlinkSync(real, path.join(stateDir, 'link'));
    assert.throws(() => verifySessionDirs('link', { stateDir }), /symlink/);
    assert.throws(() => verifySessionDirs('absent', { stateDir }), { code: 'invalid_request' });
  } finally {
    cleanup(stateDir);
  }
});

test('RdpSession refuses to use a running daemon whose session dir is not private', posixOnly, async () => {
  const stateDir = makeDirs({ baseMode: 0o700, sessionMode: 0o755 });
  try {
    // A live pid makes the SDK want to connect; the loose directory must stop it first
    fs.writeFileSync(getPidPath('s', { stateDir }), String(process.pid));
    const rdp = new RdpSession({ session: 's', stateDir, timeout: 2000 });
    await assert.rejects(rdp.getInfo(), { code: 'invalid_request' });
  } finally {
    cleanup(stateDir);
  }
});

test('a 0775 state dir with no session dir is refused, and RdpSession fails fast', posixOnly, async () => {
  const stateDir = makeStateDir('rdp-v-');
  try {
    fs.chmodSync(stateDir, 0o775);
    assert.throws(() => verifyStateDir({ stateDir }), { code: 'invalid_request' });
    const started = Date.now();
    const rdp = new RdpSession({ session: 'fresh', stateDir, timeout: 2000 });
    await assert.rejects(rdp.getInfo(), { code: 'invalid_request' });
    assert.ok(Date.now() - started < 2000, 'should fail before any spawn timeout');
    assert.equal(fs.existsSync(path.join(stateDir, 'fresh')), false, 'must not create the session dir');
    fs.chmodSync(stateDir, 0o700);
    verifyStateDir({ stateDir });
  } finally {
    cleanup(stateDir);
  }
});

test('an over-long state dir throws at construction and creates nothing', () => {
  const stateDir = path.join(os.tmpdir(), 'rdp-long-' + 'x'.repeat(120));
  assert.throws(() => new RdpSession({ session: 's', stateDir }), RdpError);
  assert.equal(fs.existsSync(stateDir), false);
});
