// Parity test: the SDK's path helpers must agree with the real daemon's on-disk layout.
// Runs only when AGENT_RDP_TEST_BINARY points at a built agent-rdp binary.
// Requires a prior `pnpm --filter ./packages/agent-rdp run build:ts` (imports from dist/).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { spawn } from 'node:child_process';
import { RdpSession, getPidPath, getSessionDir, getSocketPath, readDaemonPid } from '../dist/index.js';
import { findBinary } from '../dist/daemon.js';
import { cleanup, makeStateDir, mode, waitFor } from './helpers.mjs';

const BINARY = process.env.AGENT_RDP_TEST_BINARY;

test('daemon creates the layout and permissions the SDK expects', async (t) => {
  if (!BINARY) {
    t.skip('AGENT_RDP_TEST_BINARY not set');
    return;
  }
  const stateDir = makeStateDir('rdp-');
  const name = 'parity';
  const opts = { stateDir };
  const child = spawn(BINARY, ['--session', name, 'session', 'daemon'], {
    env: { ...process.env, AGENT_RDP_STATE_DIR: stateDir },
    stdio: 'ignore',
  });
  const exited = new Promise((resolve) => child.once('exit', resolve));
  try {
    const socketPath = getSocketPath(name, opts);
    assert.equal(typeof socketPath, 'string');
    assert.ok(await waitFor(() => fs.existsSync(socketPath), 10000), 'daemon socket did not appear');

    assert.equal(readDaemonPid(name, opts), child.pid);
    assert.equal(mode(stateDir), 0o700);
    assert.equal(mode(getSessionDir(name, opts)), 0o700);
    assert.equal(mode(socketPath), 0o600);
    assert.equal(mode(getPidPath(name, opts)), 0o600);
  } finally {
    child.kill('SIGTERM');
    await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 5000))]);
    if (child.exitCode === null) child.kill('SIGKILL');
    cleanup(stateDir);
  }
});

test('AGENT_RDP_BINARY is honoured and must exist', () => {
  const previous = process.env.AGENT_RDP_BINARY;
  try {
    process.env.AGENT_RDP_BINARY = '/nonexistent/agent-rdp';
    assert.throws(() => findBinary(), /AGENT_RDP_BINARY.*does not exist/);
    process.env.AGENT_RDP_BINARY = 'relative/agent-rdp';
    assert.throws(() => findBinary(), /absolute/);
    process.env.AGENT_RDP_BINARY = process.execPath;
    assert.equal(findBinary(), process.execPath);
  } finally {
    if (previous === undefined) delete process.env.AGENT_RDP_BINARY;
    else process.env.AGENT_RDP_BINARY = previous;
  }
});

test('RdpSession spawns the daemon into stateDir without passing it as an argument', async (t) => {
  if (!BINARY) {
    t.skip('AGENT_RDP_TEST_BINARY not set');
    return;
  }
  const stateDir = makeStateDir('rdp-');
  const name = 'sdk-spawn';
  const opts = { stateDir };
  const previous = process.env.AGENT_RDP_BINARY;
  process.env.AGENT_RDP_BINARY = BINARY;
  const rdp = new RdpSession({ session: name, stateDir, timeout: 5000 });
  try {
    // getInfo needs the daemon but no RDP server; the SDK spawns the daemon to answer it
    const info = await rdp.getInfo();
    assert.ok(info, 'getInfo returned nothing');

    const socketPath = getSocketPath(name, opts);
    assert.ok(fs.existsSync(socketPath), 'socket missing at the SDK path');
    assert.ok(fs.existsSync(getPidPath(name, opts)), 'pid file missing at the SDK path');
    const pid = readDaemonPid(name, opts);
    assert.ok(pid, 'pid file holds no pid');

    if (process.platform === 'linux') {
      const argv = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0').filter(Boolean);
      assert.deepEqual(argv.slice(1), ['--session', name, 'session', 'daemon']);
      assert.ok(!argv.some((arg) => arg.includes(stateDir)), `argv leaks the state dir: ${argv}`);
    }
  } finally {
    await rdp.close();
    const pid = readDaemonPid(name, opts);
    if (pid) {
      try {
        process.kill(pid, 'SIGTERM');
      } catch {
        // already gone
      }
      await waitFor(() => {
        try {
          process.kill(pid, 0);
          return false;
        } catch {
          return true;
        }
      }, 5000);
    }
    if (previous === undefined) delete process.env.AGENT_RDP_BINARY;
    else process.env.AGENT_RDP_BINARY = previous;
    cleanup(stateDir);
  }
});
