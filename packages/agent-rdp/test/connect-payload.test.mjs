// Verifies the exact IPC payload RdpSession.connect() sends to the daemon.
// A fake daemon listens on the session's real socket path, so no SDK internals are stubbed.
// Requires a prior `pnpm --filter ./packages/agent-rdp run build:ts` (imports from dist/).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as net from 'node:net';
import { randomUUID } from 'node:crypto';
import { RdpError, RdpSession } from '../dist/index.js';
import { getSessionDir, getSocketPath } from '../dist/client.js';
import { cleanup, makeStateDir } from './helpers.mjs';

// Use a private state directory: clients refuse a shared /tmp/agent-rdp that is world-writable
// without the sticky bit, and a test run should not depend on what is already there.
const STATE_DIR = makeStateDir('rdp-pay-');
process.env.AGENT_RDP_STATE_DIR = STATE_DIR;
process.on('exit', () => cleanup(STATE_DIR));

const CONNECTED = { success: true, data: { type: 'connected', host: 'h', width: 1, height: 1 } };

/**
 * Start a fake daemon for a fresh session; resolves with the session name and received requests.
 * `response` may be a function returning the response, to vary it per request.
 */
async function startFakeDaemon(response = CONNECTED) {
  const session = `sdk-test-${randomUUID().slice(0, 8)}`;
  const dir = getSessionDir(session);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); // clients refuse looser session dirs
  // DaemonManager.isRunning() only checks that the pid in this file is alive.
  fs.writeFileSync(`${dir}/pid`, String(process.pid));

  const requests = [];
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    let buffer = '';
    socket.on('data', (chunk) => {
      buffer += chunk.toString();
      let idx;
      while ((idx = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 1);
        requests.push(JSON.parse(line));
        const reply = typeof response === 'function' ? response() : response;
        socket.write(JSON.stringify(reply) + '\n');
      }
    });
  });
  await new Promise((resolve) => server.listen(getSocketPath(session), resolve));

  return {
    session,
    requests,
    async close() {
      // The SDK never closes its client socket; server.close() would wait forever otherwise.
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve) => server.close(resolve));
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

async function connectPayload(sessionOptions, connectOptions) {
  const daemon = await startFakeDaemon();
  try {
    const rdp = new RdpSession({ session: daemon.session, timeout: 5000, ...sessionOptions });
    await rdp.connect({ host: 'h', username: 'u', password: 'p', ...connectOptions });
    assert.equal(daemon.requests.length, 1);
    return daemon.requests[0];
  } finally {
    await daemon.close();
  }
}

test('connect sends alternate_shell verbatim when alternateShell is set', async () => {
  const shell = 'psm /u a@b /a host /c PSM-RDP';
  const payload = await connectPayload({}, { alternateShell: shell });
  assert.equal(payload.type, 'connect');
  assert.equal(payload.alternate_shell, shell);
});

test('connect omits alternate_shell when alternateShell is unset', async () => {
  const payload = await connectPayload({}, {});
  assert.equal(payload.type, 'connect');
  assert.equal('alternate_shell' in payload, false);
});

test('connect carries the core connection fields', async () => {
  const payload = await connectPayload({}, { port: 4489, domain: 'CORP', width: 1920, height: 1080 });
  assert.equal(payload.host, 'h');
  assert.equal(payload.port, 4489);
  assert.equal(payload.username, 'u');
  assert.equal(payload.password, 'p');
  assert.equal(payload.domain, 'CORP');
  assert.equal(payload.width, 1920);
  assert.equal(payload.height, 1080);
});

test('connect sends the stream options', async () => {
  const payload = await connectPayload(
    { streamPort: 9333, serveViewer: true, streamFps: 25, streamQuality: 55 },
    {},
  );
  assert.equal(payload.stream_port, 9333);
  assert.equal(payload.serve_viewer, true);
  assert.equal(payload.stream_fps, 25);
  assert.equal(payload.stream_quality, 55);
});

test('connect omits stream_fps when streamFps is unset so the daemon env/default applies', async () => {
  const payload = await connectPayload({}, {});
  assert.equal('stream_fps' in payload, false);
  assert.equal(payload.stream_quality, 80);
});

test('connect sends enable_credssp false when enableNla is false', async () => {
  const payload = await connectPayload({}, { enableNla: false });
  assert.equal(payload.enable_credssp, false);
});

test('connect omits enable_credssp when enableNla is unset so the daemon keeps NLA on', async () => {
  const payload = await connectPayload({}, {});
  assert.equal('enable_credssp' in payload, false);
});

test('connect sends server_cert_pin when serverCertPin is set', async () => {
  const pin = 'sha256/v0ED3aaQaqkZx0eWMgIKcV21wFokPfvCkSa1dZpbHNA=';
  const payload = await connectPayload({}, { serverCertPin: pin });
  assert.equal(payload.server_cert_pin, pin);
});

test('connect omits server_cert_pin when serverCertPin is unset', async () => {
  const payload = await connectPayload({}, {});
  assert.equal('server_cert_pin' in payload, false);
});

async function connectError(response) {
  const daemon = await startFakeDaemon(response);
  try {
    const rdp = new RdpSession({ session: daemon.session, timeout: 5000 });
    return await rdp.connect({ host: 'h', username: 'u', password: 'p' }).then(
      () => assert.fail('connect should have failed'),
      (error) => error,
    );
  } finally {
    await daemon.close();
  }
}

test('a refused login throws RdpError with the reason', async () => {
  const error = await connectError({
    success: false,
    error: { code: 'authentication_failed', message: 'refused', reason: 'wrong_password' },
  });
  assert.ok(error instanceof RdpError);
  assert.equal(error.code, 'authentication_failed');
  assert.equal(error.reason, 'wrong_password');
});

test('a pin mismatch throws RdpError with certificate_mismatch and no reason', async () => {
  const error = await connectError({
    success: false,
    error: { code: 'certificate_mismatch', message: 'key differs' },
  });
  assert.ok(error instanceof RdpError);
  assert.equal(error.code, 'certificate_mismatch');
  assert.equal(error.reason, undefined);
});

const PHASES = [
  { phase: 'rdp_connect', started_at_ms: 1_760_000_000_000, ms: 12, outcome: 'ok' },
  {
    phase: 'logon',
    started_at_ms: 1_760_000_000_012,
    ms: 20_000,
    outcome: 'timed_out',
    detail: { error_code: 'authentication_failed', timeout_ms: 20_000 },
  },
];

test('a failed connect throws RdpError with its phases and credential boundary', async () => {
  const error = await connectError({
    success: false,
    error: {
      code: 'authentication_failed',
      message: 'unconfirmed',
      reason: 'logon_unconfirmed',
      phases: PHASES,
      credential_boundary: 'logon',
    },
  });
  assert.ok(error instanceof RdpError);
  assert.deepEqual(error.phases, PHASES);
  assert.equal(error.credentialBoundary, 'logon');
});

test('a failed connect from a daemon that predates the trace has neither field', async () => {
  const error = await connectError({
    success: false,
    error: { code: 'connection_failed', message: 'refused' },
  });
  assert.equal(error.phases, undefined);
  assert.equal(error.credentialBoundary, undefined);
});

test('a successful connect returns its phases and credential boundary', async () => {
  const daemon = await startFakeDaemon({
    success: true,
    data: {
      type: 'connected',
      host: 'h',
      width: 1,
      height: 1,
      phases: PHASES,
      credential_boundary: 'rdp_connect',
    },
  });
  try {
    const rdp = new RdpSession({ session: daemon.session, timeout: 5000 });
    const result = await rdp.connect({ host: 'h', username: 'u', password: 'p' });
    assert.deepEqual(result.phases, PHASES);
    assert.equal(result.credentialBoundary, 'rdp_connect');
  } finally {
    await daemon.close();
  }
});

function connectedWithToken(token, port = 9333) {
  return { success: true, data: { ...CONNECTED.data, stream_token: token, stream_port: port } };
}

test('getStreamUrl carries the stream token, refreshes on reconnect and clears on disconnect', async () => {
  const tokens = ['abc', 'a b/c'];
  let connects = 0;
  const daemon = await startFakeDaemon(() => {
    // The disconnect request also gets a reply; only connect responses carry a token
    const last = daemon.requests[daemon.requests.length - 1];
    return last.type === 'connect' ? connectedWithToken(tokens[connects++]) : { success: true, data: { type: 'ok' } };
  });
  try {
    const rdp = new RdpSession({ session: daemon.session, timeout: 5000, streamPort: 9333 });
    assert.equal(rdp.getStreamUrl(), null);

    await rdp.connect({ host: 'h', username: 'u', password: 'p' });
    assert.equal(rdp.getStreamUrl(), 'ws://127.0.0.1:9333/?token=abc');

    await rdp.connect({ host: 'h', username: 'u', password: 'p' });
    assert.equal(rdp.getStreamUrl(), `ws://127.0.0.1:9333/?token=${encodeURIComponent('a b/c')}`);

    await rdp.disconnect();
    assert.equal(rdp.getStreamUrl(), null);
  } finally {
    await daemon.close();
  }
});

test('getStreamUrl uses the port the daemon reported, not the requested one', async () => {
  const daemon = await startFakeDaemon(connectedWithToken('abc', 9001));
  try {
    const rdp = new RdpSession({ session: daemon.session, timeout: 5000, streamPort: 9002 });
    const result = await rdp.connect({ host: 'h', username: 'u', password: 'p' });
    assert.equal(rdp.getStreamUrl(), 'ws://127.0.0.1:9001/?token=abc');
    assert.equal(result.streamUrl, 'ws://127.0.0.1:9001/?token=abc');
  } finally {
    await daemon.close();
  }
});

test('a failing connect after a successful one clears the stream URL', async () => {
  let fail = false;
  const daemon = await startFakeDaemon(() =>
    fail ? { success: false, error: { code: 'connection_failed', message: 'no' } } : connectedWithToken('abc'),
  );
  try {
    const rdp = new RdpSession({ session: daemon.session, timeout: 5000, streamPort: 9333 });
    await rdp.connect({ host: 'h', username: 'u', password: 'p' });
    assert.notEqual(rdp.getStreamUrl(), null);
    fail = true;
    await assert.rejects(rdp.connect({ host: 'h', username: 'u', password: 'p' }), RdpError);
    assert.equal(rdp.getStreamUrl(), null);
  } finally {
    await daemon.close();
  }
});

test('a daemon that reports no stream leaves streamUrl null and connect still succeeds', async () => {
  const daemon = await startFakeDaemon(CONNECTED);
  try {
    const rdp = new RdpSession({ session: daemon.session, timeout: 5000, streamPort: 9333 });
    const result = await rdp.connect({ host: 'h', username: 'u', password: 'p' });
    assert.equal(result.streamUrl, null);
    assert.equal(rdp.getStreamUrl(), null);
  } finally {
    await daemon.close();
  }
});

test('a re-created IPC client keeps the stream URL when no new daemon was spawned', async () => {
  const daemon = await startFakeDaemon(() => connectedWithToken('abc'));
  try {
    const rdp = new RdpSession({ session: daemon.session, timeout: 5000, streamPort: 9333 });
    await rdp.connect({ host: 'h', username: 'u', password: 'p' });
    const url = rdp.getStreamUrl();
    assert.notEqual(url, null);

    // close() drops the IPC client only; the next call reconnects to the same live daemon
    await rdp.close();
    await rdp.getInfo();
    assert.equal(rdp.getStreamUrl(), url);
  } finally {
    await daemon.close();
  }
});
