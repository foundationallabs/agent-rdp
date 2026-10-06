// Verifies the exact IPC payload RdpSession.connect() sends to the daemon.
// A fake daemon listens on the session's real socket path, so no SDK internals are stubbed.
// Requires a prior `pnpm --filter agent-rdp run build:ts` (imports from dist/).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as net from 'node:net';
import { randomUUID } from 'node:crypto';
import { RdpSession } from '../dist/index.js';
import { getSessionDir, getSocketPath } from '../dist/client.js';

/** Start a fake daemon for a fresh session; resolves with the session name and received requests. */
async function startFakeDaemon() {
  const session = `sdk-test-${randomUUID().slice(0, 8)}`;
  const dir = getSessionDir(session);
  fs.mkdirSync(dir, { recursive: true });
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
        const response = { success: true, data: { type: 'connected', host: 'h', width: 1, height: 1 } };
        socket.write(JSON.stringify(response) + '\n');
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
