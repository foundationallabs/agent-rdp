/**
 * Daemon process management for agent-rdp.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import { IpcClient } from './client.js';
import { STATE_DIR_ENV, getSessionDir, getSocketPath, getStateDir, isMissingDirError, readDaemonPid, verifySessionDirs, type PathOptions } from './paths.js';
import { RdpError } from './types.js';

/** Environment variable naming the agent-rdp binary to run instead of the platform package's. */
export const BINARY_ENV = 'AGENT_RDP_BINARY';

const MAX_STARTUP_WAIT_MS = 10000;
const STARTUP_POLL_INTERVAL_MS = 100;

// Create require function for resolving platform package paths in ESM
const require = createRequire(import.meta.url);

/**
 * Get the platform package name for the current OS/arch.
 */
export function getPlatformPackage(): string {
  const platform = process.platform; // 'darwin', 'linux'
  const arch = process.arch; // 'arm64', 'x64'
  return `@foundationallabs/agent-rdp-${platform}-${arch}`;
}

/**
 * Find the agent-rdp binary: `AGENT_RDP_BINARY` (an absolute path) when set, otherwise the
 * installed platform package's binary.
 *
 * @throws RdpError `invalid_request` when `AGENT_RDP_BINARY` is relative or does not exist.
 */
export function findBinary(): string {
  const override = process.env[BINARY_ENV];
  if (override) {
    if (!path.isAbsolute(override)) {
      throw new RdpError('invalid_request', `${BINARY_ENV} must be an absolute path, got ${JSON.stringify(override)}`);
    }
    if (!fs.existsSync(override)) {
      throw new RdpError('invalid_request', `${BINARY_ENV} points to ${override}, which does not exist`);
    }
    return override;
  }

  const platformPackage = getPlatformPackage();
  const ext = process.platform === 'win32' ? '.exe' : '';

  try {
    // Resolve the platform package's package.json, then find the binary
    const packageJsonPath = require.resolve(`${platformPackage}/package.json`);
    const packageDir = path.dirname(packageJsonPath);
    const binaryPath = path.join(packageDir, 'bin', `agent-rdp${ext}`);

    if (!fs.existsSync(binaryPath)) {
      throw new RdpError(
        'internal_error',
        `Binary not found at ${binaryPath}. Platform package ${platformPackage} may not be installed correctly.`
      );
    }

    return binaryPath;
  } catch (err) {
    if (err instanceof RdpError) {
      throw err;
    }
    throw new RdpError(
      'not_supported',
      `Platform package ${platformPackage} is not installed. ` +
        `Make sure you have the correct optional dependency installed for your platform.`
    );
  }
}

/**
 * Manages the daemon lifecycle for a session.
 */
export class DaemonManager {
  private readonly stateDir: string;
  private readonly sessionDir: string;

  /**
   * @param session Session name (validated by the path helpers).
   * @param streamPort Stream port passed to the daemon (0 = disabled).
   * @param opts Path options. The state directory is resolved once here (option, then
   *   `AGENT_RDP_STATE_DIR`, then the default) and used for every path and for the daemon.
   */
  constructor(
    private session: string,
    private streamPort: number = 0,
    opts: PathOptions = {},
  ) {
    this.stateDir = getStateDir(opts.stateDir);
    this.sessionDir = getSessionDir(session, { stateDir: this.stateDir });
    // Fail on an over-long socket path now, before anything is created.
    getSocketPath(session, { stateDir: this.stateDir });
  }

  private get pathOptions(): PathOptions {
    return { stateDir: this.stateDir };
  }

  /**
   * Check if the daemon is running (its pid file names a live process).
   */
  isRunning(): boolean {
    const pid = readDaemonPid(this.session, this.pathOptions);
    if (pid === null) {
      return false;
    }
    try {
      // Signal 0 only checks that the process exists
      process.kill(pid, 0);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Ensure the daemon is running, spawning it if necessary.
   * Returns an IpcClient connected to the daemon.
   */
  async ensureRunning(): Promise<IpcClient> {
    return (await this.ensureRunningWithStatus()).client;
  }

  /**
   * Like {@link ensureRunning}, also reporting whether this call spawned a new daemon.
   * @internal
   */
  async ensureRunningWithStatus(): Promise<{ client: IpcClient; spawned: boolean }> {
    // Never trust a pid file or socket in a directory another user controls
    this.verifyDirsIfPresent();

    const spawned = !this.isRunning();
    if (spawned) {
      await this.spawn();
      // The daemon created the directories just now; make sure no one else swapped them in
      verifySessionDirs(this.session, this.pathOptions);
    }

    const client = new IpcClient(this.session, this.pathOptions);
    await client.connect();
    return { client, spawned };
  }

  /**
   * Verify the session's directories if they exist yet. A missing session directory is fine,
   * but the state directory must still be safe if it exists (a daemon would refuse an unsafe
   * one and the user would only see a startup timeout).
   */
  private verifyDirsIfPresent(): void {
    try {
      verifySessionDirs(this.session, this.pathOptions);
    } catch (err) {
      if (!isMissingDirError(err)) throw err;
    }
  }

  /**
   * Spawn the daemon process.
   */
  private async spawn(): Promise<void> {
    const binary = findBinary();

    // Ensure session directory exists
    fs.mkdirSync(this.sessionDir, { recursive: true, mode: 0o700 });

    // Build daemon arguments
    const args = ['--session', this.session];
    if (this.streamPort > 0) {
      args.push('--stream-port', this.streamPort.toString());
    }
    args.push('session', 'daemon');

    // Spawn daemon in background
    const child = spawn(binary, args, {
      detached: true,
      stdio: 'ignore',
      env: { ...process.env, [STATE_DIR_ENV]: this.stateDir },
    });

    child.unref();

    // Wait for daemon to be ready (socket file exists or TCP port responds)
    const socketPath = getSocketPath(this.session, this.pathOptions);
    const startTime = Date.now();

    while (Date.now() - startTime < MAX_STARTUP_WAIT_MS) {
      if (typeof socketPath === 'number') {
        // Windows: try TCP connection
        try {
          const client = new IpcClient(this.session, this.pathOptions);
          await client.connect();
          await client.close();
          return;
        } catch {
          // Not ready yet
        }
      } else {
        // Unix: check if socket file exists
        if (fs.existsSync(socketPath)) {
          // Give it a moment to be ready
          await sleep(50);
          return;
        }
      }

      await sleep(STARTUP_POLL_INTERVAL_MS);
    }

    throw new RdpError('daemon_not_running', 'Daemon failed to start within timeout');
  }

  /**
   * Get the socket path for this session.
   */
  getSocketPath(): string | number {
    return getSocketPath(this.session, this.pathOptions);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
