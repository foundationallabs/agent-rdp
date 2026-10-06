# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Rust
cargo build           # Build all crates
cargo build --release # Release build
cargo test            # Run all tests
cargo test -p agent-rdp-daemon  # Test specific crate
cargo test test_name  # Run single test

# npm/pnpm
pnpm install          # Install dependencies
pnpm build            # Build native binary + copy to bin/
pnpm build:ts         # Build TypeScript only
pnpm build:all        # Cross-compile all platforms (needs `cross`)
pnpm cli              # Run the CLI (uses local platform binary)
pnpm example          # Run example script
```

## Architecture

agent-rdp is a CLI tool for AI agents to control Windows Remote Desktop sessions, built on IronRDP.

### Crate Structure

- **agent-rdp** - CLI binary that parses commands and communicates with daemon via IPC
- **agent-rdp-daemon** - Background process maintaining RDP connection and processing commands
- **agent-rdp-protocol** - Shared request/response types for IPC communication

### Monorepo Structure

This is a pnpm workspace monorepo:

- **packages/agent-rdp/** - Main npm package with TypeScript SDK and CLI entry point
- **packages/{platform}-{arch}/** - Platform-specific packages containing native binaries (`darwin-arm64`, `linux-x64`, `linux-arm64`)

The main package uses `optionalDependencies` with `os`/`cpu` fields so npm only installs the binary for the user's platform.

### TypeScript Structure

- **packages/agent-rdp/src/index.ts** - Main `RdpSession` class with sub-controllers (mouse, keyboard, scroll, clipboard, drives)
- **packages/agent-rdp/src/client.ts** - IPC client for Unix socket / TCP communication with daemon
- **packages/agent-rdp/src/daemon.ts** - Daemon lifecycle management (spawn, health check, binary resolution)
- **packages/agent-rdp/src/types.ts** - TypeScript interfaces mirroring `agent-rdp-protocol`
- **packages/agent-rdp/bin/cli.js** - CLI entry point that resolves and executes the platform binary

### Daemon-per-Session Model

1. CLI commands spawn a daemon process if one isn't running for the session
2. Daemon maintains the RDP connection and handles all RDP protocol operations
3. CLI ↔ Daemon communication via Unix sockets (macOS/Linux) or TCP (Windows)
4. Session state stored in `/tmp/agent-rdp/<session>/` (Unix) or `%TEMP%\agent-rdp\` (Windows)

### Key Components

**RDP Session** (`rdp_session.rs`): Wraps IronRDP connection with background frame processor. Handles TLS upgrade, CredSSP auth, and input/output channels.

**Handlers** (`handlers/*.rs`): Process specific command types (connect, screenshot, mouse, keyboard, clipboard, scroll). Each returns a `Response`.

**IPC**: `ipc_client.rs` (CLI side) and `ipc_server.rs` (daemon side) handle JSON-serialized Request/Response over sockets.

**Platform Abstraction**:
- `rdpdr_backend.rs` - Drive mapping backend (`NixRdpdrBackend` on Unix, custom `WinRdpdrBackend` on Windows)
- Socket paths vs TCP ports for IPC
- Temp directory locations

**WebSocket Streaming** (`ws_server.rs`, `ws_input.rs`): Optional debugging viewer. Enable with `--stream-port 9224`. Broadcasts JPEG frames, accepts mouse/keyboard input matching agent-browser protocol.

**UI Automation** (`automation/*.rs`): Windows UI Automation support via PowerShell agent. Enable with `--enable-win-automation` at connect time. Uses Dynamic Virtual Channel (DVC) for fast bidirectional IPC. See [docs/AUTOMATION.md](docs/AUTOMATION.md) for protocol details.

### Request Flow

```
CLI (agent-rdp)
  → session_manager.ensure_daemon()  # Spawns daemon if needed
  → ipc_client.send_request()        # JSON over socket
  → daemon receives via ipc_server
  → handlers::* processes command
  → rdp_session.* interacts with RDP
  → Response sent back via IPC
  → CLI formats output (JSON or human-readable)
```

### IronRDP Integration

Uses IronRDP crates for RDP protocol:
- `ironrdp` - Core protocol, connector, session management
- `ironrdp-cliprdr` - Clipboard redirection (CLIPRDR channel)
- `ironrdp-rdpdr` - Drive redirection (RDPDR channel)
- `ironrdp-tokio` - Async transport layer

Input sent as `FastPathInputEvent` (mouse via `MousePdu`, keyboard via scancode or unicode events).

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AGENT_RDP_HOST` | RDP server hostname or IP |
| `AGENT_RDP_PORT` | RDP server port (default: 3389) |
| `AGENT_RDP_USERNAME` | RDP username |
| `AGENT_RDP_PASSWORD` | RDP password |
| `AGENT_RDP_ALTERNATE_SHELL` | Alternate shell to start instead of the desktop |
| `AGENT_RDP_SESSION` | Session name (default: "default") |
| `AGENT_RDP_STREAM_PORT` | WebSocket streaming port (0 = disabled) |

## Release Process

This fork publishes `@foundationallabs/agent-rdp` and the platform packages `@foundationallabs/agent-rdp-{linux-x64,linux-arm64,darwin-arm64}` to npm. Upstream's release-please flow is removed.

1. Set the same version in `Cargo.toml` and the `package.json` of `packages/agent-rdp`, `packages/linux-x64`, `packages/linux-arm64` and `packages/darwin-arm64`
2. Push a tag `pace-v<version>` (or run the **Pace Release** workflow manually)
3. The workflow builds the three binaries, then publishes the platform packages and finally the main package with `npm publish --provenance` (needs the `NPM_TOKEN` secret)
