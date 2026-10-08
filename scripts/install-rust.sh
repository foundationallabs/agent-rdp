#!/bin/sh
# Install the toolchain pinned in rust-toolchain.toml. Extra arguments go to rustup,
# e.g. `--target aarch64-apple-darwin`.
set -eu
channel=$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$(dirname "$0")/../rust-toolchain.toml")
if [ -z "$channel" ]; then
  echo "rust-toolchain.toml has no channel" >&2
  exit 1
fi
rustup toolchain install "$channel" --profile minimal "$@"
rustc --version
