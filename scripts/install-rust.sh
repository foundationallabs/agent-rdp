#!/bin/sh
# Install the toolchain pinned in rust-toolchain.toml. Extra arguments go to rustup,
# e.g. `--target aarch64-apple-darwin`.
set -eu
toml="$(dirname "$0")/../rust-toolchain.toml"
channel=$(tr -d '\r' < "$toml" | sed -n 's/^channel = "\(.*\)"$/\1/p')
profile=$(tr -d '\r' < "$toml" | sed -n 's/^profile = "\(.*\)"$/\1/p')
if [ -z "$channel" ] || [ -z "$profile" ]; then
  echo "rust-toolchain.toml needs a channel and a profile" >&2
  exit 1
fi
rustup toolchain install "$channel" --profile "$profile" "$@"
rustc +"$channel" --version
