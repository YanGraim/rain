#!/usr/bin/env bash
# NFR-003: fails if the release `rain` binary is 15 MB or larger.
# Usage: check-binary-size.sh [path-to-binary]
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
bin="${1:-$root/target/release/rain}"
limit=$((15 * 1000 * 1000))

if [ ! -f "$bin" ]; then
  echo "::error::release binary not found at $bin"
  exit 1
fi

size="$(wc -c <"$bin" | tr -d ' ')"
if [ "$size" -ge "$limit" ]; then
  echo "::error::release binary is $size bytes, limit is $limit (NFR-003)"
  exit 1
fi
echo "release binary is $size bytes (limit $limit)"
