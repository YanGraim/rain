#!/usr/bin/env bash
# Proves every `disallowed-methods` entry in clippy.toml actually fires:
# lints ci/disallowed-probe (one call per entry) and requires one
# "disallowed method" error per configured path.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
probe="$root/ci/disallowed-probe"

# Entries that cannot be called on the stable toolchain (unstable API).
skip='^std::fs::set_permissions_nofollow$'

out="$(cd "$probe" && cargo clippy --locked --quiet --lib --target-dir "$root/target/disallowed-probe" -- -D warnings 2>&1 || true)"

if grep -q 'does not refer to' <<<"$out"; then
  echo "::error::clippy.toml has a path that does not resolve:"
  grep 'does not refer to' <<<"$out"
  exit 1
fi

missing=0
while IFS= read -r path; do
  if grep -Eq "$skip" <<<"$path"; then
    continue
  fi
  if ! grep -Fq "disallowed method \`$path\`" <<<"$out"; then
    echo "::error::clippy.toml entry \`$path\` did not fire on the probe"
    missing=1
  fi
done < <(sed -nE 's/.*path = "([^"]+)".*/\1/p' "$root/clippy.toml")

if [ "$missing" -ne 0 ]; then
  exit 1
fi
echo "all disallowed-methods entries fire"
