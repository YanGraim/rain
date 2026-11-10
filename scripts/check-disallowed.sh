#!/usr/bin/env bash
# Proves every `disallowed-methods` entry in clippy.toml actually fires:
# lints ci/disallowed-probe (one call per entry) and requires one
# "disallowed method" error per configured path.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
probe="$root/ci/disallowed-probe"

# Entries that cannot be called on the stable toolchain (unstable API).
skip='^std::fs::set_permissions_nofollow$'

if ! command -v cargo >/dev/null 2>&1; then
  echo "::error::cargo not found on PATH"
  exit 1
fi

# The probe is expected to fail clippy (every call is a lint hit), so a
# non-zero exit is normal. It must be a lint failure, though, not a missing
# toolchain or a build error that would hide every hit.
status=0
out="$(cd "$probe" && cargo clippy --locked --quiet --lib --target-dir "$root/target/disallowed-probe" -- -D warnings 2>&1)" || status=$?

if [ "$status" -eq 0 ]; then
  echo "::error::clippy passed on the probe; no disallowed method fired"
  exit 1
fi
if ! grep -q 'disallowed method' <<<"$out"; then
  echo "::error::clippy failed (exit $status) without any disallowed-method hit:"
  echo "$out"
  exit 1
fi

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
