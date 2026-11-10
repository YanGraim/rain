#!/usr/bin/env bash
# Self-test for check-no-network.sh (NFR-006): canned `cargo tree` outputs
# in scripts/fixtures/no-network must pass (pass*.txt) or fail (fail*.txt).
set -euo pipefail

dir="$(cd "$(dirname "$0")" && pwd)"
check="$dir/check-no-network.sh"
fixtures="$dir/fixtures/no-network"
bad=0

for f in "$fixtures"/pass*.txt; do
  if ! "$check" --tree-file "$f" >/dev/null 2>&1; then
    echo "::error::expected pass but failed: $(basename "$f")"
    bad=1
  fi
done
for f in "$fixtures"/fail*.txt; do
  if "$check" --tree-file "$f" >/dev/null 2>&1; then
    echo "::error::expected failure but passed: $(basename "$f")"
    bad=1
  fi
done

[ "$bad" -eq 0 ] || exit 1
echo "check-no-network self-test passed"
