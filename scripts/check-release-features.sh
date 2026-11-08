#!/usr/bin/env bash
# Fails if the `testing` feature (in-memory fakes) is enabled on any crate
# reachable from rain-cli through normal (non-dev, non-build) edges.
#
# `cargo tree -e normal` is used instead of `cargo metadata`: metadata reports
# features unified with dev-dependencies, so a crate legitimately enabling
# `testing` in its tests would be flagged. `--prefix none` with a fixed
# `{p}|{f}` format gives one parseable line per package, no tree glyphs.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"

offenders="$(
  cargo tree --locked --manifest-path "$root/Cargo.toml" -p rain-cli \
    -e normal --prefix none --format '{p}|{f}' |
    awk -F'|' '{ n = split($2, f, ","); for (i = 1; i <= n; i++) if (f[i] == "testing") print $1 }' |
    sort -u
)"

if [ -n "$offenders" ]; then
  echo "::error::feature 'testing' is enabled in rain-cli's normal dependency graph:"
  echo "$offenders"
  exit 1
fi
echo "no test features in rain-cli's normal dependency graph"
