#!/usr/bin/env bash
# NFR-006: fails if a network crate is reachable from rain-cli through
# normal (non-dev, non-build) edges, or if tokio is built with `net`.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v cargo >/dev/null 2>&1; then
  echo "::error::cargo not found on PATH"
  exit 1
fi

banned='^(reqwest|hyper|hyper-util|h2|ureq|curl|curl-sys|isahc|surf|attohttpc|minreq|ehttp|awc|actix-web|axum|warp|tonic|tungstenite|tokio-tungstenite|native-tls|rustls|openssl|openssl-sys|socket2|mio|libp2p|quinn|trust-dns-resolver|hickory-resolver)$'

# `cargo tree` failing must fail the check, so it is not run inside a pipe.
tree="$(cargo tree --locked --manifest-path "$root/Cargo.toml" -p rain-cli \
  -e normal,features --prefix none --format '{p}|{f}')"

offenders="$(
  awk -F'|' '{ split($1, p, " "); print p[1] }' <<<"$tree" | grep -E "$banned" | sort -u || true
)"
if awk -F'|' '$1 ~ /^tokio / { n = split($2, f, ","); for (i = 1; i <= n; i++) if (f[i] == "net") found = 1 } END { exit !found }' <<<"$tree"; then
  offenders="$(printf '%s\ntokio (feature net)' "$offenders" | sed '/^$/d')"
fi

if [ -n "$offenders" ]; then
  echo "::error::network crates in the rain-cli dependency graph (NFR-006):"
  echo "$offenders"
  exit 1
fi
echo "no network crates in the rain-cli dependency graph"
