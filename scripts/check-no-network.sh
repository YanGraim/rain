#!/usr/bin/env bash
# NFR-006: fails if a network crate is reachable from rain-cli through
# normal (non-dev, non-build) edges, or if tokio is built with `net`.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"

# Exact names, plus whole families matched by prefix (`hyper*`, `rustls*`, ...)
# so a new sub-crate of a banned family cannot slip through.
exact='h2|ureq|isahc|surf|attohttpc|minreq|ehttp|awc|axum|warp|tonic|native-tls|socket2|mio|quinn|trust-dns-resolver|hickory-resolver|async-std|async-net|async-io|smol|tokio-rustls|reqwless|ssh2|libssh2-sys|zmq|nng|websocket|tungstenite|tokio-tungstenite'
prefix='reqwest|hyper|rustls|curl|openssl|actix|libp2p'
banned="^((${exact})|(${prefix})[A-Za-z0-9_-]*)\$"

# Usage: check-no-network.sh [--tree-file FILE]
# --tree-file reads canned `cargo tree --prefix none --format '{p}|{f}'`
# output instead of running cargo; used by test-check-no-network.sh.
if [ "${1:-}" = "--tree-file" ]; then
  if [ -z "${2:-}" ] || [ ! -r "$2" ]; then
    echo "::error::--tree-file needs a readable file"
    exit 1
  fi
  tree="$(cat "$2")"
else
  if ! command -v cargo >/dev/null 2>&1; then
    echo "::error::cargo not found on PATH"
    exit 1
  fi
  # `cargo tree` failing must fail the check, so it is not run inside a pipe.
  tree="$(cargo tree --locked --manifest-path "$root/Cargo.toml" -p rain-cli \
    -e normal,features --prefix none --format '{p}|{f}')"
fi

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
