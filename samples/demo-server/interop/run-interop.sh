#!/usr/bin/env bash
#
# Interop conformance smoke test: boot the async-opcua demo server and drive it with an
# independent OPC UA stack (node-opcua). This is the practical substitute for the official
# UACTT, which requires OPC Foundation corporate membership.
#
#   ./run-interop.sh
#
# Requires: cargo, node (>= 18), npm. Exits non-zero if any interop check fails.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"   # the interop/ directory
host="127.0.0.1"
port="4855"
endpoint="opc.tcp://${host}:${port}/"

echo "==> installing node-opcua (first run only)"
[ -d "$here/node_modules" ] || (cd "$here" && npm install --no-audit --no-fund)

# The demo server loads log4rs.yaml (and other assets) relative to its own directory, so
# run it from there. The config's pki_dir (./pki-interop) and the cert then resolve under
# the demo-server directory.
cd "$here/.."
conf="interop/interop.server.conf"
pki="interop/pki-interop"
cert="$pki/own/cert.der"

echo "==> cleaning PKI directories"
rm -rf "$pki" "$here/client-pki"

echo "==> building demo server"
cargo build -q -p async-opcua-demo-server
echo "==> starting demo server (config: $conf)"
cargo run -q -p async-opcua-demo-server -- --config "$conf" &
srv_pid=$!
# shellcheck disable=SC2064
trap "kill ${srv_pid} 2>/dev/null || true" INT TERM EXIT

# Wait for the server to generate its certificate (up to ~60s).
for _ in $(seq 1 120); do
  [ -f "$cert" ] && break
  if ! kill -0 "$srv_pid" 2>/dev/null; then
    echo "server exited before writing $cert" >&2
    wait "$srv_pid" || true
    exit 1
  fi
  sleep 0.5
done
# Give the listener a moment after the cert appears.
sleep 2

echo "==> running interop smoke test against ${endpoint}"
set +e
node "$here/interop-test.mjs" "$endpoint"
rc=$?
set -e

echo "==> stopping demo server"
kill "$srv_pid" 2>/dev/null || true
exit "$rc"
