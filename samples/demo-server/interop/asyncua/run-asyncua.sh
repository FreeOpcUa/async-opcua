#!/usr/bin/env bash
#
# Third-stack interop test: drive the async-opcua demo server with the Python asyncua client.
# A different implementation lineage from node-opcua (JS) and open62541 (C); three passing
# stacks is a strong conformance signal and any disagreement is high-signal.
#
#   ./run-asyncua.sh
#
# Requires: cargo and python3 (>= 3.9). asyncua is used if already importable, otherwise it is
# installed into a local virtualenv (.venv, git-ignored).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
endpoint="opc.tcp://127.0.0.1:4855"

# Use a system asyncua if present, else install into a local venv.
if python3 -c "import asyncua" 2>/dev/null; then
  PY="python3"
else
  echo "==> installing asyncua into a virtualenv (first run only)"
  python3 -m venv "$here/.venv"
  "$here/.venv/bin/pip" install --quiet --upgrade pip
  "$here/.venv/bin/pip" install --quiet asyncua
  PY="$here/.venv/bin/python"
fi

# The demo server loads log4rs.yaml relative to its own directory, so run it from there.
cd "$here/../.."
conf="interop/interop.server.conf"
pki="interop/pki-interop"
cert="$pki/own/cert.der"

echo "==> cleaning PKI directory: $pki"
rm -rf "$pki"
echo "==> building demo server"
cargo build -q -p async-opcua-demo-server
echo "==> starting demo server (config: $conf)"
cargo run -q -p async-opcua-demo-server -- --config "$conf" &
srv_pid=$!
# shellcheck disable=SC2064
trap "kill ${srv_pid} 2>/dev/null || true" INT TERM EXIT
for _ in $(seq 1 120); do
  [ -f "$cert" ] && break
  if ! kill -0 "$srv_pid" 2>/dev/null; then
    echo "server exited before writing $cert" >&2
    exit 1
  fi
  sleep 0.5
done
sleep 2

echo "==> running asyncua interop client against ${endpoint}"
set +e
"$PY" "$here/asyncua-test.py" "$endpoint"
rc=$?
set -e

echo "==> stopping demo server"
kill "$srv_pid" 2>/dev/null || true
exit "$rc"
