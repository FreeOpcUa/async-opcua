#!/usr/bin/env bash
#
# Third-stack interop test: drive the async-opcua demo server with the Python asyncua client.
# A different implementation lineage from node-opcua (JS) and open62541 (C); three passing
# stacks is a strong conformance signal and any disagreement is high-signal.
#
#   ./run-asyncua.sh
#   ./run-asyncua.sh --external opc.tcp://127.0.0.1:4840
#
# Requires: cargo and python3 (>= 3.9). asyncua is used if already importable, otherwise it is
# installed into a local virtualenv (.venv, git-ignored).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
endpoint="opc.tcp://127.0.0.1:4855"
launch_server="1"

usage() {
  cat <<'USAGE'
usage:
  run-asyncua.sh
  run-asyncua.sh --external <endpoint-url>

Default mode launches the async-opcua demo server and runs the full demo profile.
External mode does not launch a server and runs the portable standard-node profile.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --external)
      if [ "$#" -lt 2 ]; then
        echo "--external requires an endpoint URL" >&2
        exit 2
      fi
      launch_server="0"
      endpoint="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      endpoint="$1"
      shift
      ;;
  esac
done

# Use a system asyncua if present, else install into a local venv.
if python3 -c "import asyncua" 2>/dev/null; then
  PY="python3"
else
  echo "==> installing asyncua into a virtualenv (first run only)"
  python3 -m venv "$here/.venv"
  "$here/.venv/bin/pip" install --quiet --upgrade pip
  # Pin the major version so a future breaking asyncua release can't silently break CI.
  "$here/.venv/bin/pip" install --quiet 'asyncua==2.0.*'
  PY="$here/.venv/bin/python"
fi

if [ "$launch_server" = "0" ]; then
  echo "==> running asyncua portable interop client against external endpoint ${endpoint}"
  exec "$PY" "$here/portable-test.py" "$endpoint"
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
