#!/usr/bin/env bash
#
# Fourth-stack interop test: drive the async-opcua demo server with the OPC Foundation reference
# stack (OPC UA .NET Standard). A different implementation lineage from node-opcua (JS),
# open62541 (C) and asyncua (Python) — and the implementation the UACTT is built on, so agreement
# here is the strongest cross-stack conformance signal we have.
#
#   ./run-dotnet.sh
#
# Requires: cargo and the .NET 8 SDK (`dotnet`). The OPC Foundation client is pulled from NuGet.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
endpoint="opc.tcp://127.0.0.1:4855"

# Locate dotnet (PATH, or a local install under $HOME/.dotnet as used in CI).
if command -v dotnet >/dev/null 2>&1; then
  DOTNET="dotnet"
elif [ -x "$HOME/.dotnet/dotnet" ]; then
  DOTNET="$HOME/.dotnet/dotnet"
else
  echo "dotnet SDK not found (install .NET 8)" >&2
  exit 1
fi

echo "==> building .NET interop client"
"$DOTNET" build -c Release -v q "$here/interop.csproj" >/dev/null

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

echo "==> running .NET (OPC Foundation reference) interop client against ${endpoint}"
set +e
"$DOTNET" run -c Release --no-build --project "$here/interop.csproj" -- "$endpoint"
rc=$?
set -e

echo "==> stopping demo server"
kill "$srv_pid" 2>/dev/null || true
exit "$rc"
