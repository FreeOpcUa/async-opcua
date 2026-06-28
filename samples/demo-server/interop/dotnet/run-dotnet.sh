#!/usr/bin/env bash
#
# Fourth-stack interop test: drive the async-opcua demo server with the OPC Foundation reference
# stack (OPC UA .NET Standard). A different implementation lineage from node-opcua (JS),
# open62541 (C) and asyncua (Python) — and the implementation the UACTT is built on, so agreement
# here is the strongest cross-stack conformance signal we have.
#
#   ./run-dotnet.sh
#   ./run-dotnet.sh --profile portable
#   ./run-dotnet.sh --external opc.tcp://127.0.0.1:4840
#
# Requires: cargo and the .NET 8 SDK (`dotnet`). The OPC Foundation client is pulled from NuGet.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
endpoint="opc.tcp://127.0.0.1:4855"
profile="async-opcua-demo"
security="auto"
launch_server="1"

usage() {
  cat <<'USAGE'
usage:
  run-dotnet.sh
  run-dotnet.sh --profile portable [--security none|best|auto]
  run-dotnet.sh --external <endpoint-url> [--profile portable|async-opcua-demo] [--security none|best|auto]

Default mode launches the async-opcua demo server and runs the full demo profile.
External mode does not launch a server and defaults to the portable profile with --security auto.
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
      if [ "$profile" = "async-opcua-demo" ]; then
        profile="portable"
      fi
      shift 2
      ;;
    --profile)
      if [ "$#" -lt 2 ]; then
        echo "--profile requires a value" >&2
        exit 2
      fi
      profile="$2"
      shift 2
      ;;
    --security)
      if [ "$#" -lt 2 ]; then
        echo "--security requires a value" >&2
        exit 2
      fi
      security="$2"
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

if [ "$launch_server" = "0" ]; then
  echo "==> running .NET (OPC Foundation reference) interop client against external endpoint ${endpoint}"
  exec "$DOTNET" run -c Release --no-build --project "$here/interop.csproj" -- \
    --profile "$profile" --security "$security" "$endpoint"
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

echo "==> running .NET (OPC Foundation reference) interop client against ${endpoint} (profile: ${profile})"
set +e
"$DOTNET" run -c Release --no-build --project "$here/interop.csproj" -- \
  --profile "$profile" --security "$security" "$endpoint"
rc=$?
set -e

echo "==> stopping demo server"
kill "$srv_pid" 2>/dev/null || true
exit "$rc"
