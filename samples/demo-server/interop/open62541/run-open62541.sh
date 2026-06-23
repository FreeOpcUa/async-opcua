#!/usr/bin/env bash
#
# Second-stack interop test: drive the async-opcua demo server with an open62541 (C) client.
# A different implementation lineage from the node-opcua harness, so two passing stacks are
# a strong conformance signal and a disagreement is high-signal.
#
#   ./run-open62541.sh
#
# Requires: cargo, cmake, gcc/make, git, and the OpenSSL dev headers. The open62541 source
# is cloned + built once (cached under src/ and build/, both git-ignored).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
endpoint="opc.tcp://127.0.0.1:4855"
O62_VERSION="v1.4.6"

# 1. Fetch + build open62541 (single-file amalgamation with OpenSSL encryption) — cached.
if [ ! -f "$here/build/open62541.c" ]; then
  echo "==> fetching open62541 $O62_VERSION"
  rm -rf "$here/src"
  git clone --depth 1 --branch "$O62_VERSION" https://github.com/open62541/open62541.git "$here/src"
  echo "==> building open62541 (amalgamation + OpenSSL encryption)"
  cmake -S "$here/src" -B "$here/build" \
    -DUA_ENABLE_AMALGAMATION=ON -DUA_ENABLE_ENCRYPTION=OPENSSL \
    -DUA_ENABLE_SUBSCRIPTIONS=ON -DUA_BUILD_EXAMPLES=OFF -DCMAKE_BUILD_TYPE=Release >/dev/null
  make -C "$here/build" -j"$(nproc)" >/dev/null
fi

# 2. Compile the conformance client against the amalgamation (if missing or stale).
if [ ! -x "$here/client" ] || [ "$here/client.c" -nt "$here/client" ]; then
  echo "==> compiling open62541 client"
  gcc -O2 "$here/client.c" "$here/build/open62541.c" -I"$here/build" \
    -lssl -lcrypto -lpthread -o "$here/client"
fi

# 3. Boot the demo server (shared interop config; run from the demo-server dir for log4rs.yaml).
cd "$here/../.."
conf="interop/interop.server.conf"
pki="interop/pki-interop"
cert="$pki/own/cert.der"
echo "==> cleaning PKI directory: $pki"
rm -rf "$pki"
echo "==> building + starting demo server (config: $conf)"
cargo run -q -p async-opcua-demo-server -- --config "$conf" &
srv_pid=$!
# shellcheck disable=SC2064
trap "kill ${srv_pid} 2>/dev/null || true" INT TERM EXIT
for _ in $(seq 1 120); do
  [ -f "$cert" ] && break
  if ! kill -0 "$srv_pid" 2>/dev/null; then
    echo "server exited before writing $cert" >&2
    wait "$srv_pid" || true
    exit 1
  fi
  sleep 0.5
done
sleep 2

echo "==> running open62541 interop client against ${endpoint}"
set +e
"$here/client" "$endpoint"
rc=$?
set -e

echo "==> stopping demo server"
kill "$srv_pid" 2>/dev/null || true
exit "$rc"
