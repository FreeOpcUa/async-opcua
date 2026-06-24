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
    -DUA_ENABLE_SUBSCRIPTIONS=ON -DUA_ENABLE_PUBSUB=ON \
    -DUA_BUILD_EXAMPLES=OFF -DCMAKE_BUILD_TYPE=Release >/dev/null
  make -C "$here/build" -j"$(nproc)" >/dev/null
fi

# 1b. Cross-stack PubSub check: open62541's own decoder reads an async-opcua-produced UADP
# NetworkMessage and confirms the publisher/group/writer IDs, the UInt16 Status and the payload
# value (Part 14 §7.2.2.2.2 / §7.2.4.5.4). File-based, so no server is needed. The fixture is
# byte-pinned by the Rust test interop_golden_uadp_vector_is_byte_stable.
if [ ! -x "$here/decode-uadp" ] || [ "$here/decode-uadp.c" -nt "$here/decode-uadp" ]; then
  echo "==> compiling open62541 UADP decoder"
  gcc -O2 "$here/decode-uadp.c" "$here/build/open62541.c" -I"$here/build" \
    -lssl -lcrypto -lpthread -o "$here/decode-uadp"
fi
echo "==> open62541 PubSub UADP decode check"
"$here/decode-uadp" "$here/uadp-fixture.bin"

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
# A companion server that does NOT auto-trust client certs, for the untrusted-cert test.
nt_conf="interop/interop.server.notrust.conf"
nt_pki="interop/pki-notrust"
nt_cert="$nt_pki/own/cert.der"
nt_endpoint="opc.tcp://127.0.0.1:4856"
echo "==> cleaning PKI directories: $pki $nt_pki"
rm -rf "$pki" "$nt_pki"
echo "==> building demo server"
cargo build -q -p async-opcua-demo-server
echo "==> starting demo servers (trust-all :4855, no-trust :4856)"
cargo run -q -p async-opcua-demo-server -- --config "$conf" &
srv_pid=$!
cargo run -q -p async-opcua-demo-server -- --config "$nt_conf" &
srv_pid2=$!
# shellcheck disable=SC2064
trap "kill ${srv_pid} ${srv_pid2} 2>/dev/null || true" INT TERM EXIT
for _ in $(seq 1 120); do
  [ -f "$cert" ] && [ -f "$nt_cert" ] && break
  if ! kill -0 "$srv_pid" 2>/dev/null || ! kill -0 "$srv_pid2" 2>/dev/null; then
    echo "a server exited before writing its certificate" >&2
    exit 1
  fi
  sleep 0.5
done
sleep 2

echo "==> running open62541 interop client against ${endpoint}"
set +e
NOTRUST_ENDPOINT="$nt_endpoint" "$here/client" "$endpoint"
rc=$?
set -e

echo "==> stopping demo servers"
kill "$srv_pid" "$srv_pid2" 2>/dev/null || true
exit "$rc"
