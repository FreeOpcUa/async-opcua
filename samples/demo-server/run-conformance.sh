#!/usr/bin/env bash
#
# Feature 020 (US3) — launch a demo-server conformance profile for the UACTT.
#
# Boots one of the two demo-server profiles with a clean PKI directory, then
# prints the endpoint URLs and the server certificate thumbprints you must trust
# in the UACTT (and where to drop the UACTT client cert to be trusted back).
#
#   ./run-conformance.sh rsa            # RSA profile  (port 4855)
#   ./run-conformance.sh ecc            # ECC profile, P-256 (port 4856)
#   ./run-conformance.sh ecc p384       # ECC profile, P-384
#
# See docs/ctt-conformance.md for the full UACTT run guide.
set -euo pipefail

profile="${1:-}"
curve="${2:-p256}"

# Run from this script's directory so the demo-server's relative paths resolve.
cd "$(dirname "$0")"

case "$profile" in
  rsa)
    conf="sample.server.test.conf"
    pki="./pki"
    port="4855"
    args=(--config "$conf")
    ;;
  ecc)
    conf="sample.server.ecc.conf"
    pki="./pki-ecc"
    port="4856"
    args=(--config "$conf" --ecc "$curve")
    ;;
  *)
    echo "usage: $0 <rsa|ecc> [p256|p384]" >&2
    exit 2
    ;;
esac

host="$(hostname)"
cert="$pki/own/cert.der"

echo "==> cleaning PKI directory: $pki"
rm -rf "$pki"

echo "==> starting '$profile' demo-server (config: $conf)"
cargo run -q -p async-opcua-demo-server -- "${args[@]}" &
srv_pid=$!
# shellcheck disable=SC2064
trap "kill ${srv_pid} 2>/dev/null || true" INT TERM EXIT

# Wait for the server to provision/generate its certificate (up to ~30s).
for _ in $(seq 1 60); do
  [ -f "$cert" ] && break
  if ! kill -0 "$srv_pid" 2>/dev/null; then
    echo "server exited before writing $cert" >&2
    wait "$srv_pid"
    exit 1
  fi
  sleep 0.5
done

echo
echo "================================================================"
echo " ${profile} profile is up. Configure the UACTT against:"
echo "----------------------------------------------------------------"
echo "  Endpoint URL : opc.tcp://${host}:${port}/"
if [ "$profile" = "ecc" ]; then
  echo "  Policies     : ECC_nistP256 / ECC_nistP384 (Sign, SignAndEncrypt)"
else
  echo "  Policies     : None, Basic128Rsa15, Basic256, Basic256Sha256,"
  echo "                 Aes128-Sha256-RsaOaep, Aes256-Sha256-RsaPss (Sign, SignAndEncrypt)"
fi
echo "  User tokens  : Anonymous; user/pass sample1 (pwd: sample1_password); x509"
echo "----------------------------------------------------------------"
if [ -f "$cert" ] && command -v openssl >/dev/null 2>&1; then
  sha1="$(openssl x509 -in "$cert" -inform der -noout -fingerprint -sha1 2>/dev/null | cut -d= -f2)"
  sha256="$(openssl x509 -in "$cert" -inform der -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
  echo "  Server cert  : $cert"
  echo "    SHA1   : ${sha1}"
  echo "    SHA256 : ${sha256}"
else
  echo "  Server cert  : $cert (install 'openssl' to print thumbprints)"
fi
echo "----------------------------------------------------------------"
echo " Cross-trust:"
echo "  * Trust THIS server cert in the UACTT (import $cert)."
echo "  * Drop the UACTT client cert into ${pki}/trusted/ (then restart, or"
echo "    the server auto-trusts clients: trust_client_certs=true)."
echo "================================================================"
echo " Press Ctrl-C to stop the server."
echo

wait "$srv_pid"
