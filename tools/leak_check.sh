#!/usr/bin/env bash
# Spec 004 T045: verify zero memory leaks during peak zero-copy parsing.
#
# Runs the core crate's zero-copy and serialization allocation tests under
# valgrind. Requires valgrind to be installed.
#
# Usage: ./tools/leak_check.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v valgrind >/dev/null 2>&1; then
    echo "error: valgrind is not installed (e.g. apt install valgrind)" >&2
    exit 1
fi

# Build the test binaries without running them.
cargo test -p async-opcua-core --no-run --test zero_copy_alloc --test serialization_alloc 2>&1 | tail -2

for test_bin in zero_copy_alloc serialization_alloc; do
    bin=$(find target/debug/deps -maxdepth 1 -name "${test_bin}-*" -type f -executable | head -1)
    if [ -z "$bin" ]; then
        echo "error: test binary for $test_bin not found" >&2
        exit 1
    fi
    echo "=== valgrind: $test_bin"
    # Rust's libtest harness leaves a small thread-local allocation that
    # Valgrind reports as "possibly lost". Treat definite/indirect leaks as
    # failures; still print the full summary for visibility.
    valgrind \
        --leak-check=full \
        --show-leak-kinds=definite,indirect \
        --errors-for-leak-kinds=definite,indirect \
        --error-exitcode=1 \
        "$bin"
done

echo "No leaks detected."
