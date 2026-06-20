#!/usr/bin/env bash
# shellcheck disable=SC2046  # release-package-args.sh intentionally expands to multiple args
cargo release version $(./tools/release-package-args.sh) --execute "$1"
