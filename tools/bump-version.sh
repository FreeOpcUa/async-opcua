#!/usr/bin/env bash
cargo release version $(./tools/release-package-args.sh) --execute $1
