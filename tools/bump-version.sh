#!/usr/bin/env bash

# release-package-args.sh prints the package flags space-separated on one line
# (e.g. "--package a --package b"). Read them into an array so each flag is
# passed to cargo as its own argument, without relying on unquoted word
# splitting of a command substitution.
read -ra pkg_args < <(./tools/release-package-args.sh)
cargo release version "${pkg_args[@]}" --execute "$1"
