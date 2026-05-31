#!/usr/bin/env bash

# Get arguments for calls to `cargo release`, listing the packages we want to publish explicitly.

packages=$(./tools/publish-targets.sh)

while IFS= read -r line; do
    echo -n "--package $line "
done <<< "$packages"
