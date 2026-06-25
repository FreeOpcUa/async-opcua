#!/usr/bin/env bash

# Check if all release targets have the same version number set, which we currently require. All releases
# release every package, currently.
packages=$(./tools/publish-targets.sh)

items=""

while IFS= read -r line; do
    if [[ -n "$items" ]]; then
        items+=", "
    fi
    items+="\"$line\""
done <<< "$packages"

versions=$(cargo metadata --format-version 1 | jq --raw-output '.packages[] | select(.name | IN($items[])) | .version' --argjson items "[$items]")

unique=$(echo "$versions" | tr ' ' '\n' | sort -u | wc -l)

if [[ "$unique" != "1" ]]; then
    echo "At least one package has the wrong version. Versions:"
    cargo metadata --format-version 1 | jq --raw-output '.packages[] | select(.name | IN($items[])) | "\(.name): \(.version)"' --argjson items "[$items]"
    exit 1
fi

echo "$versions" | tr ' ' '\n' | sort -u
