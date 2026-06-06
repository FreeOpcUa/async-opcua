#!/usr/bin/env bash

# Get the list of publish targets, for use in other scripts.
ITEMS=(
    'async-opcua-client'
    'async-opcua-core'
    'async-opcua-core-namespace'
    'async-opcua-crypto'
    'async-opcua-macros'
    'async-opcua-nodes'
    'async-opcua-server'
    'async-opcua-types'
    'async-opcua-xml'
    'async-opcua-codegen'
)

for item in "${ITEMS[@]}"; do
    echo "$item"
done
