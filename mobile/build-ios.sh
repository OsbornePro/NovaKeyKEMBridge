#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

gomobile bind -target=ios -o build/NovaKeyKEMBridge.xcframework ./novakeykem
echo "Built: build/NovaKeyKEMBridge.xcframework"

