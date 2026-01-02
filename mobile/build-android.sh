#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
export PATH="$JAVA_HOME/bin:$PATH"

gomobile bind -target=android -androidapi 21 -o build/NovaKeyKEMBridge.aar ./novakeykem
echo "Built: build/NovaKeyKEMBridge.aar"

