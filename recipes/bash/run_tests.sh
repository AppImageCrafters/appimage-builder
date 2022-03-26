#!/bin/bash
set -e
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

echo "Running tests"

for entry in "$SCRIPT_DIR/tests"/*; do
  echo "Running: $entry"
  $entry
done
