#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$root/bin"
(
	cd "$root"
	go build -o "$root/bin/central-overrides" ./tools/central-overrides
)