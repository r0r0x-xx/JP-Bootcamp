#!/usr/bin/env bash
# Thin wrapper so nobody has to remember the module path.
cd "$(dirname "$0")"
exec python3 -m pwnsat_ids.cli "$@"
