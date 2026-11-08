#!/bin/bash
cd "$(dirname "$0")"
if [ -x ./liquiddrop ]; then exec ./liquiddrop "$@"; fi
if [ -x ./target/release/liquiddrop ]; then exec ./target/release/liquiddrop "$@"; fi
exec python3 liquiddrop.py "$@"
