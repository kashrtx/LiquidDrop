#!/bin/bash
cd "$(dirname "$0")"
if [ -x ./liquiddrop ]; then ./liquiddrop "$@"
elif [ -x ./target/release/liquiddrop ]; then ./target/release/liquiddrop "$@"
else python3 liquiddrop.py "$@"; fi
read -p "Press Enter to close..."
