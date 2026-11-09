#!/bin/bash
cd "$(dirname "$0")"
python3 liquiddrop.py "$@"
read -p "Press Enter to close..."
