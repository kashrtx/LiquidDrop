#!/bin/bash
cd "$(dirname "$0")"
python liquiddrop.py "$@"
read -p "Press Enter to close..."
