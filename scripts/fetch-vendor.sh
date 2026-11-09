#!/usr/bin/env bash
# Downloads pdf.js into ui/vendor/ so PDF preview works without internet.
# The build embeds anything in ui/vendor automatically. Run once before `cargo build`.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="3.11.174"
DEST="ui/vendor/pdfjs"
mkdir -p "$DEST"
for f in pdf.min.js pdf.worker.min.js; do
  curl -fsSL "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/${VERSION}/${f}" -o "$DEST/$f"
done
echo "pdf.js ${VERSION} saved to $DEST"
