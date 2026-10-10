#!/bin/bash
# Build worker-bundle.js for Cloudflare dashboard deploy.
# Concatenates src/*.js into one module file; strips intra-bundle
# import lines (they'd re-declare already-defined identifiers).
# Lesson 2026-10-10: a naive cat of the sources ships
#   `import { sendPush } from './webpush.js'`
# alongside `export function sendPush`, which is a SyntaxError
# ("Identifier 'sendPush' has already been declared") in the dashboard.
set -e
cd "$(dirname "$0")"
{
  echo "/* Bundled single-file worker for dashboard deploy."
  echo "   Sources: src/webpush.js + src/prayer.js + src/index.js"
  echo "   Built: $(date +%F) */"
  cat src/webpush.js src/prayer.js src/index.js
} | grep -v "^import .* from '\./" > worker-bundle.js
cp worker-bundle.js /tmp/wb-check.mjs
node --check /tmp/wb-check.mjs && echo "worker-bundle.js OK"
