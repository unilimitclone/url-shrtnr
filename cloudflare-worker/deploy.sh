#!/bin/bash
# One-shot deploy for the spoo.me custom-domains dispatcher Worker.
# Requires: wrangler CLI, CLOUDFLARE_API_TOKEN env var (or `wrangler login`).
#
# The deploy is idempotent — re-running upgrades the existing Worker in place.

set -euo pipefail

if ! command -v wrangler >/dev/null 2>&1; then
  echo "wrangler not found. install: npm i -g wrangler" >&2
  exit 1
fi

cd "$(dirname "$0")"

echo "deploying spoo-custom-domains-dispatcher..."
wrangler deploy

echo
echo "verify route bound:"
echo "  CF dashboard → spoo.me zone → Workers Routes → confirm customers.spoo.me/* → spoo-custom-domains-dispatcher"
echo
echo "smoke test once a Custom Hostname is registered:"
echo "  curl -sI https://<customer-hostname>/"
echo "  expect HTTP/2 200 (or whatever the spoo.me app returns)"
