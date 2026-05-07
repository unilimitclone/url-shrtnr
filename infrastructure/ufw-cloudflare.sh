#!/bin/bash
# Restrict inbound 443 to Cloudflare IP ranges only.
# Run on VPS as root. Idempotent — safe to re-run from cron.
#
# CF publishes its IP ranges at:
#   https://www.cloudflare.com/ips-v4
#   https://www.cloudflare.com/ips-v6
#
# Without this allowlist, any attacker who discovers our origin IP could
# bypass CF (and bypass orange-cloud DDoS / WAF / rate limit).

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
	echo "must run as root" >&2
	exit 1
fi

echo "[ufw-cloudflare] resetting CF allow rules…"

# Drop existing CF rules (matches comment 'Cloudflare-vN'). UFW lists rules
# numbered, so we collect their indices and delete from highest to lowest to
# keep remaining indices stable as we go.
mapfile -t cf_rule_nums < <(ufw status numbered | awk -F'[][]' '/Cloudflare-v[46]/ { print $2 }' | sort -rn)
if (( ${#cf_rule_nums[@]} > 0 )); then
	for n in "${cf_rule_nums[@]}"; do
		[[ -z "$n" ]] && continue
		ufw --force delete "$n" >/dev/null
	done
fi

echo "[ufw-cloudflare] applying baseline rules…"
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow 22/tcp comment 'SSH' >/dev/null

echo "[ufw-cloudflare] fetching CF IP ranges…"
v4=$(curl -fsS https://www.cloudflare.com/ips-v4)
v6=$(curl -fsS https://www.cloudflare.com/ips-v6)

if [[ -z "$v4" || -z "$v6" ]]; then
	echo "[ufw-cloudflare] empty CF IP list — refusing to proceed" >&2
	exit 2
fi

echo "[ufw-cloudflare] adding 443 allow rules for CF…"
while IFS= read -r ip; do
	[[ -z "$ip" ]] && continue
	ufw allow proto tcp from "$ip" to any port 443 comment 'Cloudflare-v4' >/dev/null
done <<< "$v4"

while IFS= read -r ip; do
	[[ -z "$ip" ]] && continue
	ufw allow proto tcp from "$ip" to any port 443 comment 'Cloudflare-v6' >/dev/null
done <<< "$v6"

echo "[ufw-cloudflare] enabling UFW…"
yes | ufw enable >/dev/null
ufw reload >/dev/null

echo "[ufw-cloudflare] done. Rules:"
ufw status | head -50
