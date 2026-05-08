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
#
# Order matters: fetch CF ranges and validate BEFORE mutating UFW. A failed
# fetch mid-run could otherwise leave the host with default-deny and no
# allow rules — locking 443 entirely.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
	echo "must run as root" >&2
	exit 1
fi

# ── Step 1: fetch CF IP ranges (read-only, safe to fail) ───────────────
echo "[ufw-cloudflare] fetching CF IP ranges…"
v4=$(curl -fsS --connect-timeout 5 --max-time 20 https://www.cloudflare.com/ips-v4)
v6=$(curl -fsS --connect-timeout 5 --max-time 20 https://www.cloudflare.com/ips-v6)

if [[ -z "$v4" || -z "$v6" ]]; then
	echo "[ufw-cloudflare] empty CF IP list — refusing to proceed (UFW unchanged)" >&2
	exit 2
fi

# ── Step 2: drop ALL prior 443 allow rules ─────────────────────────────
# Catches both our own Cloudflare-v[46] tagged rules AND any pre-existing
# broad rules like `ufw allow 443/tcp` that would let traffic bypass CF.
# Anything other than CF allow on 443 is a regression we re-establish below.
echo "[ufw-cloudflare] dropping existing 443 allow rules…"
mapfile -t rule_nums < <(
	ufw status numbered \
		| awk -F'[][]' '/^\[/ {
			# print rule number for any ALLOW IN line that mentions 443
			if ($0 ~ /443.*ALLOW IN/) print $2
		}' \
		| sort -rn
)
if (( ${#rule_nums[@]} > 0 )); then
	for n in "${rule_nums[@]}"; do
		[[ -z "$n" ]] && continue
		ufw --force delete "$n" >/dev/null
	done
fi

# ── Step 3: baseline policy ────────────────────────────────────────────
echo "[ufw-cloudflare] applying baseline rules…"
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow 22/tcp comment 'SSH' >/dev/null

# ── Step 4: add CF allow rules ─────────────────────────────────────────
# TCP for HTTP/2 + HTTP/1.1, UDP for HTTP/3 (QUIC). Compose maps both.
echo "[ufw-cloudflare] adding 443 allow rules for CF (TCP + UDP)…"
while IFS= read -r ip; do
	[[ -z "$ip" ]] && continue
	ufw allow proto tcp from "$ip" to any port 443 comment 'Cloudflare-v4' >/dev/null
	ufw allow proto udp from "$ip" to any port 443 comment 'Cloudflare-v4' >/dev/null
done <<< "$v4"

while IFS= read -r ip; do
	[[ -z "$ip" ]] && continue
	ufw allow proto tcp from "$ip" to any port 443 comment 'Cloudflare-v6' >/dev/null
	ufw allow proto udp from "$ip" to any port 443 comment 'Cloudflare-v6' >/dev/null
done <<< "$v6"

# ── Step 5: enable + reload ────────────────────────────────────────────
echo "[ufw-cloudflare] enabling UFW…"
ufw --force enable >/dev/null
ufw reload >/dev/null

echo "[ufw-cloudflare] done. Rules:"
ufw status | head -60
