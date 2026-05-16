# spoo.me Custom Domain Dispatcher Worker

CF Worker that catches CF SaaS Custom Hostname traffic and proxies it
to our Caddy origin. Required because CF SaaS + fallback origin alone
doesn't dispatch arbitrary customer-hostname traffic on the Free plan.

## Flow

```
customer browser → <customer-hostname>
  ↓ CF SaaS terminates TLS (per-hostname cert, auto-renewed)
  ↓ dispatches per Custom Hostname's custom_origin_server = customers.spoo.me

[at spoo.me zone]
  ↓ Worker route customers.spoo.me/* catches
  ↓ this Worker runs
  ↓ fetch(http://<hetzner-rDNS>/) + X-Forwarded-Host = customer hostname

[off CF — Hetzner rDNS sidesteps CF Worker loop detection]
  ↓ UFW lets CF IPs hit port 80
  ↓ Caddy :80 rewrites Host = X-Forwarded-Host
  ↓ reverse_proxy app:8000 with Host: customer hostname

spoo app
```

## Why HTTP, not HTTPS, for the Worker → origin hop

Two CF constraints stack:

1. **CF Workers can't attach Authenticated Origin Pulls (AOP) client
   cert** on outbound fetch. Caddy's `:443` mTLS check would fail with
   `tls: certificate required`. (CF SaaS edge auto-attaches AOP when
   dispatching directly to a fallback origin; Workers don't.)
2. **CF Worker loop detection** triggers on any fetch to a hostname on
   the same CF zone, even DNS-only records. Fetching `customers.spoo.me`
   or any `*.spoo.me` proxied hostname returns 520 with `sliver=none`.

Workaround: fetch a non-CF-managed hostname (Hetzner reverse DNS
`static.<rev-ip>.clients.your-server.de`) over plain HTTP. UFW restricts
port 80 to CF IP ranges, so the plaintext hop only exists between CF
datacenter and our origin. Caddy `header_up Host` rewrites the upstream
Host header to the customer's hostname (CF Workers can't override Host
themselves) so the app builds asset URLs against the right hostname.

## One-time deploy

### Install wrangler

```bash
npm i -g wrangler
```

### Authenticate

Interactive:

```bash
wrangler login
```

Or API token with `Account → Workers Scripts → Edit` and
`Zone → Workers Routes → Edit` (spoo.me zone):

```bash
export CLOUDFLARE_API_TOKEN=<token>
export CLOUDFLARE_ACCOUNT_ID=<account-id>
```

### Deploy

```bash
./deploy.sh
```

Uploads `worker.js`, binds it to `customers.spoo.me/*` on spoo.me zone
(per `wrangler.toml`).

### Confirm

`spoo.me zone → Workers Routes` — verify pattern + worker name.

### Shared secret for Worker → origin auth

Port 80 is reachable from any CF IP. The shared secret ensures only
*our* Worker can use the dispatcher path: Worker sends
`X-Worker-Auth: <secret>`, Caddy 403s without it.

Generate once:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Put the same value in two places:

- **Hetzner box** `/opt/spoo/.env.production`:
  `WORKER_AUTH_SECRET=<the-value>` (Caddy reads via `{env.WORKER_AUTH_SECRET}`)
- **CF Worker secret** (encrypted, scoped to this Worker):
  ```bash
  cd cloudflare-worker
  wrangler secret put WORKER_AUTH_SECRET
  # paste the value at the prompt
  ```

Rotate by repeating with a new value, deploying Caddy + Worker
together. Brief mismatch window during rotation → 403 responses.

### Other prerequisites on origin (one-time, separate from this dir)

- UFW: port 80 allowed from CF IPs (`infrastructure/ufw-cloudflare.sh`
  handles both 443 + 80).
- Caddyfile: `:80` listener with shared-secret matcher +
  `header_up Host {http.request.header.X-Forwarded-Host}`.
- DNS in spoo.me zone: `customers A 192.0.2.0 Proxied` (sentinel — the
  Worker route binds to the hostname; the A record is required by CF
  for the route to engage but is never actually contacted).

## Verification

After a Custom Hostname is registered + DNS propagates:

```bash
curl -sI https://<customer-hostname>/
```

Expect a 2xx/3xx response. Trace:

```bash
curl -s https://<customer-hostname>/cdn-cgi/trace | grep sliver
```

`sliver` should be `010-tier1` or similar — confirms Worker engaged.
Stream live Worker logs:

```bash
wrangler tail spoo-custom-domains-dispatcher --format pretty
```

## Updating

Edit `worker.js`, rerun `./deploy.sh`. Live in seconds.

## Removal

```bash
wrangler delete
```

Then remove the route from CF dashboard.
