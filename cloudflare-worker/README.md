# spoo.me Custom Domain Dispatcher Worker

CF Worker that fronts CF SaaS Custom Hostname traffic and proxies it to
our fallback origin. Required because CF SaaS + fallback origin alone
doesn't dispatch arbitrary customer-hostname traffic on the Free plan —
a Worker route bound to the dispatch endpoint is what actually engages
SaaS routing.

## Why

Without this Worker, CF SaaS registrations succeed (cert issued, hostname
status active) but real traffic returns 520 with `sliver=none` because
CF has no Worker route catching the dispatched request.

With this Worker bound to `customers.spoo.me/*`:

```
customer browser
    ↓ DNS resolves customer hostname via CF SaaS
CF edge (TLS terminated with SaaS cert)
    ↓ dispatched per Custom Hostname's custom_origin_server = customers.spoo.me
Worker route catches customers.spoo.me/*
    ↓ this Worker fetches proxy-fallback.spoo.me with X-Forwarded-Host preserved
CF anycast → Caddy on Hetzner (zone-level Authenticated Origin Pulls)
    ↓ Caddy validates AOP client cert → reverse_proxy app:8000
spoo app
```

## One-time deploy

### 1. Install wrangler

```bash
npm i -g wrangler
```

### 2. Authenticate

Either interactively:

```bash
wrangler login
```

Or export an API token with `Account → Workers Scripts → Edit` and
`Zone → Workers Routes → Edit` for the spoo.me zone:

```bash
export CLOUDFLARE_API_TOKEN=<token>
export CLOUDFLARE_ACCOUNT_ID=<account-id>   # from CF dashboard
```

### 3. Deploy

```bash
./deploy.sh
```

This uploads `worker.js` and binds it to `customers.spoo.me/*` on the
spoo.me zone (per `wrangler.toml`).

### 4. Confirm route in CF dashboard

`spoo.me zone → Workers Routes` — verify:
- Pattern: `customers.spoo.me/*`
- Worker: `spoo-custom-domains-dispatcher`

## Verification

Once a customer Custom Hostname is registered (via the spoo app's API)
and DNS propagates:

```bash
curl -sI https://<customer-hostname>/
```

Expect a non-520 response (whatever the spoo.me app returns for the
hostname's request). Trace:

```bash
curl -s https://<customer-hostname>/cdn-cgi/trace | grep sliver
```

`sliver=` should now show a value other than `none` (typically `010-tier1`
or similar) — confirms the Worker engaged.

## Updating

Edit `worker.js`, re-run `./deploy.sh`. CF rolls the new code to the
edge in seconds.

## Removal

```bash
wrangler delete
```

Then remove the route from the CF dashboard.
