// spoo.me Custom Domain dispatcher (Cloudflare Worker).
//
// Why this exists: CF SaaS Custom Hostnames + fallback origin alone don't
// dispatch arbitrary customer-hostname traffic to a single backend on the
// Free plan. A Worker route bound to the dispatch endpoint is the actual
// routing mechanism — it catches Custom Hostname traffic and proxies it to
// our origin while preserving the customer's original Host header.
//
// Flow:
//   1. Customer browser → CF anycast (resolves customer hostname)
//   2. CF SaaS terminates TLS with the per-hostname SaaS cert
//   3. CF SaaS dispatches per the hostname's custom_origin_server setting
//      (set to ORIGIN_HOST below — usually customers.spoo.me)
//   4. Worker route customers.spoo.me/* catches the dispatched request
//   5. This Worker fetches FALLBACK_ORIGIN with X-Forwarded-Host preserving
//      the customer hostname so the app can scope alias lookups
//   6. CF→origin TLS uses zone-level Authenticated Origin Pulls so Caddy
//      validates the request actually came from CF
//
// Single-backend setup: no per-tenant routing, no metadata lookup. If we
// ever need per-tenant dispatch later, read request.cf.hostMetadata.appName
// and route accordingly — CF SaaS exposes custom_metadata via the binding.

const FALLBACK_ORIGIN = "proxy-fallback.spoo.me";

// Hop-by-hop headers per RFC 7230 §6.1 — must not be forwarded as-is.
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function buildOutboundHeaders(request, customerHost) {
  const out = new Headers();
  for (const [name, value] of request.headers.entries()) {
    if (HOP_BY_HOP.has(name.toLowerCase())) continue;
    if (name.toLowerCase() === "host") continue; // set by fetch from URL
    out.set(name, value);
  }
  // Customer hostname → app's tenant resolver middleware (PR4) reads this
  // to scope alias lookups by tenant.
  out.set("X-Forwarded-Host", customerHost);
  return out;
}

export default {
  async fetch(request) {
    const originalUrl = new URL(request.url);
    const customerHost = request.headers.get("host") || originalUrl.hostname;

    const upstream = new URL(originalUrl);
    upstream.hostname = FALLBACK_ORIGIN;

    const init = {
      method: request.method,
      headers: buildOutboundHeaders(request, customerHost),
      redirect: "manual",
    };
    if (request.method !== "GET" && request.method !== "HEAD") {
      init.body = request.body;
    }

    try {
      const response = await fetch(upstream.toString(), init);
      return response;
    } catch (err) {
      return new Response(`upstream fetch failed: ${err.message}`, {
        status: 502,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }
  },
};
