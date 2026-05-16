// spoo.me Custom Domain dispatcher. See README.md for the routing
// chain + why the fetch target is the Hetzner rDNS over plain HTTP.

const FALLBACK_ORIGIN = "http://static.168.161.156.178.clients.your-server.de";

// RFC 7230 §6.1 — never forward as-is.
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

function buildOutboundHeaders(request, customerHost, authSecret) {
  const out = new Headers();
  // RFC 7230 §6.1: headers named in Connection are also hop-by-hop.
  const dynamicHops = new Set(
    (request.headers.get("connection") || "")
      .split(",")
      .map((v) => v.trim().toLowerCase())
      .filter(Boolean),
  );
  for (const [name, value] of request.headers.entries()) {
    const lower = name.toLowerCase();
    if (HOP_BY_HOP.has(lower)) continue;
    if (dynamicHops.has(lower)) continue;
    if (lower === "host") continue;
    out.set(name, value);
  }
  // Caddy rewrites Host from this header (Workers can't override Host).
  out.set("X-Forwarded-Host", customerHost);
  if (authSecret) {
    out.set("X-Worker-Auth", authSecret);
  }
  return out;
}

export default {
  async fetch(request, env) {
    const originalUrl = new URL(request.url);
    const customerHost = request.headers.get("host") || originalUrl.hostname;

    const upstream = new URL(FALLBACK_ORIGIN);
    upstream.pathname = originalUrl.pathname;
    upstream.search = originalUrl.search;

    const init = {
      method: request.method,
      headers: buildOutboundHeaders(request, customerHost, env.WORKER_AUTH_SECRET),
      redirect: "manual",
    };
    if (request.method !== "GET" && request.method !== "HEAD") {
      init.body = request.body;
    }

    try {
      const response = await fetch(upstream.toString(), init);
      console.log(
        `customer=${customerHost} status=${response.status} cf-ray=${response.headers.get("cf-ray") || "n/a"}`,
      );
      return response;
    } catch (err) {
      // Full error stays in Worker logs; client sees a generic message.
      console.error("upstream fetch failed", customerHost, err);
      return new Response("upstream fetch failed", {
        status: 502,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }
  },
};
