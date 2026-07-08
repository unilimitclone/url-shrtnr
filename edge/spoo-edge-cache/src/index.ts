/**
 * spoo-edge-cache — pure-reader edge cache for hot short URLs.
 *
 * The Worker makes NO decisions: origin promotes eligible hot URLs into
 * KV (services/edge_cache.py) and this Worker serves
 * whatever it finds there. Miss, excluded path, unknown entry type, or
 * any internal error → passthrough to origin, which is exactly today's
 * request path. Entries self-expire via KV TTL (invalidation v1).
 *
 * Contract (key format + entry JSON) is pinned by ../contract/ and
 * tested from both sides — change only in lockstep.
 */

interface EdgeCacheEntry {
  type: string;
  url: string;
  status: number;
}

/** Path prefixes that are never short codes — skip KV entirely. */
const EXCLUDED_PREFIXES = [
  "/api/",
  "/dashboard/",
  "/auth/",
  "/oauth/",
  "/static/",
  "/stats/",
];

/**
 * KV key for this request, or null when the request can never be a
 * cached short-code redirect (wrong method, excluded path, password
 * attempt, nested path, file-ish path).
 */
export function lookupKey(request: Request): string | null {
  if (request.method !== "GET" && request.method !== "HEAD") return null;

  const url = new URL(request.url);
  // Password attempts must always reach origin for verification.
  if (url.searchParams.has("password")) return null;

  const path = url.pathname;
  if (path === "/" || path.includes(".")) return null;
  if (EXCLUDED_PREFIXES.some((prefix) => path.startsWith(prefix))) return null;

  const code = path.slice(1);
  if (code.length === 0 || code.includes("/")) return null;

  // Promotion writes keys with the canonical host: lowercase, no www.
  const host = url.hostname.toLowerCase().replace(/^www\./, "");
  // Emoji codes arrive percent-encoded; keys store raw characters.
  return `cache:${host}:${decodeURIComponent(code)}`;
}

export default {
  async fetch(request, env, ctx): Promise<Response> {
    try {
      const key = lookupKey(request);
      if (key === null) return passthrough(request, env);

      const entry = await env.EDGE_CACHE.get<EdgeCacheEntry>(key, "json");
      if (
        entry === null ||
        entry.type !== "redirect" ||
        typeof entry.url !== "string"
      ) {
        // Miss, or an entry type this Worker version doesn't know —
        // origin always knows how to answer.
        return passthrough(request, env);
      }

      console.log(
        JSON.stringify({
          event: "edge_hit",
          key,
          colo: request.cf?.colo,
          // Recon for meta-tags preview serving: learn the real runtime
          // verifiedBotCategory strings on this zone before enforcing them
          // (docs say "Page Preview"; one report says "Preview"; Slackbot
          // is categorized "Webhooks"). Field is absent from workers-types.
          botCategory: (request.cf as { verifiedBotCategory?: string } | undefined)
            ?.verifiedBotCategory,
          ua: request.headers.get("user-agent") ?? "",
        }),
      );
      return new Response(null, {
        status: entry.status === 301 ? 301 : 302,
        headers: {
          Location: entry.url,
          "X-Robots-Tag": "noindex, nofollow, noarchive",
          "X-Spoo-Edge": "hit",
        },
      });
    } catch (err) {
      // Fail-open: worst case is exactly today's request path. Explicit
      // catch (not passThroughOnException) so the error is visible.
      console.error(
        JSON.stringify({ event: "edge_cache_error", error: String(err) }),
      );
      return passthrough(request, env);
    }
  },
} satisfies ExportedHandler<Env>;

/**
 * Continue to origin. ORIGIN_OVERRIDE exists only in local dev
 * (.dev.vars) so `wrangler dev` can target a local compose app;
 * deployed environments never define it and take the plain
 * fetch(request) path through CF's normal proxy chain.
 */
function passthrough(request: Request, env: Env): Promise<Response> {
  if (env.ORIGIN_OVERRIDE) {
    const url = new URL(request.url);
    const origin = new URL(env.ORIGIN_OVERRIDE);
    url.protocol = origin.protocol;
    url.host = origin.host;
    return fetch(new Request(url, request));
  }
  return fetch(request);
}
