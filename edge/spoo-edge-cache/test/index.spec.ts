import {
  createExecutionContext,
  env,
  fetchMock,
  waitOnExecutionContext,
} from "cloudflare:test";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

import fixtures from "../contract/fixtures.json";
import worker, { lookupKey } from "../src/index";

beforeAll(() => {
  fetchMock.activate();
  fetchMock.disableNetConnect();
});
afterEach(() => fetchMock.assertNoPendingInterceptors());

/** Stub the next passthrough to origin and tag it so tests can assert
 * "this request reached origin" unambiguously. */
function expectOriginFetch(
  host = "https://spoo.me",
  path: string | RegExp = /.*/,
  method = "GET",
) {
  fetchMock.get(host).intercept({ path, method }).reply(200, "origin-served");
}

// The handler is typed for edge-ingress requests (IncomingRequestCfProperties);
// the cast below is the pattern CF's own worker templates use in tests.
type IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

async function dispatch(request: Request): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await worker.fetch(request as IncomingRequest, env, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

describe("contract fixtures", () => {
  for (const fixture of fixtures.entries) {
    it(`serves: ${fixture.name}`, async () => {
      await env.EDGE_CACHE.put(fixture.key, JSON.stringify(fixture.value));
      const code = fixture.key.split(":").slice(2).join(":");
      const response = await dispatch(
        new Request(`https://spoo.me/${encodeURIComponent(code)}`),
      );

      expect(response.status).toBe(fixture.expect.status);
      expect(response.headers.get("Location")).toBe(fixture.expect.location);
      expect(response.headers.get("X-Spoo-Edge")).toBe("hit");
      expect(response.headers.get("X-Robots-Tag")).toContain("noindex");
    });
  }

  for (const fixture of fixtures.malformed) {
    it(`passes through: ${fixture.name}`, async () => {
      await env.EDGE_CACHE.put(fixture.key, fixture.raw);
      const code = fixture.key.split(":").slice(2).join(":");
      expectOriginFetch();
      const response = await dispatch(
        new Request(`https://spoo.me/${encodeURIComponent(code)}`),
      );

      expect(await response.text()).toBe("origin-served");
    });
  }
});

describe("serving behavior", () => {
  it("KV miss passes through to origin", async () => {
    expectOriginFetch("https://spoo.me", "/nothere");
    const response = await dispatch(new Request("https://spoo.me/nothere"));
    expect(await response.text()).toBe("origin-served");
    expect(response.headers.get("X-Spoo-Edge")).toBeNull();
  });

  it("HEAD is served from cache like GET", async () => {
    await env.EDGE_CACHE.put(
      "cache:spoo.me:headcode",
      JSON.stringify({ type: "redirect", url: "https://example.com", status: 302 }),
    );
    const response = await dispatch(
      new Request("https://spoo.me/headcode", { method: "HEAD" }),
    );
    expect(response.status).toBe(302);
  });

  it("www host is normalized to the canonical key", async () => {
    await env.EDGE_CACHE.put(
      "cache:spoo.me:wwwcode",
      JSON.stringify({ type: "redirect", url: "https://example.com", status: 302 }),
    );
    const response = await dispatch(new Request("https://www.spoo.me/wwwcode"));
    expect(response.status).toBe(302);
  });

  it("?password= bypasses the cache even when an entry exists", async () => {
    await env.EDGE_CACHE.put(
      "cache:spoo.me:pwcode",
      JSON.stringify({ type: "redirect", url: "https://example.com", status: 302 }),
    );
    expectOriginFetch();
    const response = await dispatch(
      new Request("https://spoo.me/pwcode?password=hunter2"),
    );
    expect(await response.text()).toBe("origin-served");
  });

  it("POST passes through untouched", async () => {
    expectOriginFetch("https://spoo.me", "/", "POST");
    const response = await dispatch(
      new Request("https://spoo.me/", { method: "POST", body: "url=x" }),
    );
    expect(await response.text()).toBe("origin-served");
  });

  it("a throwing KV binding fails open to origin", async () => {
    expectOriginFetch("https://spoo.me", "/failopen");
    const brokenEnv = {
      ...env,
      EDGE_CACHE: {
        get: () => {
          throw new Error("kv exploded");
        },
      },
    } as unknown as typeof env;
    const ctx = createExecutionContext();
    const response = await worker.fetch(
      new Request("https://spoo.me/failopen") as IncomingRequest,
      brokenEnv,
      ctx,
    );
    await waitOnExecutionContext(ctx);
    expect(await response.text()).toBe("origin-served");
  });
});

describe("lookupKey routing", () => {
  const cases: Array<[string, string | null]> = [
    ["https://spoo.me/abc1234", "cache:spoo.me:abc1234"],
    ["https://www.spoo.me/abc1234", "cache:spoo.me:abc1234"],
    ["https://spoo.me/%F0%9F%9A%80", "cache:spoo.me:🚀"],
    ["https://spoo.me/", null],
    ["https://spoo.me/api/v1/shorten", null],
    ["https://spoo.me/dashboard/urls", null],
    ["https://spoo.me/auth/login", null],
    ["https://spoo.me/oauth/google", null],
    ["https://spoo.me/static/app.css", null],
    ["https://spoo.me/stats/abc1234", null],
    ["https://spoo.me/favicon.ico", null],
    ["https://spoo.me/a/b", null],
    ["https://spoo.me/abc?password=x", null],
  ];

  for (const [url, expected] of cases) {
    it(`${url} → ${expected}`, () => {
      expect(lookupKey(new Request(url))).toBe(expected);
    });
  }

  it("non-GET/HEAD methods never produce a key", () => {
    expect(
      lookupKey(new Request("https://spoo.me/abc", { method: "POST" })),
    ).toBeNull();
  });
});
