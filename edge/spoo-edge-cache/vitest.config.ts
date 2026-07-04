import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

// Tests run inside actual workerd with the KV binding simulated from
// wrangler.jsonc — the closest thing to production short of a PoP.
export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        wrangler: { configPath: "./wrangler.jsonc" },
      },
    },
  },
});
