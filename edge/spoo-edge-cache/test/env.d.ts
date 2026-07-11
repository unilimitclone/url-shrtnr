import type {} from "@cloudflare/vitest-pool-workers";

declare module "cloudflare:test" {
  // The env the pool injects mirrors the wrangler.jsonc bindings.
  interface ProvidedEnv extends Env {}
}
