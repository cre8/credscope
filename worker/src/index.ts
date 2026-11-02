import { createProxy, type FetchProxy } from './proxy'

// The entry of the Cloudflare Worker, see worker/wrangler.jsonc

interface RateLimit {
  limit(options: { key: string }): Promise<{ success: boolean }>
}

interface Env {
  /** The origins of the pages, comma-separated */
  ALLOWED_ORIGINS: string
  /** The requests a client may make */
  RATE_LIMITER: RateLimit
}

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void
}

let proxy: FetchProxy | undefined

export default {
  fetch(request: Request, env: Env, context: ExecutionContext): Promise<Response> {
    proxy ??= createProxy({
      allowedOrigins: env.ALLOWED_ORIGINS.split(',').map((origin) => origin.trim()),
      cache: (caches as unknown as { default: Cache }).default,
      // Called on the global object, as a worker requires
      fetch: (url, init) => fetch(url, init),
      limit: async (key) => (await env.RATE_LIMITER.limit({ key })).success,
    })
    return proxy(request, (promise) => context.waitUntil(promise))
  },
}
