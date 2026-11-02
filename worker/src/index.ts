import { createProxy, type FetchProxy } from './proxy'

// The entry of the Cloudflare Worker, see worker/wrangler.jsonc

interface Env {
  /** The origins of the pages, comma-separated */
  ALLOWED_ORIGINS: string
}

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void
}

let proxy: FetchProxy | undefined

export default {
  fetch(request: Request, env: Env, context: ExecutionContext): Promise<Response> {
    proxy ??= createProxy({
      allowedOrigins: env.ALLOWED_ORIGINS.split(',').map((origin) => origin.trim()),
      // The cache of the data center, which the Cache API of a worker has besides the named ones
      cache: (caches as unknown as { default: Cache }).default,
      // The fetch of a worker throws when called on another object than the global one
      fetch: (url, init) => fetch(url, init),
    })
    return proxy(request, (promise) => context.waitUntil(promise))
  },
}
