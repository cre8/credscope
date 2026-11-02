// Fetches documents for the pages when their server does not allow other websites to, as the servers
// of most trusted lists, status lists and metadata do not send CORS headers. It answers the pages only,
// fetches from public hosts only, and returns what it fetches as an inert download, so other websites
// cannot use it as a CORS proxy and it cannot serve a page under its domain. The pages verify the
// signatures of what it returns, as they do for what they fetch themselves.

/** The longest a document is cached, in seconds */
export const CACHE_SECONDS = 3600
/** The largest document fetched, in bytes; the largest national trusted list is about 5 MB */
export const MAX_BYTES = 20 * 1024 * 1024
/** How long to wait for a server, in milliseconds */
const TIMEOUT_MS = 20_000
/** How many redirects to follow */
export const MAX_REDIRECTS = 5

const USER_AGENT = 'Credscope fetch proxy (+https://credscope.eudi-wallet.dev/)'
const NAME = 'credscope'

// Pages served by `pnpm dev` and `pnpm preview`
const LOCAL_ORIGIN = /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/

// Domains that name no public host, see RFC 6761, 6762, 7686 and 8375
const PRIVATE_DOMAINS = ['localhost', 'local', 'internal', 'home.arpa', 'lan', 'test', 'invalid', 'example', 'onion']

// What makes the responses inert where they are opened as a page, so the proxy cannot serve one
const SAFE_HEADERS = {
  'content-disposition': 'attachment',
  'x-content-type-options': 'nosniff',
  'content-security-policy': "default-src 'none'; sandbox",
  'referrer-policy': 'no-referrer',
  'x-robots-tag': 'noindex',
}

export interface ProxyOptions {
  /** The origins of the pages; those on localhost are allowed as well */
  allowedOrigins: string[]
  cache: Cache
  fetch: (url: string, init: RequestInit) => Promise<Response>
  /** Whether a client, by its IP address, may make another request */
  limit: (key: string) => Promise<boolean>
  now?: () => number
}

/** Answers a request; `waitUntil` keeps the worker alive for what is done after the response */
export type FetchProxy = (request: Request, waitUntil: (promise: Promise<unknown>) => void) => Promise<Response>

/** A request the proxy does not fulfil, with the error type of RFC 9209 and a message for the page */
class ProxyError extends Error {
  constructor(
    readonly status: number,
    readonly type: string,
    message: string
  ) {
    super(message)
  }
}

/** The URL without its fragment, or undefined if it is no http(s) URL on the default port of a public host */
export function publicUrl(text: string): string | undefined {
  let url: URL
  try {
    url = new URL(text.trim())
  } catch {
    return undefined
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return undefined
  if (url.port || url.username || url.password) return undefined
  // An IP address is no host name, and IPv4 addresses in other forms are written as one by now
  const host = url.hostname.replace(/\.$/, '')
  if (host.startsWith('[') || /^[\d.]+$/.test(host) || !host.includes('.')) return undefined
  if (PRIVATE_DOMAINS.some((domain) => host === domain || host.endsWith(`.${domain}`))) return undefined
  url.hash = ''
  return url.href
}

/**
 * How long a response may be cached, in seconds, at most CACHE_SECONDS: as its Cache-Control says or,
 * without a lifetime there, a tenth of the time since it was last modified (RFC 9111, 4.2.2)
 */
export function freshness(headers: Headers, now: number): number {
  const directives = (headers.get('cache-control') ?? '').toLowerCase()
  if (/(^|[\s,])(no-store|no-cache|private)($|[\s,=])/.test(directives)) return 0
  const lifetime = /(?:^|[\s,])s-maxage=(\d+)/.exec(directives) ?? /(?:^|[\s,])max-age=(\d+)/.exec(directives)
  if (lifetime) return Math.min(Number(lifetime[1]), CACHE_SECONDS)
  const modified = Date.parse(headers.get('last-modified') ?? '')
  if (Number.isNaN(modified)) return 0
  return Math.max(0, Math.min(Math.floor((now - modified) / 10_000), CACHE_SECONDS))
}

/** The body, or a ProxyError if it is larger than `max` bytes */
async function readAtMost(response: Response, max: number): Promise<Uint8Array<ArrayBuffer>> {
  const tooLarge = () =>
    new ProxyError(413, 'http_response_body_size', `The document is larger than ${max / 1024 / 1024} MB.`)
  if (Number(response.headers.get('content-length')) > max) {
    await response.body?.cancel()
    throw tooLarge()
  }
  const reader = response.body?.getReader()
  if (!reader) return new Uint8Array()
  const chunks: Uint8Array[] = []
  let size = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    size += value.byteLength
    if (size > max) {
      await reader.cancel()
      throw tooLarge()
    }
    chunks.push(value)
  }
  const bytes = new Uint8Array(size)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return bytes
}

export function createProxy({ allowedOrigins, cache, fetch, limit, now = Date.now }: ProxyOptions): FetchProxy {
  const isAllowedOrigin = (origin: string) => allowedOrigins.includes(origin) || LOCAL_ORIGIN.test(origin)

  /** The response of the server, following redirects as long as they stay on public hosts */
  async function fetchFollowing(url: string, signal: AbortSignal): Promise<Response> {
    for (let redirects = 0; ; redirects++) {
      const response = await fetch(url, {
        headers: { accept: '*/*', 'user-agent': USER_AGENT },
        redirect: 'manual',
        signal,
      })
      const location = response.headers.get('location')
      if (response.status < 300 || response.status >= 400 || !location) return response
      await response.body?.cancel()
      const host = new URL(url).host
      if (redirects === MAX_REDIRECTS) {
        throw new ProxyError(502, 'http_request_denied', `${host} redirects more than ${MAX_REDIRECTS} times.`)
      }
      const next = publicUrl(new URL(location, url).href)
      if (!next) {
        throw new ProxyError(403, 'http_request_denied', `${host} redirects to ${location}, which is no public host.`)
      }
      url = next
    }
  }

  /** The document at `url`, from the cache or else from its server; undefined bytes for an error status */
  async function fetchDocument(
    url: string,
    base: string,
    waitUntil: (promise: Promise<unknown>) => void
  ): Promise<{ status: number; bytes?: Uint8Array<ArrayBuffer> }> {
    // Cached under the URL of the proxy, as the cache of a worker is for the hosts of its zone
    const key = new Request(`${base}?${new URLSearchParams({ url })}`)
    const cached = await cache.match(key)
    if (cached) return { status: 200, bytes: new Uint8Array(await cached.arrayBuffer()) }

    const host = new URL(url).host
    let response: Response
    let bytes: Uint8Array<ArrayBuffer>
    try {
      response = await fetchFollowing(url, AbortSignal.timeout(TIMEOUT_MS))
      if (!response.ok) {
        await response.body?.cancel()
        return { status: response.status }
      }
      bytes = await readAtMost(response, MAX_BYTES)
    } catch (error) {
      if (error instanceof ProxyError) throw error
      if (error instanceof Error && error.name === 'TimeoutError') {
        throw new ProxyError(
          504,
          'http_response_timeout',
          `${host} did not answer within ${TIMEOUT_MS / 1000} seconds.`
        )
      }
      throw new ProxyError(502, 'destination_unavailable', `${host} cannot be reached from the Credscope proxy.`)
    }
    const seconds = freshness(response.headers, now())
    if (seconds > 0) {
      waitUntil(cache.put(key, new Response(bytes, { headers: { 'cache-control': `max-age=${seconds}` } })))
    }
    return { status: 200, bytes }
  }

  return async (request, waitUntil) => {
    const origin = request.headers.get('origin')
    const cors: Record<string, string> = { vary: 'Origin', 'access-control-expose-headers': 'Proxy-Status' }
    if (origin && isAllowedOrigin(origin)) cors['access-control-allow-origin'] = origin

    const fail = ({ status, type, message }: ProxyError) =>
      new Response(message, {
        status,
        headers: {
          ...SAFE_HEADERS,
          ...cors,
          'content-type': 'text/plain; charset=utf-8',
          'cache-control': 'no-store',
          'proxy-status': `${NAME}; error=${type}`,
        },
      })

    // Only a fetch() of the pages: other websites could use it as a CORS proxy, and a link to it, which
    // a browser opens without an Origin, could pass off a document as one of its domain
    if (!origin || !isAllowedOrigin(origin) || request.headers.get('sec-fetch-mode') !== 'cors') {
      return fail(new ProxyError(403, 'http_request_denied', 'The Credscope proxy only fetches for its pages.'))
    }
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      const response = fail(new ProxyError(405, 'http_request_denied', 'Only GET and HEAD are allowed.'))
      response.headers.set('allow', 'GET, HEAD')
      return response
    }
    const requestUrl = new URL(request.url)
    if (requestUrl.pathname !== '/') {
      return fail(new ProxyError(404, 'http_request_denied', 'Fetch a document with /?url=<URL of the document>.'))
    }
    const url = publicUrl(requestUrl.searchParams.get('url') ?? '')
    if (!url) {
      return fail(
        new ProxyError(
          400,
          'http_request_error',
          'The Credscope proxy only fetches http(s) URLs on the default port of a public host.'
        )
      )
    }
    if (!(await limit(request.headers.get('cf-connecting-ip') ?? ''))) {
      const response = fail(
        new ProxyError(429, 'http_request_denied', 'Too many requests to the Credscope proxy, try again in a minute.')
      )
      response.headers.set('retry-after', '60')
      return response
    }

    try {
      const { status, bytes } = await fetchDocument(url, `${requestUrl.origin}/`, waitUntil)
      const headers = { ...SAFE_HEADERS, ...cors, 'cache-control': 'no-store' }
      if (!bytes) {
        return new Response(null, {
          status,
          headers: { ...headers, 'proxy-status': `${NAME}; received-status=${status}` },
        })
      }
      return new Response(request.method === 'HEAD' ? null : bytes, {
        headers: { ...headers, 'content-type': 'application/octet-stream', 'proxy-status': NAME },
      })
    } catch (error) {
      if (error instanceof ProxyError) return fail(error)
      throw error
    }
  }
}
