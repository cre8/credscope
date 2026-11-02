// Fetches documents for the pages when their server does not allow other websites to: the EU List
// of Trusted Lists and the lists it points to, whose servers do not send CORS headers. It fetches
// nothing else, so it is no open proxy. The pages verify the signatures of what it returns, so they
// do not need to trust it.

/** Where the EU publishes its List of Trusted Lists, the same as EU_LOTL_URL in src/trusted-list.ts */
export const EU_LOTL_URL = 'https://ec.europa.eu/tools/lotl/eu-lotl.xml'

/** How long a document is cached, in seconds */
export const CACHE_SECONDS = 3600
/** The largest document fetched, in bytes; the largest national list is about 5 MB */
export const MAX_BYTES = 20 * 1024 * 1024
/** How long to wait for a server, in milliseconds */
const TIMEOUT_MS = 20_000

const USER_AGENT = 'Credscope fetch proxy (+https://credscope.eudi-wallet.dev/)'
const NAME = 'credscope'

// Pages served by `pnpm dev` and `pnpm preview`
const LOCAL_ORIGIN = /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/

// What makes the responses inert where they are opened as a page, so the proxy cannot serve one
const SAFE_HEADERS = {
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

const XML_ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }

/** The URL in the form to compare it, without its fragment, or undefined if it is no http(s) URL */
export function normalizeUrl(text: string): string | undefined {
  let url: URL
  try {
    url = new URL(text.trim())
  } catch {
    return undefined
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return undefined
  url.hash = ''
  return url.href
}

/** The URLs of the lists a trusted list points to, from its TSLLocation elements */
export function tslLocations(xml: string): string[] {
  const urls: string[] = []
  for (const [, location] of xml.matchAll(/<(?:[\w.-]+:)?TSLLocation>([^<]*)<\/(?:[\w.-]+:)?TSLLocation>/g)) {
    const url = normalizeUrl(location.replace(/&(amp|lt|gt|quot|apos);/g, (_, name: string) => XML_ENTITIES[name]))
    if (url) urls.push(url)
  }
  return urls
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

export function createProxy({ allowedOrigins, cache, fetch, now = Date.now }: ProxyOptions): FetchProxy {
  // The lists the LOTL points to, read again when the LOTL is
  let allowed: { urls: Set<string>; until: number } | undefined

  const isAllowedOrigin = (origin: string) => allowedOrigins.includes(origin) || LOCAL_ORIGIN.test(origin)

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
    let bytes: Uint8Array<ArrayBuffer>
    try {
      const response = await fetch(url, {
        headers: { accept: '*/*', 'user-agent': USER_AGENT },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      })
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
    waitUntil(cache.put(key, new Response(bytes, { headers: { 'cache-control': `max-age=${CACHE_SECONDS}` } })))
    return { status: 200, bytes }
  }

  async function allowedUrls(base: string, waitUntil: (promise: Promise<unknown>) => void): Promise<Set<string>> {
    if (allowed && allowed.until > now()) return allowed.urls
    const lotl = await fetchDocument(EU_LOTL_URL, base, waitUntil)
    if (!lotl.bytes) {
      throw new ProxyError(
        502,
        'destination_unavailable',
        `The EU LOTL, which lists what the Credscope proxy fetches, answered ${lotl.status}.`
      )
    }
    const urls = new Set([EU_LOTL_URL, ...tslLocations(new TextDecoder().decode(lotl.bytes))])
    allowed = { urls, until: now() + CACHE_SECONDS * 1000 }
    return urls
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

    // Another website, which could otherwise use it as a CORS proxy
    if (origin && !isAllowedOrigin(origin)) {
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
    const url = normalizeUrl(requestUrl.searchParams.get('url') ?? '')
    if (!url) {
      return fail(new ProxyError(400, 'http_request_error', 'Give the http(s) URL of a document as ?url=.'))
    }

    const base = `${requestUrl.origin}/`
    try {
      if (url !== EU_LOTL_URL && !(await allowedUrls(base, waitUntil)).has(url)) {
        throw new ProxyError(
          403,
          'http_request_denied',
          'The Credscope proxy only fetches the EU List of Trusted Lists and the lists it points to.'
        )
      }
      const { status, bytes } = await fetchDocument(url, base, waitUntil)
      const headers = { ...SAFE_HEADERS, ...cors }
      if (!bytes) {
        return new Response(null, {
          status,
          headers: { ...headers, 'cache-control': 'no-store', 'proxy-status': `${NAME}; received-status=${status}` },
        })
      }
      return new Response(request.method === 'HEAD' ? null : bytes, {
        headers: {
          ...headers,
          'content-type': 'application/octet-stream',
          'cache-control': `public, max-age=${CACHE_SECONDS}`,
          'proxy-status': NAME,
        },
      })
    } catch (error) {
      if (error instanceof ProxyError) return fail(error)
      throw error
    }
  }
}
