import { describe, expect, it } from 'vitest'
import { CACHE_SECONDS, createProxy, freshness, MAX_BYTES, MAX_REDIRECTS, publicUrl } from '../proxy'

const PAGES = 'https://credscope.eudi-wallet.dev'
const PROXY = 'https://credscope-fetch.eudi-wallet.dev/'
const LIST = 'https://tl.bundesnetzagentur.de/TL-DE.xml'
const STATUS = 'https://issuer.example.org/status/1'

/** The Cache API of a worker, as far as the proxy uses it */
class MemoryCache {
  readonly entries = new Map<string, Response>()
  async match(request: Request) {
    return this.entries.get(request.url)?.clone()
  }
  async put(request: Request, response: Response) {
    this.entries.set(request.url, response)
  }
}

const NOW = Date.parse('2026-11-02T12:00:00Z')

/** A proxy whose servers answer with `documents`, or 404 */
function setup(documents: Record<string, () => Response> = {}, { allow = true } = {}) {
  const cache = new MemoryCache()
  const fetched: string[] = []
  const limited: string[] = []
  const pending: Promise<unknown>[] = []
  const proxy = createProxy({
    allowedOrigins: [PAGES],
    cache: cache as unknown as Cache,
    fetch: async (url, init) => {
      expect(init.redirect).toBe('manual')
      fetched.push(url)
      const document = documents[url]
      return document ? document() : new Response('Not found', { status: 404 })
    },
    limit: async (key) => {
      limited.push(key)
      return allow
    },
    now: () => NOW,
  })
  /** A request of the pages, as fetch() makes it, unless `origin` or `fetchMode` say otherwise */
  const request = async (
    target: string | null,
    init: RequestInit & { origin?: string | null; fetchMode?: string | null; path?: string } = {}
  ) => {
    const url = new URL(init.path ?? PROXY)
    if (target !== null) url.searchParams.set('url', target)
    const headers = new Headers(init.headers)
    const origin = init.origin === undefined ? PAGES : init.origin
    if (origin) headers.set('origin', origin)
    const mode = init.fetchMode === undefined ? 'cors' : init.fetchMode
    if (mode) headers.set('sec-fetch-mode', mode)
    headers.set('cf-connecting-ip', '192.0.2.1')
    const response = await proxy(new Request(url, { method: init.method, headers }), (promise) => pending.push(promise))
    await Promise.all(pending)
    return response
  }
  return { request, fetched, limited, cache }
}

const document =
  (body: string, headers: Record<string, string> = {}) =>
  () =>
    new Response(body, { headers })
const redirect = (location: string) => () => new Response(null, { status: 302, headers: { location } })

describe('publicUrl', () => {
  it('takes http(s) URLs on public hosts, without their fragment', () => {
    expect(publicUrl(` ${LIST}#top `)).toBe(LIST)
    expect(publicUrl('http://tl.nbu.gov.sk/kca/tsl/tsl.xml')).toBe('http://tl.nbu.gov.sk/kca/tsl/tsl.xml')
    expect(publicUrl('https://gov.hr/Usluge povjerenja/RH.xml')).toBe('https://gov.hr/Usluge%20povjerenja/RH.xml')
  })

  it('refuses other schemes, ports and credentials', () => {
    for (const url of [
      'not a URL',
      'javascript:alert(1)',
      'file:///etc/passwd',
      'ftp://example.org/list.xml',
      'https://example.org:8443/list.xml',
      'https://user:secret@example.org/list.xml',
    ]) {
      expect(publicUrl(url), url).toBeUndefined()
    }
  })

  it('refuses IP addresses and names of no public host', () => {
    for (const url of [
      'http://127.0.0.1/',
      'http://10.0.0.1/',
      'http://0x7f.1/',
      'http://2130706433/',
      'http://[::1]/',
      'http://localhost/',
      'http://localhost./',
      'http://api.localhost/',
      'http://intranet/',
      'http://printer.local/',
      'http://service.internal/',
      'http://router.home.arpa/',
      'http://app.test/',
    ]) {
      expect(publicUrl(url), url).toBeUndefined()
    }
  })
})

describe('freshness', () => {
  const headers = (init: Record<string, string>) => new Headers(init)
  const ago = (seconds: number) => new Date(NOW - seconds * 1000).toUTCString()

  it('follows Cache-Control, up to an hour', () => {
    expect(freshness(headers({ 'cache-control': 'public, max-age=60' }), NOW)).toBe(60)
    expect(freshness(headers({ 'cache-control': 'max-age=60, s-maxage=120' }), NOW)).toBe(120)
    expect(freshness(headers({ 'cache-control': 'max-age=86400' }), NOW)).toBe(CACHE_SECONDS)
    for (const value of ['no-store', 'no-cache', 'private, max-age=60', 'private="set-cookie", max-age=60']) {
      expect(freshness(headers({ 'cache-control': value }), NOW), value).toBe(0)
    }
  })

  it('caches for a tenth of the time since the last change, without a lifetime', () => {
    expect(freshness(headers({ 'last-modified': ago(300) }), NOW)).toBe(30)
    expect(freshness(headers({ 'last-modified': ago(30 * 86400) }), NOW)).toBe(CACHE_SECONDS)
    expect(freshness(headers({ 'last-modified': ago(-60) }), NOW)).toBe(0)
    expect(freshness(headers({}), NOW)).toBe(0)
  })
})

describe('the fetch proxy', () => {
  it('fetches a document, as an inert download', async () => {
    const { request, fetched, limited } = setup({ [STATUS]: document('eyJ0eXAiOiJzdGF0dXNsaXN0K2p3dCJ9') })
    const response = await request(STATUS)
    expect(response.status).toBe(200)
    expect(await response.text()).toBe('eyJ0eXAiOiJzdGF0dXNsaXN0K2p3dCJ9')
    expect(Object.fromEntries(response.headers)).toMatchObject({
      'access-control-allow-origin': PAGES,
      'access-control-expose-headers': 'Proxy-Status',
      vary: 'Origin',
      'content-type': 'application/octet-stream',
      'content-disposition': 'attachment',
      'x-content-type-options': 'nosniff',
      'content-security-policy': "default-src 'none'; sandbox",
      'cache-control': 'no-store',
      'proxy-status': 'credscope',
    })
    expect(fetched).toEqual([STATUS])
    expect(limited).toEqual(['192.0.2.1'])
  })

  it('caches a document as long as its server allows, under the URL of the proxy', async () => {
    const { request, fetched, cache } = setup({
      [LIST]: document('<TSL/>', { 'cache-control': 'max-age=600' }),
      [STATUS]: document('status', { 'cache-control': 'no-store' }),
    })
    for (const url of [LIST, LIST, STATUS, STATUS]) expect((await request(url)).status).toBe(200)
    expect(fetched).toEqual([LIST, STATUS, STATUS])
    expect([...cache.entries.keys()]).toEqual([`${PROXY}?${new URLSearchParams({ url: LIST })}`])
    expect(cache.entries.get(`${PROXY}?${new URLSearchParams({ url: LIST })}`)?.headers.get('cache-control')).toBe(
      'max-age=600'
    )
  })

  it('refuses other websites, which could use it as a CORS proxy', async () => {
    const { request, fetched } = setup({ [LIST]: document('<TSL/>') })
    const response = await request(LIST, { origin: 'https://evil.example' })
    expect(response.status).toBe(403)
    expect(response.headers.get('access-control-allow-origin')).toBeNull()
    expect(response.headers.get('proxy-status')).toBe('credscope; error=http_request_denied')
    expect(fetched).toEqual([])
  })

  it('refuses links to it and requests without an origin', async () => {
    const { request, fetched } = setup({ [LIST]: document('<TSL/>') })
    // A browser opens a link without an Origin, as a navigation
    expect((await request(LIST, { origin: null, fetchMode: 'navigate' })).status).toBe(403)
    expect((await request(LIST, { fetchMode: 'navigate' })).status).toBe(403)
    expect((await request(LIST, { fetchMode: 'no-cors' })).status).toBe(403)
    expect((await request(LIST, { fetchMode: null })).status).toBe(403)
    expect((await request(LIST, { origin: null })).status).toBe(403)
    expect(fetched).toEqual([])
  })

  it('answers pages on localhost', async () => {
    const { request } = setup({ [LIST]: document('<TSL/>') })
    const response = await request(LIST, { origin: 'http://localhost:5173' })
    expect(response.status).toBe(200)
    expect(response.headers.get('access-control-allow-origin')).toBe('http://localhost:5173')
  })

  it('refuses URLs that are not on a public host', async () => {
    const { request, fetched } = setup()
    for (const url of ['http://localhost:8080/status', 'http://192.168.1.10/list.xml', 'https://example.org:8443/']) {
      const response = await request(url)
      expect(response.status).toBe(400)
      expect(await response.text()).toMatch(/public host/)
    }
    expect(fetched).toEqual([])
  })

  it('follows redirects on public hosts', async () => {
    const { request, fetched } = setup({
      'https://example.org/list': redirect('/list.xml'),
      'https://example.org/list.xml': document('<TSL/>'),
    })
    const response = await request('https://example.org/list')
    expect(await response.text()).toBe('<TSL/>')
    expect(fetched).toEqual(['https://example.org/list', 'https://example.org/list.xml'])
  })

  it('refuses redirects to other hosts than public ones, and too many', async () => {
    const { request, fetched } = setup({
      'https://example.org/private': redirect('http://169.254.169.254/latest/meta-data/'),
      'https://example.org/loop': redirect('https://example.org/loop'),
    })
    const private_ = await request('https://example.org/private')
    expect(private_.status).toBe(403)
    expect(await private_.text()).toMatch(/redirects to http:\/\/169\.254\.169\.254\/latest\/meta-data\/, which is no/)
    expect(fetched).toEqual(['https://example.org/private'])
    const loop = await request('https://example.org/loop')
    expect(loop.status).toBe(502)
    expect(await loop.text()).toMatch(/redirects more than 5 times/)
    expect(fetched).toHaveLength(1 + MAX_REDIRECTS + 1)
  })

  it('limits the requests of a client', async () => {
    const { request, fetched } = setup({ [LIST]: document('<TSL/>') }, { allow: false })
    const response = await request(LIST)
    expect(response.status).toBe(429)
    expect(response.headers.get('retry-after')).toBe('60')
    expect(response.headers.get('access-control-allow-origin')).toBe(PAGES)
    expect(fetched).toEqual([])
  })

  it('answers HEAD without a body', async () => {
    const { request } = setup({ [LIST]: document('<TSL/>') })
    const response = await request(LIST, { method: 'HEAD' })
    expect(response.status).toBe(200)
    expect(await response.text()).toBe('')
  })

  it('refuses other methods, paths and URLs', async () => {
    const { request } = setup({ [LIST]: document('<TSL/>') })
    const post = await request(LIST, { method: 'POST' })
    expect(post.status).toBe(405)
    expect(post.headers.get('allow')).toBe('GET, HEAD')
    expect((await request(LIST, { path: `${PROXY}other` })).status).toBe(404)
    expect((await request(null)).status).toBe(400)
  })

  it('passes on the status of a server that fails', async () => {
    const { request, cache } = setup()
    const response = await request(LIST)
    expect(response.status).toBe(404)
    expect(response.headers.get('proxy-status')).toBe('credscope; received-status=404')
    expect(cache.entries.size).toBe(0)
  })

  it('says when a server cannot be reached, or does not answer in time', async () => {
    const { request } = setup({
      [LIST]: () => {
        throw new TypeError('fetch failed')
      },
      [STATUS]: () => {
        throw new DOMException('The operation timed out.', 'TimeoutError')
      },
    })
    const unreachable = await request(LIST)
    expect(unreachable.status).toBe(502)
    expect(unreachable.headers.get('proxy-status')).toBe('credscope; error=destination_unavailable')
    expect(await unreachable.text()).toBe('tl.bundesnetzagentur.de cannot be reached from the Credscope proxy.')
    const slow = await request(STATUS)
    expect(slow.status).toBe(504)
    expect(await slow.text()).toBe('issuer.example.org did not answer within 20 seconds.')
  })

  it('refuses documents that are too large, by their length or as they come', async () => {
    const large = new Uint8Array(MAX_BYTES + 1)
    const { request } = setup({
      [LIST]: () => new Response(large, { headers: { 'content-length': String(large.byteLength) } }),
      [STATUS]: () =>
        new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(large.subarray(0, MAX_BYTES))
              controller.enqueue(large.subarray(MAX_BYTES))
              controller.close()
            },
          })
        ),
    })
    for (const url of [LIST, STATUS]) {
      const response = await request(url)
      expect(response.status).toBe(413)
      expect(response.headers.get('proxy-status')).toBe('credscope; error=http_response_body_size')
    }
  })
})
