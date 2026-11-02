import { describe, expect, it } from 'vitest'
import { EU_LOTL_URL as INSPECTOR_LOTL_URL } from '../../../src/trusted-list'
import { CACHE_SECONDS, createProxy, EU_LOTL_URL, MAX_BYTES, normalizeUrl, tslLocations } from '../proxy'

const PAGES = 'https://credscope.eudi-wallet.dev'
const PROXY = 'https://credscope-fetch.eudi-wallet.dev/'
const DE = 'https://tl.bundesnetzagentur.de/TL-DE.xml'
const HR = 'https://gov.hr/UserDocsImages/Usluge%20povjerenja/Pouzdani_popis_RH.xml'

const LOTL = `<?xml version="1.0" encoding="UTF-8"?>
<tsl:TrustServiceStatusList xmlns:tsl="http://uri.etsi.org/02231/v2#">
  <tsl:SchemeInformation>
    <tsl:PointersToOtherTSL>
      <tsl:OtherTSLPointer><tsl:TSLLocation>${EU_LOTL_URL}</tsl:TSLLocation></tsl:OtherTSLPointer>
      <tsl:OtherTSLPointer><tsl:TSLLocation> ${DE} </tsl:TSLLocation></tsl:OtherTSLPointer>
      <tsl:OtherTSLPointer><tsl:TSLLocation>https://gov.hr/UserDocsImages/Usluge povjerenja/Pouzdani_popis_RH.xml</tsl:TSLLocation></tsl:OtherTSLPointer>
      <tsl:OtherTSLPointer><TSLLocation>https://example.org/list.xml?a=1&amp;b=2</TSLLocation></tsl:OtherTSLPointer>
      <tsl:OtherTSLPointer><tsl:TSLLocation>ftp://example.org/list.xml</tsl:TSLLocation></tsl:OtherTSLPointer>
    </tsl:PointersToOtherTSL>
  </tsl:SchemeInformation>
</tsl:TrustServiceStatusList>`

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

/** A proxy whose servers answer with `documents`, or 404 */
function setup(documents: Record<string, () => Response> = {}) {
  const cache = new MemoryCache()
  const fetched: string[] = []
  const pending: Promise<unknown>[] = []
  let time = 0
  const proxy = createProxy({
    allowedOrigins: [PAGES],
    cache: cache as unknown as Cache,
    fetch: async (url) => {
      fetched.push(url)
      const document = documents[url]
      return document ? document() : new Response('Not found', { status: 404 })
    },
    now: () => time,
  })
  const request = async (target: string | null, init: RequestInit & { origin?: string | null; path?: string } = {}) => {
    const url = new URL(init.path ?? PROXY)
    if (target !== null) url.searchParams.set('url', target)
    const headers = new Headers(init.headers)
    const origin = init.origin === undefined ? PAGES : init.origin
    if (origin) headers.set('origin', origin)
    const response = await proxy(new Request(url, { ...init, headers }), (promise) => pending.push(promise))
    await Promise.all(pending)
    return response
  }
  return { request, fetched, cache, advance: (ms: number) => (time += ms) }
}

const lotl = () => new Response(LOTL)

describe('the fetch proxy', () => {
  it('uses the URL of the EU LOTL of the inspector', () => {
    expect(EU_LOTL_URL).toBe(INSPECTOR_LOTL_URL)
  })

  it('reads the lists the LOTL points to', () => {
    expect(tslLocations(LOTL)).toEqual([EU_LOTL_URL, DE, HR, 'https://example.org/list.xml?a=1&b=2'])
  })

  it('compares URLs without their fragment', () => {
    expect(normalizeUrl(`${DE}#top`)).toBe(DE)
    expect(normalizeUrl('javascript:alert(1)')).toBeUndefined()
    expect(normalizeUrl('not a URL')).toBeUndefined()
  })

  it('fetches the EU LOTL, as an inert download', async () => {
    const { request } = setup({ [EU_LOTL_URL]: lotl })
    const response = await request(EU_LOTL_URL)
    expect(response.status).toBe(200)
    expect(await response.text()).toBe(LOTL)
    expect(Object.fromEntries(response.headers)).toMatchObject({
      'access-control-allow-origin': PAGES,
      'access-control-expose-headers': 'Proxy-Status',
      vary: 'Origin',
      'content-type': 'application/octet-stream',
      'x-content-type-options': 'nosniff',
      'content-security-policy': "default-src 'none'; sandbox",
      'cache-control': `public, max-age=${CACHE_SECONDS}`,
      'proxy-status': 'credscope',
    })
  })

  it('fetches a list the LOTL points to', async () => {
    const { request, fetched } = setup({ [EU_LOTL_URL]: lotl, [HR]: () => new Response('<TSL/>') })
    const response = await request('https://gov.hr/UserDocsImages/Usluge povjerenja/Pouzdani_popis_RH.xml')
    expect(response.status).toBe(200)
    expect(await response.text()).toBe('<TSL/>')
    expect(fetched).toEqual([EU_LOTL_URL, HR])
  })

  it('fetches nothing else', async () => {
    const { request, fetched } = setup({ [EU_LOTL_URL]: lotl })
    const response = await request('https://example.org/')
    expect(response.status).toBe(403)
    expect(response.headers.get('proxy-status')).toBe('credscope; error=http_request_denied')
    expect(response.headers.get('access-control-allow-origin')).toBe(PAGES)
    expect(await response.text()).toMatch(/only fetches the EU List of Trusted Lists/)
    expect(fetched).toEqual([EU_LOTL_URL])
  })

  it('caches what it fetches, and the lists the LOTL points to', async () => {
    const { request, fetched, advance } = setup({ [EU_LOTL_URL]: lotl, [DE]: () => new Response('<TSL/>') })
    await request(DE)
    await request(DE)
    expect(fetched).toEqual([EU_LOTL_URL, DE])
    advance(CACHE_SECONDS * 1000)
    await request(DE)
    // The cache of the test does not expire, that of a worker does
    expect(fetched).toEqual([EU_LOTL_URL, DE])
  })

  it('caches under the URL of the proxy', async () => {
    const { request, cache } = setup({ [EU_LOTL_URL]: lotl })
    await request(EU_LOTL_URL)
    expect([...cache.entries.keys()]).toEqual([`${PROXY}?${new URLSearchParams({ url: EU_LOTL_URL })}`])
  })

  it('refuses other websites, which could use it as a CORS proxy', async () => {
    const { request, fetched } = setup({ [EU_LOTL_URL]: lotl })
    const response = await request(EU_LOTL_URL, { origin: 'https://evil.example' })
    expect(response.status).toBe(403)
    expect(response.headers.get('access-control-allow-origin')).toBeNull()
    expect(fetched).toEqual([])
  })

  it('allows pages on localhost and requests without an origin', async () => {
    const { request } = setup({ [EU_LOTL_URL]: lotl })
    const local = await request(EU_LOTL_URL, { origin: 'http://localhost:5173' })
    expect(local.headers.get('access-control-allow-origin')).toBe('http://localhost:5173')
    const direct = await request(EU_LOTL_URL, { origin: null })
    expect(direct.status).toBe(200)
    expect(direct.headers.get('access-control-allow-origin')).toBeNull()
  })

  it('answers HEAD without a body', async () => {
    const { request } = setup({ [EU_LOTL_URL]: lotl })
    const response = await request(EU_LOTL_URL, { method: 'HEAD' })
    expect(response.status).toBe(200)
    expect(await response.text()).toBe('')
  })

  it('refuses other methods, paths and URLs', async () => {
    const { request } = setup({ [EU_LOTL_URL]: lotl })
    const post = await request(EU_LOTL_URL, { method: 'POST' })
    expect(post.status).toBe(405)
    expect(post.headers.get('allow')).toBe('GET, HEAD')
    expect((await request(EU_LOTL_URL, { path: `${PROXY}other` })).status).toBe(404)
    expect((await request(null)).status).toBe(400)
    expect((await request('file:///etc/passwd')).status).toBe(400)
  })

  it('passes on the status of a server that fails', async () => {
    const { request, cache } = setup({ [EU_LOTL_URL]: lotl })
    const response = await request(DE)
    expect(response.status).toBe(404)
    expect(response.headers.get('proxy-status')).toBe('credscope; received-status=404')
    expect(cache.entries.size).toBe(1)
  })

  it('says when a server cannot be reached', async () => {
    const { request } = setup({
      [EU_LOTL_URL]: lotl,
      [DE]: () => {
        throw new TypeError('fetch failed')
      },
    })
    const response = await request(DE)
    expect(response.status).toBe(502)
    expect(response.headers.get('proxy-status')).toBe('credscope; error=destination_unavailable')
    expect(await response.text()).toBe('tl.bundesnetzagentur.de cannot be reached from the Credscope proxy.')
  })

  it('says when the EU LOTL cannot be fetched', async () => {
    const { request } = setup({ [EU_LOTL_URL]: () => new Response('', { status: 503 }) })
    const response = await request(DE)
    expect(response.status).toBe(502)
    expect(await response.text()).toMatch(/answered 503/)
  })

  it('refuses documents that are too large, by their length or as they come', async () => {
    const large = new Uint8Array(MAX_BYTES + 1)
    const { request } = setup({
      [EU_LOTL_URL]: lotl,
      [DE]: () => new Response(large, { headers: { 'content-length': String(large.byteLength) } }),
      [HR]: () =>
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
    for (const url of [DE, HR]) {
      const response = await request(url)
      expect(response.status).toBe(413)
      expect(response.headers.get('proxy-status')).toBe('credscope; error=http_response_body_size')
    }
  })
})
