// The browser fetches a document straight from its server. Where the server does not allow other
// websites to, as for the EU LOTL, nearly every national trusted list and many status lists, the page
// asks the fetch proxy of worker/, which fetches from public hosts. Signatures are checked here all the same.

/** The fetch proxy, none when empty */
const PROXY = import.meta.env.VITE_FETCH_PROXY ?? 'https://credscope-fetch.eudi-wallet.dev/'

export interface Fetched {
  bytes: Uint8Array
  /** Whether the proxy fetched it */
  proxied: boolean
}

/** A document that cannot be fetched */
export class FetchError extends Error {
  constructor(
    message: string,
    /** Whether the browser could not fetch it, so it has to be downloaded instead */
    readonly blocked = false
  ) {
    super(message)
  }
}

async function fetchThroughProxy(url: URL): Promise<Fetched> {
  // A failed fetch does not say why; a missing CORS header is the common cause
  const blocked = `${url.href} could not be fetched. The server may not allow requests from other websites (CORS), or it is unreachable.`
  if (!PROXY) throw new FetchError(blocked, true)
  const proxyUrl = new URL(PROXY)
  proxyUrl.searchParams.set('url', url.href)
  let response: Response
  try {
    response = await fetch(proxyUrl, { credentials: 'omit' })
  } catch {
    throw new FetchError(`${blocked} Nor can the Credscope proxy be reached.`, true)
  }
  if (response.ok) return { bytes: new Uint8Array(await response.arrayBuffer()), proxied: true }
  // An error of the proxy, rather than of the server, see RFC 9209
  if (response.headers.get('proxy-status')?.includes('error=')) {
    throw new FetchError(`${blocked} ${await response.text()}`, true)
  }
  throw new FetchError(`The server answered ${response.status} to the Credscope proxy.`)
}

/** Fetch a document, through the proxy if the browser cannot */
export async function fetchBytes(url: URL): Promise<Fetched> {
  let response: Response
  try {
    response = await fetch(url, { credentials: 'omit' })
  } catch {
    return fetchThroughProxy(url)
  }
  if (!response.ok) throw new FetchError(`The server answered ${response.status} ${response.statusText}.`)
  return { bytes: new Uint8Array(await response.arrayBuffer()), proxied: false }
}
