/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** The fetch proxy, see web/src/fetch.ts; empty for none */
  readonly VITE_FETCH_PROXY?: string
}
