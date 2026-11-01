<p align="center"><img src="assets/logo.svg" alt="" width="96" height="96"></p>

# Credscope

Parse digital identity documents and check each element against its specification, in the browser and on the command
line as `credscope`.

| Format | Specification | Input |
| --- | --- | --- |
| Trusted list | ETSI TS 119 612 | XML |
| List of Trusted Entities | ETSI TS 119 602 | JSON or JWS |
| Registration certificate | ETSI TS 119 475 | JWS |
| Access certificate | ETSI TS 119 411-8 | PEM, base64, hex or DER |
| Token Status List | draft-ietf-oauth-status-list-16 | JWT |
| SD-JWT and SD-JWT VC | RFC 9901, draft-ietf-oauth-sd-jwt-vc | compact, with or without Key Binding JWT |
| mdoc | ISO/IEC 18013-5 | IssuerSigned or DeviceResponse, CBOR as bytes, hex or base64url |
| OpenID4VP request | OpenID4VP, ETSI TS 119 475 | checked for over-asking against the registration certificate |

It is built on the packages of [identity-common-ts](https://github.com/openwallet-foundation-labs/identity-common-ts).
The checks of trusted lists, LoTEs, certificates and requests come from their validators. Those of status lists,
SD-JWTs and mdocs are here, built on the decoding of `@owf/token-status-list`, `@sd-jwt/core` and `@owf/mdoc`.

Each issue has a severity, a code, a message, the requirement it comes from where known, and a path into the parsed
document, so it can be shown at the element it concerns. These are the `ValidationIssue`s of `@owf/identity-common`.
Checks that recur across specifications, such as `invalid_typ`, `expired` and `not_yet_valid`, use its common codes,
with their context, e.g. the expected and the actual `typ`.

## Status

This is a prototype. It needs changes to identity-common-ts that are not released yet, see
[openwallet-foundation-labs/identity-common-ts#404](https://github.com/openwallet-foundation-labs/identity-common-ts/pull/404).
Until they are, it is built against a checkout of identity-common-ts next to this one, see [Development](#development).
It is meant to move to the OpenWallet Foundation Labs later.

## Web pages

<https://cre8.github.io/credscope/>

The start page takes any document, recognises its format, and loads only the parsers of that format. Each format has a
page of its own, with the inputs its further checks need:

| Page | Further inputs |
| --- | --- |
| `trusted-list/` | Check the signer against the EU LOTL, or against certificates |
| `lote/` | Signer key or trust anchor |
| `registration-certificate/` | Access certificate of the relying party, signer key or trust anchor |
| `access-certificate/` | Certificate of the issuing CA |
| `status-list/` | `uri` of the reference, signer key or trust anchor |
| `sd-jwt/` | Issuer key or trust anchor, expected `nonce` and `aud` |
| `mdoc/` | |
| `over-asking/` | Request and registration certificate |

Documents can be pasted, dropped as a file or fetched from a URL. For a status list, the page also counts the statuses
and looks up the status at an index. For an SD-JWT, it resolves the claims and shows the claim each disclosure
discloses. For an mdoc, it shows the Mobile Security Object and every element, and compares the digest of each element
with the one in the MSO.

### Signatures

Signatures are verified with the Web Crypto API of the browser:

- A JWS is verified with the key you give, as JWK, JWK Set or certificates, or else with the `x5c` of its header. When
  you give a certificate and the header has an `x5c`, the chain of the `x5c` has to lead to it, so it acts as the trust
  anchor. Without a trust anchor, a valid signature proves integrity only.
- The Key Binding JWT of an SD-JWT is verified with the key in `cnf`.
- The EU List of Trusted Lists is verified against the signing certificates shipped with `@owf/eudi-tl`. Another
  trusted list is verified against the certificates you give, or against those the EU LOTL lists for its territory,
  which the page then fetches from `ec.europa.eu`.
- An access certificate is verified with the certificate of its CA.

### Examples

Each page offers examples that show what it checks: documents that pass, and documents with a planted problem. An
example opens as `#example=<id>`, e.g. `sd-jwt/#example=other-verifier`, so it can be linked to.

`web/scripts/examples.ts` makes them into `web/src/examples/` with `pnpm examples`. The signed examples are made with
throwaway keys and the test CA of `@owf/eudi-access-certificate`, valid until 2036. `web/src/__tests__/examples.test.mts`
runs every example as its page does and checks the issues and signature results it was made to show.

### Sharing a result

"Copy link to this result" puts the input of the page into the fragment of the URL, after the `#`, which browsers do not
send to the server. Long values are compressed with raw DEFLATE and encoded as base64url. Links can also be written by
hand:

```text
trusted-list/#url=https://ec.europa.eu/tools/lotl/eu-lotl.xml
sd-jwt/#doc=eyJ…~&nonce=n-0S6&aud=https://verifier.example
status-list/#doc=eyJ…&uri=https://example.com/statuslists/1&lookup=42
```

The names are those of the fields of the page: `url` or `doc` for the document, `lookup` for the index of a status list,
and `key`, `nonce`, `aud`, `uri`, `access`, `issuer`, `signers`, `lotl`, `request` and `registration`. A link holds the
input in full, so anyone with the link sees it.

### Privacy

Everything runs in the browser: nothing that is pasted, dropped or checked is sent to a server. Once loaded, a page only
makes a request to fetch a URL you give, or the EU LOTL when you check a signer against it.

## Command line

```bash
pnpm build:cli
node bin/credscope.mjs --help
```

A document is a file, an http(s) URL, `-` for standard input, or the document itself. The format is recognised, or given
with `--format`:

```bash
# A national trusted list, with its signer checked against the certificates the EU LOTL has for it
credscope https://tl.bundesnetzagentur.de/TL-DE.xml --lotl

# An SD-JWT VC presentation, with the issuer's trust anchor and what the verifier expects
credscope presentation.txt --key issuing-ca.pem --nonce n-0S6 --aud https://verifier.example

# A registration certificate for the relying party of an access certificate
credscope registration.jwt --access-certificate access.pem

# The status at an index of a status list, as JSON
curl -s https://example.com/statuslists/1 | credscope - --index 42 --json

# An OpenID4VP request against the registration certificate in its verifier_info
credscope over-asking request.jwt
```

Keys and certificates are given as a file or as text: a JWK, a JWK Set, or PEM. `--json` prints the result with the
parsed document, bytes as hex. `--link` prints a link that opens the document in the web page of its format.

The command line tool fetches without the cross-origin limits of a browser, so national trusted lists can be checked
straight from their servers.

The exit status is 0 without errors, 1 with errors or an invalid signature, and 2 when a document cannot be read.
`--strict` also fails on warnings and on signatures that could not be verified, e.g. for want of a key.

### Single executable

`pnpm build:binary` builds the command line tool as a single executable of Node.js, which runs without Node.js
installed. This needs Node.js 25.7 or later, and makes an executable for the platform it runs on. Each release, tagged
`v<version>`, has one for Linux x64 attached as `credscope-linux-x64`, with its SHA-256 checksum:

```bash
sha256sum --check credscope-linux-x64.sha256
chmod +x credscope-linux-x64
./credscope-linux-x64 --help
```

## Development

The packages of identity-common-ts are linked from a checkout next to this one, and used from their TypeScript sources:

```bash
git clone https://github.com/openwallet-foundation-labs/identity-common-ts.git
git -C identity-common-ts switch feat/validation-findings
pnpm --dir identity-common-ts install
git clone https://github.com/cre8/credscope.git
cd credscope
pnpm install
pnpm dev
```

Once the packages are released, the links in `package.json` become their versions.

| Script | What it does |
| --- | --- |
| `pnpm dev` | The web pages with live reload |
| `pnpm test` | The tests, including every example |
| `pnpm ci:check` | Style, types and tests |
| `pnpm build` | The web pages into `dist/web` and the command line tool into `dist/cli` |
| `pnpm examples` | Makes the examples of the pages again |

The checks are in `src/`, which the pages import as `#inspector`. Each page is an `index.html` in `web/`, in the folder of
its name; `web/layout.ts` adds the header, navigation, result area and footer they share, and `web/src/site.ts` lists
the pages.

## Deployment

- `.github/workflows/ci.yml` checks style, types and tests, and builds, on every push and pull request.
- `.github/workflows/pages.yml` publishes the web pages to GitHub Pages on every push to `main`. The build uses a
  relative base, so it works under any path.
- `.github/workflows/release.yml` builds the Linux executable for a tag `v*` and attaches it to the GitHub release of
  the tag.

`assets/logo.svg` is the logo, also the icon of the pages. `assets/social-preview.png`, made from
`assets/social-preview.svg` with `rsvg-convert`, is the image GitHub shows when the repository is shared, set under
Settings → Social preview.

Each workflow checks out identity-common-ts next to this repository, at the `identity-common-ref` of
`.github/actions/setup/action.yml`.

## Limitations

- Fetching a URL in the browser needs the server to allow cross-origin requests. The EU List of Trusted Lists does, but
  the national trusted lists do not. Download those and drop the file, or use the command line tool.
- The issuer signature of an mdoc, the device signature or MAC of a DeviceResponse, and the signatures of request
  objects are not verified. A JWS signed with a key named by `kid` alone needs that key to be given.
- Revocation is not checked: neither the CRLs of certificates nor the status of an SD-JWT VC or mdoc.
- Status lists are only read in JWT format, not as CWT.
- SD-JWTs are read in compact serialization, not as JSON. The type metadata of a vct is not fetched.
- A request passed by reference (`request_uri`) is not fetched; paste its request object instead.

## License

[Apache License Version 2.0](LICENSE)
