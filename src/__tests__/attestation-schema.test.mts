import { hasher } from '@owf/crypto'
import { base64, base64urlEncode } from '@owf/identity-common'
import { describe, expect, it } from 'vitest'
import { inspectAttestationSchema } from '../attestation-schema'
import { detect } from '../detect'
import type { Inspection } from '../inspection'

const fakeJws = (header: Record<string, unknown>, payload: unknown) =>
  `${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(JSON.stringify(payload))}.c2ln`

const integrity = (content: string) => `sha256-${base64.encode(hasher(content, 'sha256'))}`

const PID_VCT = 'urn:eudi:pid:1'
const DOCUMENTS: Record<string, string> = {
  'https://catalogue.example/rulebook.md': '# PID rulebook',
  'https://catalogue.example/type-metadata.json': JSON.stringify({ vct: PID_VCT, name: 'PID' }),
  'https://catalogue.example/mdoc.json': JSON.stringify({ type: 'object' }),
}

const schemaMeta = (documents = DOCUMENTS) => ({
  id: 'https://catalogue.example/attestations/pid',
  version: '1.0.0',
  rulebookURI: 'https://catalogue.example/rulebook.md',
  rulebookIntegrity: integrity(documents['https://catalogue.example/rulebook.md']),
  attestationLoS: 'iso_18045_high',
  bindingType: 'key',
  schemaURIs: [
    {
      formatIdentifier: 'dc+sd-jwt',
      uri: 'https://catalogue.example/type-metadata.json',
      integrity: integrity(documents['https://catalogue.example/type-metadata.json']),
      meta: { vct: PID_VCT },
    },
    {
      formatIdentifier: 'mso_mdoc',
      uri: 'https://catalogue.example/mdoc.json',
      integrity: integrity(documents['https://catalogue.example/mdoc.json']),
      meta: { doctype_value: 'eu.europa.ec.eudi.pid.1' },
    },
  ],
})

/** Serve the documents, from a buffer that holds more than each, as a response body may */
const serve = (documents: Record<string, string>) => async (url: string) => {
  const content = documents[url]
  if (content === undefined) throw new Error('404')
  const bytes = new TextEncoder().encode(`padding${content}`)
  return bytes.subarray('padding'.length)
}

const references = async (inspection: Inspection) =>
  inspection.signatures?.find(({ label }) => label === 'Referenced documents')?.verify(crypto)

describe('inspectAttestationSchema', () => {
  it('recognises a SchemaMeta as JSON and as JWS', () => {
    const json = JSON.stringify(schemaMeta())
    expect(detect(json)).toBe('attestation-schema')
    expect(detect(fakeJws({ typ: 'attestation-schema+jwt', alg: 'ES256' }, schemaMeta()))).toBe('attestation-schema')

    const inspection = inspectAttestationSchema(json)
    expect(inspection).toMatchObject({ kind: 'attestation-schema', issues: [], signatures: [] })
    expect(inspection.facts).toEqual([
      ['Attestation', 'https://catalogue.example/attestations/pid'],
      ['Version', '1.0.0'],
      ['Formats', `dc+sd-jwt (${PID_VCT}), mso_mdoc (eu.europa.ec.eudi.pid.1)`],
      ['Level of security', 'iso_18045_high'],
      ['Binding', 'key'],
    ])
    expect(inspection.notes).toContain(
      'The rulebook and the schemas are not fetched, so their integrity is not checked'
    )
  })

  it('reports the issues of the SchemaMeta at their element, and of the JWT', () => {
    const meta = { ...schemaMeta(), version: '1.0' }
    expect(inspectAttestationSchema(JSON.stringify(meta)).issues).toEqual([
      expect.objectContaining({ code: 'invalid_format', path: ['version'] }),
    ])

    const signed = inspectAttestationSchema(fakeJws({ typ: 'JWT', alg: 'ES256' }, meta))
    expect(signed.issues.map(({ code, path }) => ({ code, path }))).toEqual([
      { code: 'invalid_typ', path: ['header', 'typ'] },
      { code: 'invalid_format', path: ['payload', 'version'] },
    ])
    expect(signed.signatures?.map(({ label }) => label)).toEqual(['Signature'])
  })

  it('rejects JSON that is not a SchemaMeta', () => {
    expect(() => inspectAttestationSchema('{"vct": "x"}')).toThrow('it has no schemaURIs')
  })

  it('checks the rulebook and the schemas against their integrity', async () => {
    const inspection = inspectAttestationSchema(JSON.stringify(schemaMeta()), { loadReference: serve(DOCUMENTS) })
    expect(inspection.checks).toContain('Integrity of the rulebook and the schemas')
    await expect(references(inspection)).resolves.toEqual({
      status: 'valid',
      message: `Valid: the rulebook and the schemas of dc+sd-jwt and mso_mdoc match their integrity, and the type metadata is for ${PID_VCT}.`,
    })
  })

  it('reports a referenced document that does not match, and one that cannot be fetched', async () => {
    const check = (documents: Record<string, string>) =>
      references(inspectAttestationSchema(JSON.stringify(schemaMeta()), { loadReference: serve(documents) }))

    await expect(check({ ...DOCUMENTS, 'https://catalogue.example/rulebook.md': '# Another' })).resolves.toEqual({
      status: 'invalid',
      message: 'Invalid: the rulebook does not match rulebookIntegrity.',
    })
    await expect(check({ ...DOCUMENTS, 'https://catalogue.example/mdoc.json': '{}' })).resolves.toMatchObject({
      status: 'invalid',
      message: expect.stringContaining('integrity mismatch'),
    })

    // Type metadata of another vct, which matches the integrity the SchemaMeta gives for it
    const otherVct = { ...DOCUMENTS, 'https://catalogue.example/type-metadata.json': JSON.stringify({ vct: 'urn:x' }) }
    const meta = schemaMeta(otherVct)
    await expect(
      references(inspectAttestationSchema(JSON.stringify(meta), { loadReference: serve(otherVct) }))
    ).resolves.toMatchObject({
      status: 'invalid',
      message: expect.stringContaining('does not match the catalogue entry vct'),
    })

    const { 'https://catalogue.example/mdoc.json': _, ...missing } = DOCUMENTS
    await expect(check(missing)).resolves.toEqual({
      status: 'unverified',
      message: 'Not verified: https://catalogue.example/mdoc.json cannot be fetched: 404',
    })
  })
})
