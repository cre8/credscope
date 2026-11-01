import { base64url, hex } from '@owf/identity-common'
import { cborEncode, IssuerSigned } from '@owf/mdoc'
import { describe, expect, it } from 'vitest'
import { deviceResponse } from '../../test/fixtures/mdoc-device-response'
import { issuerSignedBytes } from '../../test/fixtures/mdoc-issuer-signed'
import { InspectionError, inspect } from '../index'
import { MDOC_CODES as CODES } from '../mdoc'
import { anchorOf } from '../paths'

const DIGEST_CODES: string[] = [CODES.DIGEST_MISMATCH, CODES.MISSING_DIGEST, CODES.MISSING_NAMESPACE_DIGESTS]

describe('mdoc inspection', () => {
  it('reads an IssuerSigned as bytes, base64url and hex, and matches every element digest', () => {
    for (const input of [issuerSignedBytes, base64url.encode(issuerSignedBytes), hex.encode(issuerSignedBytes)]) {
      const inspection = inspect(input)
      expect(inspection).toMatchObject({ kind: 'mdoc', title: 'mdoc IssuerSigned (ISO/IEC 18013-5)' })
      expect(inspection.issues.filter((issue) => DIGEST_CODES.includes(issue.code))).toEqual([])
    }

    const inspection = inspect(issuerSignedBytes)
    expect(inspection.facts?.[0]).toEqual(['Document type', 'org.iso.18013.5.1.mDL'])
    expect(inspection.value).toMatchObject({
      mso: { docType: 'org.iso.18013.5.1.mDL', validityInfo: { signed: expect.any(Date) } },
      issuerAuth: { x5chain: 1, certificate: { notBefore: expect.any(Date) } },
      namespaces: {
        'org.iso.18013.5.1': expect.arrayContaining([expect.objectContaining({ elementIdentifier: 'family_name' })]),
      },
    })
    for (const issue of inspection.issues) {
      expect(anchorOf(inspection.value, issue.path).missing).toEqual([])
    }
  })

  it('reports an element whose digest differs from the one in the MSO', () => {
    const issuerSigned = IssuerSigned.decode(issuerSignedBytes)
    const [namespace, items] = [...(issuerSigned.issuerNamespaces?.issuerNamespaces ?? [])][0]
    const random = items[0].random

    // Change the random of the first element in the encoded bytes
    const tampered = issuerSignedBytes.slice()
    const offset = tampered.findIndex((_, index) => random.every((byte, i) => tampered[index + i] === byte))
    tampered[offset] ^= 0xff

    expect(inspect(tampered).issues).toContainEqual(
      expect.objectContaining({ code: CODES.DIGEST_MISMATCH, path: ['namespaces', namespace, 0] })
    )
  })

  it('reads a DeviceResponse and checks each document', () => {
    const inspection = inspect(hex.encode(deviceResponse))
    expect(inspection).toMatchObject({ kind: 'mdoc', title: 'mdoc DeviceResponse (ISO/IEC 18013-5)' })
    expect(inspection.facts).toContainEqual(['Documents', 'org.iso.18013.5.1.mDL'])
    // The example dates from 2020, and its documentErrors are empty
    expect(inspection.issues.map(({ code, path }) => ({ code, path }))).toEqual([
      { code: CODES.EXPIRED, path: ['documents', 0, 'issuerSigned', 'mso', 'validityInfo', 'validUntil'] },
    ])
  })

  it('rejects CBOR that is not an mdoc', () => {
    expect(() => inspect(cborEncode(new Map([['foo', 1]])))).toThrow(InspectionError)
  })
})
