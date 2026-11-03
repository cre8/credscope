import { resolveSchemaReferences, type SchemaMeta, zSchemaMeta } from '@owf/eudi-attestation-schema'
import {
  base64,
  compareBytes,
  decodeJwt,
  parseWithSchema,
  prefixIssuePaths,
  type ValidationIssue,
} from '@owf/identity-common'
import { type DocumentInput, errorMessage, isRecord, JWS, toText } from './input'
import { type Inspection, InspectionError, type SignatureCheck, type SignatureResult } from './inspection'
import { jwtIssues } from './jwt'
import { jwsSignatureCheck } from './signature'

/** The `typ` of a signed SchemaMeta */
export const ATTESTATION_SCHEMA_TYP = 'attestation-schema+jwt'

export interface AttestationSchemaOptions {
  /** The key or certificates of the signer of a signed SchemaMeta */
  key?: string
  /**
   * Fetch the rulebook and the schemas the SchemaMeta references, to check them against their
   * integrity. Resolves with the bytes at a URL.
   */
  loadReference?: (url: string) => Promise<Uint8Array>
}

const issueKey = (issue: ValidationIssue) => `${issue.code}|${issue.path.join('.')}`

/** Whether the bytes have the digest of a `sha256-<base64>` SRI value, which the schema has checked */
async function matchesIntegrity(bytes: Uint8Array, integrity: string, crypto: Crypto): Promise<boolean> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', Uint8Array.from(bytes)))
  return compareBytes(digest, base64.decode(integrity.trim().slice('sha256-'.length)))
}

/**
 * Fetch the rulebook and the schemas of the SchemaMeta and check them against their integrity.
 * A schema of `dc+sd-jwt` that is SD-JWT VC Type Metadata is checked with the documents it
 * extends, and has to be for the `vct` of the SchemaMeta.
 */
async function verifyReferences(
  schemaMeta: SchemaMeta,
  loadReference: (url: string) => Promise<Uint8Array>,
  crypto: Crypto
): Promise<SignatureResult> {
  let unreachable: string | undefined
  const load = async (url: string) => {
    try {
      // A copy of its own: @owf/eudi-attestation-schema hashes the whole buffer of the bytes
      return Uint8Array.from(await loadReference(url))
    } catch (error) {
      const message = errorMessage(error)
      unreachable = message.includes(url) ? message : `${url} cannot be fetched: ${message}`
      throw error
    }
  }
  try {
    if (!(await matchesIntegrity(await load(schemaMeta.rulebookURI), schemaMeta.rulebookIntegrity, crypto))) {
      return { status: 'invalid', message: `Invalid: the rulebook does not match rulebookIntegrity.` }
    }
    const references = await resolveSchemaReferences({
      schemaMeta,
      resolve: async (uri) => ({ content: await load(uri) }),
    })
    const typeMetadata = references.flatMap((reference) => (reference.typeMetadata ? [reference.typeMetadata.vct] : []))
    return {
      status: 'valid',
      message: `Valid: the rulebook and the schemas of ${references.map((reference) => reference.format).join(' and ')} match their integrity${typeMetadata.length ? `, and the type metadata is for ${typeMetadata.join(', ')}` : ''}.`,
    }
  } catch (error) {
    if (unreachable) return { status: 'unverified', message: `Not verified: ${unreachable}` }
    return { status: 'invalid', message: `Invalid: ${errorMessage(error)}` }
  }
}

/** The facts of the SchemaMeta, as far as it has them */
function schemaMetaFacts(document: Record<string, unknown>): [string, string][] {
  const facts: [string, string][] = []
  const text = (value: unknown) => (typeof value === 'string' ? value : undefined)
  const add = (label: string, value: string | undefined) => {
    if (value) facts.push([label, value])
  }
  add('Attestation', text(document.id))
  add('Version', text(document.version))
  const formats = (Array.isArray(document.schemaURIs) ? document.schemaURIs : []).flatMap((schemaUri) => {
    if (!isRecord(schemaUri) || typeof schemaUri.formatIdentifier !== 'string') return []
    const meta = isRecord(schemaUri.meta) ? schemaUri.meta : {}
    const type = text(meta.vct) ?? text(meta.doctype_value)
    return [type ? `${schemaUri.formatIdentifier} (${type})` : schemaUri.formatIdentifier]
  })
  add('Formats', formats.join(', '))
  add('Level of security', text(document.attestationLoS))
  add('Binding', text(document.bindingType))
  return facts
}

/**
 * Parse the SchemaMeta of an attestation of the EUDI catalogue of attestations (TS11), as JSON
 * or as a JWS, check it, verify its signature and, when asked to, the integrity of the rulebook
 * and the schemas it references.
 */
export function inspectAttestationSchema(input: DocumentInput, options: AttestationSchemaOptions = {}): Inspection {
  const text = toText(input)
  if (!text) throw new InspectionError('There is nothing to inspect')

  let document: unknown
  let header: Record<string, unknown> | undefined
  if (JWS.test(text)) {
    try {
      ;({ header, payload: document } = decodeJwt<Record<string, unknown>, Record<string, unknown>>(text))
    } catch (error) {
      throw new InspectionError(`This looks like a JWS, but it cannot be decoded: ${errorMessage(error)}`)
    }
  } else {
    try {
      document = JSON.parse(text)
    } catch (error) {
      throw new InspectionError(`An attestation schema is JSON or a JWS, and this is neither: ${errorMessage(error)}`)
    }
  }
  if (!isRecord(document) || !('schemaURIs' in document)) {
    throw new InspectionError('This is not the SchemaMeta of an attestation, as it has no schemaURIs')
  }

  const result = parseWithSchema(zSchemaMeta, document)
  const schemaIssues = result.success ? [] : result.issues
  const checks = ['TS11 SchemaMeta']
  const notes: string[] = []
  const signatures: SignatureCheck[] = []

  let issues: ValidationIssue[] = schemaIssues
  if (header) {
    checks.push(`${ATTESTATION_SCHEMA_TYP} header and claims`)
    const jwt = jwtIssues(header, document, { typ: [ATTESTATION_SCHEMA_TYP] })
    // iat is a claim of the JWT and a member of the SchemaMeta, so it is reported once
    const reported = new Set(jwt.map(issueKey))
    issues = [...jwt, ...prefixIssuePaths('payload', schemaIssues).filter((issue) => !reported.has(issueKey(issue)))]
    signatures.push(jwsSignatureCheck(text, header, options.key))
  } else {
    notes.push('Unsigned JSON, so there is no signature to verify')
  }

  const { loadReference } = options
  if (!loadReference) {
    notes.push('The rulebook and the schemas are not fetched, so their integrity is not checked')
  } else if (!result.success) {
    notes.push('The rulebook and the schemas are not fetched, as the SchemaMeta is invalid')
  } else {
    checks.push('Integrity of the rulebook and the schemas')
    const schemaMeta = result.data
    signatures.push({
      label: 'Referenced documents',
      verify: (crypto) => verifyReferences(schemaMeta, loadReference, crypto),
    })
  }

  return {
    kind: 'attestation-schema',
    title: 'Attestation schema (TS11 SchemaMeta)',
    checks,
    notes,
    value: header ? { header, payload: document } : document,
    issues,
    facts: schemaMetaFacts(document),
    signatures,
  }
}
