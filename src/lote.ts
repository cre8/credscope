import { LOTE_TYPES, LOTE_VALIDATION_CODES, LoteProfile, validateLote, validateLoteProfile } from '@owf/eudi-lote'
import { decodeJwt, prefixIssuePaths, type ValidationIssue } from '@owf/identity-common'
import { type DocumentInput, errorMessage, isRecord, JWS, toText } from './input'
import { type Inspection, InspectionError } from './inspection'
import { checkJades, jadesFact } from './jades'
import { jwsSignatureCheck } from './signature'

export interface LoTEOptions {
  /** The key or certificates of the signer of a LoTE JWS */
  key?: string
}

const issueKey = (issue: ValidationIssue) => `${issue.code}|${issue.path.join('.')}`

/** The annex of TS 119 602 of each EU profile, whose clause 4 requires a compact JAdES baseline B signature */
const PROFILE_ANNEXES: Partial<Record<LoteProfile, string>> = {
  [LoteProfile.EuPidProvidersList]: 'D',
  [LoteProfile.EuWalletProvidersList]: 'E',
  [LoteProfile.EuWrpacProvidersList]: 'F',
  [LoteProfile.EuWrprcProvidersList]: 'G',
  [LoteProfile.EuPubEaaProvidersList]: 'H',
}

/** Parse an ETSI TS 119 602 List of Trusted Entities, as JSON or JWS, and check it and its profile */
export function inspectLoTE(input: DocumentInput, options: LoTEOptions = {}): Inspection {
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
      throw new InspectionError(`A LoTE is JSON or a JWS, and this is neither: ${errorMessage(error)}`)
    }
  }
  if (!isRecord(document) || !('LoTE' in document)) {
    throw new InspectionError('This is not a LoTE document, as it has no LoTE property')
  }

  const structure = validateLote(document)
  const issues = [...structure.issues]
  const checks = ['ETSI TS 119 602 structure']
  const notes: string[] = []
  const facts: [string, string][] = []

  // Only the profile of the LoTEType reports more than a LoTEType mismatch
  const matched = Object.values(LoteProfile)
    .map((profile) => ({ profile, result: validateLoteProfile(document, profile) }))
    .find(
      ({ result }) =>
        result.valid || result.issues.some((issue) => issue.code !== LOTE_VALIDATION_CODES.UNEXPECTED_LOTE_TYPE)
    )
  if (matched) {
    // Named as in its LoTEType, e.g. EUWRPACProvidersList
    checks.push(`${LOTE_TYPES[matched.profile].split('/').pop()} profile`)
    // The profile schemas extend the structure schema, so skip what it already reported
    const reported = new Set(issues.map(issueKey))
    issues.push(...matched.result.issues.filter((issue) => !reported.has(issueKey(issue))))
    // A Pub-EAA Providers List can list withdrawn services (TS 119 602 H), which are not to be trusted
    if (matched.result.valid && 'notifiedTrustedEntities' in matched.result) {
      const listed = matched.result.lote.LoTE.TrustedEntitiesList?.length ?? 0
      facts.push(['Notified trusted entities', `${matched.result.notifiedTrustedEntities.length} of ${listed}`])
    }
  } else {
    notes.push('No profile check, as the LoTEType is not the one of an EU profile')
  }
  if (!header) notes.push('Unsigned JSON, so there is no signature to verify')

  // A list of another type is not required to have a JAdES signature, so it gets warnings only
  const annex = matched && PROFILE_ANNEXES[matched.profile]
  const jades = header && checkJades(header, annex ? { requirement: `Clause ${annex}.4` } : { severity: 'warning' })
  if (jades) {
    checks.push('ETSI TS 119 182-1 JAdES baseline B-B')
    facts.unshift(jadesFact(jades))
  }

  return {
    kind: 'lote',
    title: 'List of Trusted Entities (ETSI TS 119 602)',
    checks,
    notes,
    value: header ? { header, payload: document } : document,
    issues: jades ? [...jades.issues, ...prefixIssuePaths('payload', issues)] : issues,
    facts,
    signatures: header ? [jwsSignatureCheck(text, header, options.key)] : undefined,
  }
}
