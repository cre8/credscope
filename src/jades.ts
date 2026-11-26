import { JadesProfile, type JadesValidationIssue, type ProtectedHeaderParams, validateProfile } from '@owf/eudi-jades'
import { prefixIssuePaths, type ValidationSeverity } from '@owf/identity-common'

/** An issue of the JAdES check, with a JAdES or a schema code */
export type JadesIssue = JadesValidationIssue

export interface JadesCheck {
  /** Whether the header meets the JAdES baseline B-B level */
  baselineB: boolean
  /** What keeps it from meeting it, with paths starting at `header` */
  issues: JadesIssue[]
}

/**
 * Check the protected header of a compact JWS against the JAdES baseline B-B level of ETSI TS
 * 119 182-1. A compact JWS has no unprotected header, so it cannot carry the components of the
 * levels above.
 *
 * @param severity Of the issues: `error` where a specification requires a JAdES signature
 * @param requirement The requirement of that specification
 */
export function checkJades(
  header: Record<string, unknown>,
  { severity = 'error', requirement }: { severity?: ValidationSeverity; requirement?: string } = {}
): JadesCheck {
  // The schema of the protected header and the checks beyond it, e.g. of a time-stamp in adoTst
  const result = validateProfile(header as ProtectedHeaderParams, JadesProfile.B_B)
  // A compact JWS has only the protected header, which `header` names here
  const issues = result.issues.map((issue) =>
    issue.path[0] === 'protected'
      ? { ...issue, path: issue.path.slice(1), ...(issue.pathLabels && { pathLabels: issue.pathLabels.slice(1) }) }
      : issue
  )
  return {
    baselineB: result.valid,
    issues: prefixIssuePaths('header', issues).map((issue) => ({
      ...issue,
      severity,
      message: `JAdES baseline B-B: ${issue.message}`,
      ...(requirement ? { requirement } : {}),
    })),
  }
}

/** The fact of a JAdES check, to show with the others */
export const jadesFact = ({ baselineB }: JadesCheck): [string, string] => [
  'JAdES',
  baselineB ? 'Baseline B-B (ETSI TS 119 182-1)' : 'Not a JAdES baseline B-B signature',
]
