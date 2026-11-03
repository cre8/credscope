import { JadesProfile, type ProtectedHeaderParams, validateProfile, zProtectedHeader } from '@owf/eudi-jades'
import {
  type CommonValidationCode,
  parseWithSchema,
  prefixIssuePaths,
  type SchemaValidationCode,
  type ValidationIssueOf,
  type ValidationSeverity,
} from '@owf/identity-common'

/** An issue of the JAdES check, with a schema code */
export type JadesIssue = ValidationIssueOf<CommonValidationCode | SchemaValidationCode>

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
  const result = parseWithSchema(zProtectedHeader, header)
  const issues: JadesIssue[] = result.success ? [] : result.issues
  // The checks beyond the schema, e.g. of a time-stamp in adoTst, which only give messages
  if (result.success) {
    for (const message of validateProfile(header as ProtectedHeaderParams, JadesProfile.B_B).missing ?? []) {
      issues.push({ severity: 'error', code: 'invalid_value', path: [], message })
    }
  }
  return {
    baselineB: issues.length === 0,
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
