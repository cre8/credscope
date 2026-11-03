import { parseWithSchema, prefixIssuePaths, zTyp } from '@owf/identity-common'
import {
  assertCriticalHeaderParameters,
  JoseValidationError,
  type JoseValidationIssue,
  type JwsProtectedHeader,
  type JwtPayload,
  type VerifyJwtClaimsOptions,
  verifyJwtClaims,
  zJwtHeader,
  zJwtPayload,
} from '@owf/jose'
import { isRecord } from './input'

// The checks of a JWT are those of @owf/jose, which throws at the first part that does not
// validate. These run each part on its own, so every issue is reported.

/** The issues of a check of @owf/jose, which throws them */
function issuesOf(check: () => void): JoseValidationIssue[] {
  try {
    check()
    return []
  } catch (error) {
    if (error instanceof JoseValidationError) return error.issues
    throw error
  }
}

const issueKey = (issue: JoseValidationIssue) => `${issue.code}|${issue.path.join('.')}`

/**
 * The issues of the header of a JWT: its parameters (RFC 7515), `crit`, and `typ` when it has to
 * be one of the given media types
 */
export function jwtHeaderIssues(header: unknown, typ?: [string, ...string[]]): JoseValidationIssue[] {
  const result = parseWithSchema(zJwtHeader, header)
  const issues = result.success ? [] : result.issues
  // Also when another parameter is invalid; a crit that is not a list of names is a schema issue
  if (isRecord(header) && Array.isArray(header.crit) && header.crit.every((name) => typeof name === 'string')) {
    const protectedHeader = header as JwsProtectedHeader
    issues.push(...issuesOf(() => assertCriticalHeaderParameters({ protectedHeader })))
  }
  if (typ && isRecord(header)) {
    const typResult = parseWithSchema(zTyp(...typ), header.typ)
    if (!typResult.success) issues.push(...prefixIssuePaths('typ', typResult.issues))
  }
  return issues
}

/**
 * The issues of the claims of a JWT: the registered claims (RFC 7519), and the claims against the
 * time and the values the verifier expects, see `verifyJwtClaims` of @owf/jose
 */
export function jwtClaimsIssues(payload: unknown, options?: VerifyJwtClaimsOptions): JoseValidationIssue[] {
  const result = parseWithSchema(zJwtPayload, payload)
  const issues = result.success ? [] : result.issues
  if (!isRecord(payload)) return issues
  // A time claim that is not a number is also a schema issue, so it is reported once
  const reported = new Set(issues.map(issueKey))
  for (const issue of issuesOf(() => verifyJwtClaims(payload as JwtPayload, options))) {
    if (!reported.has(issueKey(issue))) issues.push(issue)
  }
  return issues
}

/** What a type of JWT requires beyond RFC 7515 and RFC 7519 */
export interface JwtProfile {
  /** The media types `typ` has to be one of */
  typ?: [string, ...string[]]
  /** The checks of the claims against the time and the values the verifier expects */
  claims?: VerifyJwtClaimsOptions
}

/**
 * The issues of the header and the claims of a JWT, with paths that start at `header` or
 * `payload`. The signature is not verified.
 */
export function jwtIssues(header: unknown, payload: unknown, { typ, claims }: JwtProfile = {}): JoseValidationIssue[] {
  return [
    ...prefixIssuePaths('header', jwtHeaderIssues(header, typ)),
    ...prefixIssuePaths('payload', jwtClaimsIssues(payload, claims)),
  ]
}
