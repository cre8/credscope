import {
  base64url,
  type CommonValidationCode,
  toValidationResult,
  VALIDATION_CODES,
  type ValidationIssueOf,
  type ValidationResult,
  type ValidationSeverity,
} from '@owf/identity-common'
import type { JoseValidationIssue } from '@owf/jose'
import { type BitsPerStatus, JWT_STATUS_LIST_TYPE, StatusList } from '@owf/token-status-list'
import { isRecord } from './input'
import { jwtIssues } from './jwt'

/**
 * Codes of the issues of {@link validateStatusListJwt} beyond those of the JWT checks of
 * @owf/jose, with the section of draft-ietf-oauth-status-list-16 as `requirement` where a check
 * has one.
 */
export const STATUS_LIST_VALIDATION_CODES = {
  /** `exp` is missing, which is RECOMMENDED (Section 5.1) */
  MISSING_EXPIRATION_TIME: 'missing_expiration_time',
  /** `exp` is at or before `iat` */
  EXPIRES_BEFORE_ISSUED: VALIDATION_CODES.EXPIRES_BEFORE_ISSUED,
  /** `ttl` is missing, which is RECOMMENDED (Section 5.1) */
  MISSING_TTL: 'missing_ttl',
  /** `ttl` is not a positive number (Section 5.1) */
  INVALID_TTL: 'invalid_ttl',
  /** `status_list` is missing or not an object (Section 5.1) */
  MISSING_STATUS_LIST: 'missing_status_list',
  /** `bits` is not 1, 2, 4 or 8 (Section 4.2) */
  INVALID_BITS: 'invalid_bits',
  /** `lst` is not a base64url encoded, ZLIB compressed byte array (Section 4.2) */
  INVALID_LST: 'invalid_lst',
  /** `aggregation_uri` is not a URI (Section 4.2) */
  INVALID_AGGREGATION_URI: 'invalid_aggregation_uri',
} as const

/** A code of a issue of {@link validateStatusListJwt} beyond those of the JWT checks */
export type StatusListValidationCode = (typeof STATUS_LIST_VALIDATION_CODES)[keyof typeof STATUS_LIST_VALIDATION_CODES]

/**
 * An issue of {@link validateStatusListJwt}: of the JWT checks of @owf/jose, e.g. `invalid_typ`,
 * `claim_missing` or `expired`, or with a code of {@link STATUS_LIST_VALIDATION_CODES}
 */
export type StatusListIssue = ValidationIssueOf<StatusListValidationCode> | JoseValidationIssue

export interface ValidateStatusListJwtOptions {
  /** The `uri` of the status list reference the token was fetched for. Without it, `sub` is not compared. */
  uri?: string
  /** Reference time for `iat`, `nbf` and `exp`; defaults to now. Pass `false` to skip these checks. */
  now?: Date | false
  /** Clock tolerance applied to `iat`, `nbf` and `exp`, in seconds. Defaults to 30. */
  skewSeconds?: number
}

/** `valid` when none of the issues, with paths starting at `header` or `payload`, is an error */
export interface StatusListJwtValidationResult extends ValidationResult<StatusListIssue> {
  /** The status list, when `bits` and `lst` could be decoded */
  statusList?: StatusList
}

const C = STATUS_LIST_VALIDATION_CODES
const BITS: readonly number[] = [1, 2, 4, 8] satisfies BitsPerStatus[]
const BASE64URL = /^[A-Za-z0-9_-]*$/

// The JWT checks that Section 5.1 requires of a Status List Token
const SECTION_5_1 = new Set([
  'invalid_typ|header.typ',
  'claim_missing|payload.sub',
  'claim_value_mismatch|payload.sub',
  'claim_missing|payload.iat',
])

// Not URL.canParse, which not every runtime of the package has
function isUri(value: string): boolean {
  try {
    new URL(value)
    return true
  } catch {
    return false
  }
}

/**
 * Check the header and the claims of a Status List Token in JWT format, reporting every
 * problem as a issue rather than throwing at the first one. Use it to inspect a token;
 * a verifier uses `verifyStatusListJwtHeader` and `verifyStatusListJwtClaims` of
 * @owf/token-status-list after verifying the signature, which this does not do.
 *
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-5.1
 */
export function validateStatusListJwt(
  header: unknown,
  payload: unknown,
  { uri, now = new Date(), skewSeconds = 30 }: ValidateStatusListJwtOptions = {}
): StatusListJwtValidationResult {
  const issues: StatusListIssue[] = jwtIssues(header, payload, {
    typ: [JWT_STATUS_LIST_TYPE],
    claims: {
      ...(now === false
        ? { checkExpirationTime: false, checkNotBefore: false, checkIssuedAt: false }
        : { now, skewSeconds }),
      requiredClaims: ['sub', 'iat'],
      expectedSubject: uri,
    },
  }).map((issue) =>
    SECTION_5_1.has(`${issue.code}|${issue.path.join('.')}`) ? { ...issue, requirement: 'Section 5.1' } : issue
  )
  const add = (
    severity: ValidationSeverity,
    code: Exclude<StatusListValidationCode, CommonValidationCode>,
    path: (string | number)[],
    message: string,
    requirement?: string
  ) => issues.push({ severity, code, path, message, ...(requirement ? { requirement } : {}) })
  const result = (statusList?: StatusList): StatusListJwtValidationResult => ({
    ...toValidationResult(issues),
    ...(statusList ? { statusList } : {}),
  })
  if (!isRecord(header) || !isRecord(payload)) return result()

  // Times, beyond those @owf/jose checks against now
  if (payload.exp === undefined) {
    add('warning', C.MISSING_EXPIRATION_TIME, ['payload', 'exp'], 'exp is missing, which is RECOMMENDED', 'Section 5.1')
  }
  const { iat, exp } = payload
  if (typeof iat === 'number' && typeof exp === 'number' && exp <= iat) {
    issues.push({
      severity: 'error',
      code: C.EXPIRES_BEFORE_ISSUED,
      path: ['payload', 'exp'],
      message: 'exp must be after iat',
      context: { issuedAt: new Date(iat * 1000), expiresAt: new Date(exp * 1000) },
    })
  }

  // Time to live
  const { ttl } = payload
  if (ttl === undefined) {
    add('warning', C.MISSING_TTL, ['payload', 'ttl'], 'ttl is missing, which is RECOMMENDED', 'Section 5.1')
  } else if (typeof ttl !== 'number' || !(ttl > 0)) {
    add('error', C.INVALID_TTL, ['payload', 'ttl'], 'ttl must be a positive number of seconds', 'Section 5.1')
  }

  // Status list
  const statusList = payload.status_list
  if (!isRecord(statusList)) {
    add('error', C.MISSING_STATUS_LIST, ['payload', 'status_list'], 'status_list must be an object', 'Section 5.1')
    return result()
  }
  const { bits, lst, aggregation_uri: aggregationUri } = statusList
  const path = ['payload', 'status_list']
  const validBits = typeof bits === 'number' && BITS.includes(bits)
  if (!validBits) {
    add('error', C.INVALID_BITS, [...path, 'bits'], 'bits must be 1, 2, 4 or 8', 'Section 4.2')
  }
  if (aggregationUri !== undefined && (typeof aggregationUri !== 'string' || !isUri(aggregationUri))) {
    add(
      'error',
      C.INVALID_AGGREGATION_URI,
      [...path, 'aggregation_uri'],
      'aggregation_uri must be a URI',
      'Section 4.2'
    )
  }

  if (typeof lst !== 'string' || !BASE64URL.test(lst)) {
    add('error', C.INVALID_LST, [...path, 'lst'], 'lst must be a base64url encoded string', 'Section 4.2')
    return result()
  }
  if (!validBits) return result()
  try {
    return result(
      StatusList.decompressStatusListFromBytes(
        base64url.decode(lst),
        bits as BitsPerStatus,
        typeof aggregationUri === 'string' ? aggregationUri : undefined
      )
    )
  } catch {
    add('error', C.INVALID_LST, [...path, 'lst'], 'lst is not a ZLIB compressed byte array', 'Section 4.2')
    return result()
  }
}
