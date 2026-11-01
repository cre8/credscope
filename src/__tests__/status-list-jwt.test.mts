import { createHeaderAndPayload, type JWT_STATUS_LIST_TYPE, StatusList } from '@owf/token-status-list'
import { describe, expect, it } from 'vitest'
import { STATUS_LIST_VALIDATION_CODES as CODES, validateStatusListJwt } from '../status-list-jwt'

const NOW = new Date('2026-06-01T00:00:00Z')
const IAT = Math.floor(NOW.getTime() / 1000) - 60
const URI = 'https://example.com/statuslists/1'

function token(claims: Record<string, unknown> = {}) {
  const list = new StatusList([0, 1, 2, 0, 0, 0, 0, 0], 2)
  const { header, payload } = createHeaderAndPayload(
    list,
    { iss: 'https://example.com', sub: URI, iat: IAT, exp: IAT + 3600, ttl: 300 },
    { alg: 'ES256', typ: '' as typeof JWT_STATUS_LIST_TYPE }
  )
  return { header: header as Record<string, unknown>, payload: { ...payload, ...claims } as Record<string, unknown> }
}

const codes = (result: ReturnType<typeof validateStatusListJwt>) => result.issues.map((issue) => issue.code)

describe('validateStatusListJwt', () => {
  it('accepts a conforming token and returns its status list', () => {
    const { header, payload } = token()
    const result = validateStatusListJwt(header, payload, { uri: URI, now: NOW })

    expect(result).toMatchObject({ valid: true, issues: [] })
    expect(result.statusList?.getStatus(1)).toBe(1)
    expect(result.statusList?.getStatus(2)).toBe(2)
  })

  it('accepts typ in its full media type form', () => {
    const { header, payload } = token()
    const result = validateStatusListJwt({ ...header, typ: 'application/statuslist+jwt' }, payload, { now: NOW })
    expect(result.valid).toBe(true)
  })

  it('reports each problem as a issue with its path and section', () => {
    const { payload } = token()
    const result = validateStatusListJwt(
      { typ: 'JWT' },
      { ...payload, sub: undefined, iat: 'yesterday', ttl: -1, status_list: { bits: 3, lst: '***' } },
      { now: NOW }
    )

    expect(result.valid).toBe(false)
    expect(result.statusList).toBeUndefined()
    expect(result.issues).toEqual([
      {
        severity: 'error',
        code: CODES.INVALID_TYP,
        path: ['header', 'typ'],
        message: 'typ is JWT, it must be statuslist+jwt',
        requirement: 'Section 5.1',
        context: { expected: ['statuslist+jwt'], actual: 'JWT' },
      },
      expect.objectContaining({ code: CODES.MISSING_ALG, path: ['header', 'alg'] }),
      expect.objectContaining({ code: CODES.MISSING_SUBJECT, path: ['payload', 'sub'] }),
      expect.objectContaining({ code: CODES.INVALID_TIME_CLAIM, path: ['payload', 'iat'] }),
      expect.objectContaining({ code: CODES.INVALID_TTL, path: ['payload', 'ttl'] }),
      expect.objectContaining({ code: CODES.INVALID_BITS, path: ['payload', 'status_list', 'bits'] }),
      expect.objectContaining({ code: CODES.INVALID_LST, path: ['payload', 'status_list', 'lst'] }),
    ])
  })

  it('reports the recommended exp and ttl as warnings', () => {
    const { header, payload } = token({ exp: undefined, ttl: undefined })
    const result = validateStatusListJwt(header, payload, { now: NOW })

    expect(result.valid).toBe(true)
    expect(result.issues.map(({ severity, code }) => ({ severity, code }))).toEqual([
      { severity: 'warning', code: CODES.MISSING_EXPIRATION_TIME },
      { severity: 'warning', code: CODES.MISSING_TTL },
    ])
  })

  it('compares sub with the uri when one is given', () => {
    const { header, payload } = token()
    expect(codes(validateStatusListJwt(header, payload, { uri: 'https://example.com/other', now: NOW }))).toEqual([
      CODES.SUBJECT_MISMATCH,
    ])
    expect(validateStatusListJwt(header, payload, { now: NOW }).valid).toBe(true)
  })

  it('checks the validity window against now, within the clock skew', () => {
    const { header, payload } = token({ nbf: IAT + 7200 })
    const later = new Date((IAT + 3600 + 31) * 1000)

    expect(codes(validateStatusListJwt(header, payload, { now: later }))).toEqual([CODES.NOT_YET_VALID, CODES.EXPIRED])
    expect(codes(validateStatusListJwt(header, payload, { now: new Date((IAT + 3600 + 29) * 1000) }))).toEqual([
      CODES.NOT_YET_VALID,
    ])
    expect(validateStatusListJwt(header, payload, { now: false }).valid).toBe(true)
  })

  it('rejects exp before iat and iat in the future', () => {
    const { header, payload } = token({ iat: IAT + 7200, exp: IAT + 3600 })
    expect(codes(validateStatusListJwt(header, payload, { now: NOW }))).toEqual([
      CODES.EXPIRES_BEFORE_ISSUED,
      CODES.ISSUED_IN_FUTURE,
    ])
  })

  it('rejects an lst that does not decompress and an invalid aggregation_uri', () => {
    const { header, payload } = token({ status_list: { bits: 1, lst: 'AAAA', aggregation_uri: 'not a uri' } })
    const result = validateStatusListJwt(header, payload, { now: NOW })

    expect(codes(result)).toEqual([CODES.INVALID_AGGREGATION_URI, CODES.INVALID_LST])
    expect(result.issues[1].message).toBe('lst is not a ZLIB compressed byte array')
  })

  it('reports a header or payload that is not an object', () => {
    const result = validateStatusListJwt('header', null)
    expect(result.issues.map((issue) => issue.path)).toEqual([['header'], ['payload']])
    expect(codes(result)).toEqual([CODES.INVALID_STRUCTURE, CODES.INVALID_STRUCTURE])
  })
})
