import { base64url } from '@owf/identity-common'
import { JWT_STATUS_LIST_TYPE, type StatusList } from '@owf/token-status-list'

/**
 * The header and payload of a Status List Token in JWT format carrying `list`, without signing it.
 * `@owf/token-status-list` only makes signed tokens; the tests and examples sign or fake the signature themselves.
 */
export function statusListHeaderAndPayload(
  list: StatusList,
  payload: Record<string, unknown>,
  header: Record<string, unknown> & { alg: string }
) {
  return {
    header: { ...header, typ: JWT_STATUS_LIST_TYPE } as Record<string, unknown> & { alg: string; typ: string },
    payload: {
      ...payload,
      status_list: {
        bits: list.getBitsPerStatus(),
        lst: base64url.encode(list.compressStatusListToBytes()),
        ...(list.aggregationUri !== undefined && { aggregation_uri: list.aggregationUri }),
      },
    } as Record<string, unknown>,
  }
}
