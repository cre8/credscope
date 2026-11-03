import { examples } from '../examples/attestation-schema'
import { inspectAttestationSchemaPage } from '../inspectors'
import { startPage } from '../page'

startPage({ format: 'attestation-schema', inspect: inspectAttestationSchemaPage, examples })
