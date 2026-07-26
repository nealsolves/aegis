import assert from 'node:assert/strict'
import test from 'node:test'
import { assertExpectedApiResponses } from './smoke-architecture.mjs'

const CONTRACT_BODY = { api_contract_version: '1' }

test('accepts successful contract-one health and manifest traffic at the expected origin', () => {
  assert.doesNotThrow(() => assertExpectedApiResponses(
    [
      {
        url: 'http://127.0.0.1:8000/health',
        status: 200,
        body: CONTRACT_BODY,
      },
      {
        url: 'http://127.0.0.1:8000/api/demo/manifest',
        status: 200,
        body: CONTRACT_BODY,
      },
    ],
    'http://127.0.0.1:8000',
    'desktop',
  ))
})

test('rejects a frontend compiled for a different local API origin', () => {
  assert.throws(
    () => assertExpectedApiResponses(
      [
        {
          url: 'http://127.0.0.1:9000/health',
          status: 200,
          body: CONTRACT_BODY,
        },
        {
          url: 'http://127.0.0.1:9000/api/demo/manifest',
          status: 200,
          body: CONTRACT_BODY,
        },
      ],
      'http://127.0.0.1:8000',
      'phone',
    ),
    /expected API origin http:\/\/127\.0\.0\.1:8000.*127\.0\.0\.1:9000/i,
  )
})

test('rejects unsuccessful or incompatible browser API responses', () => {
  assert.throws(
    () => assertExpectedApiResponses(
      [
        {
          url: 'http://127.0.0.1:8000/health',
          status: 503,
          body: CONTRACT_BODY,
        },
        {
          url: 'http://127.0.0.1:8000/api/demo/manifest',
          status: 200,
          body: { api_contract_version: '2' },
        },
      ],
      'http://127.0.0.1:8000',
      'desktop',
    ),
    /health returned HTTP 503/i,
  )
})
