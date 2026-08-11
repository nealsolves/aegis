import {
  formatPublicDemoError,
  parsePublicApiError,
  parsePublicDemoError,
} from '@/lib/publicError'

const REQUEST_ID = 'a'.repeat(32)

describe('public demo errors', () => {
  it('parses and formats only a complete safe envelope', () => {
    const value = {
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Please try again shortly.',
      request_id: REQUEST_ID,
      diagnostic: '/private/secret',
    }

    expect(parsePublicDemoError(value)).toEqual({
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Please try again shortly.',
      request_id: REQUEST_ID,
    })
    expect(formatPublicDemoError(value)).toBe(
      `Please try again shortly. (request ${REQUEST_ID})`,
    )
  })

  it.each([
    null,
    'hostile',
    { code: 'bad-code', message: 'safe', request_id: REQUEST_ID },
    { code: 'SAFE', message: '', request_id: REQUEST_ID },
    { code: 'SAFE', message: 'bad\nmessage', request_id: REQUEST_ID },
    { code: 'SAFE', message: 'safe', request_id: '/private/secret' },
    { code: 'SAFE', message: 'safe' },
  ])('rejects malformed public errors', (value) => {
    expect(parsePublicDemoError(value)).toBeNull()
    expect(formatPublicDemoError(value)).toBeNull()
  })

  it('reads only a validated detail envelope from non-2xx JSON', async () => {
    const response = new Response(JSON.stringify({
      detail: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'Please try again shortly.',
        request_id: REQUEST_ID,
      },
      traceback: '/private/secret',
    }), { status: 429, statusText: '/private/secret' })

    await expect(parsePublicApiError(response)).resolves.toBe(
      `Please try again shortly. (request ${REQUEST_ID})`,
    )
  })

  it.each([
    new Response('not json', { status: 500, statusText: '/private/secret' }),
    new Response('{"detail":"/private/secret"}', { status: 500 }),
    new Response(JSON.stringify({
      detail: { code: 'SAFE', message: '/private/secret' },
    }), { status: 503 }),
  ])('falls back without echoing an unknown body or status text', async (response) => {
    await expect(parsePublicApiError(response)).resolves.toBe(
      `Request failed (${response.status}).`,
    )
  })
})
