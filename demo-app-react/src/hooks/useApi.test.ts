import { renderHook, act, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import { useApi } from '@/hooks/useApi'
import { AigcProvider } from '@/context/AigcContext'

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((res) => {
    resolve = res
  })
  return { promise, resolve }
}

describe('useApi', () => {
  it('starts idle', () => {
    const { result } = renderHook(() => useApi(), { wrapper: AigcProvider })
    expect(result.current.loading).toBe(false)
    expect(result.current.error).toBeNull()
  })

  it('returns data on success', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce({
      ok: true,
      json: async () => ({ status: 'ok' }),
    }))

    const { result } = renderHook(() => useApi<{ status: string }>(), { wrapper: AigcProvider })
    let data: { status: string } | null = null
    await act(async () => { data = await result.current.call('/health') })
    expect(data).toEqual({ status: 'ok' })
    expect(result.current.loading).toBe(false)
    vi.unstubAllGlobals()
  })

  it('sets error on fetch failure', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValueOnce(new Error('Network error')))

    const { result } = renderHook(() => useApi(), { wrapper: AigcProvider })
    await act(async () => { await result.current.call('/health') })
    await waitFor(() => expect(result.current.error).toBe('Network error'))
    vi.unstubAllGlobals()
  })

  it('uses only a complete safe API error envelope', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      detail: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'Please try again shortly.',
        request_id: 'a'.repeat(32),
      },
      traceback: '/private/secret',
    }), { status: 429, statusText: '/private/secret' })))

    const { result } = renderHook(() => useApi(), { wrapper: AigcProvider })
    await act(async () => { await result.current.call('/health') })

    expect(result.current.error).toBe(
      `Please try again shortly. (request ${'a'.repeat(32)})`,
    )
    expect(result.current.error).not.toContain('/private/')
    vi.unstubAllGlobals()
  })

  it('falls back without echoing an unknown response body', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      '{"detail":"/private/secret"}',
      { status: 500, statusText: '/private/secret' },
    )))

    const { result } = renderHook(() => useApi(), { wrapper: AigcProvider })
    await act(async () => { await result.current.call('/health') })

    expect(result.current.error).toBe('Request failed (500).')
    vi.unstubAllGlobals()
  })

  it('uses POST with Content-Type when body is provided', async () => {
    const mockFetch = vi.fn().mockResolvedValueOnce({ ok: true, json: async () => ({}) })
    vi.stubGlobal('fetch', mockFetch)

    const { result } = renderHook(() => useApi(), { wrapper: AigcProvider })
    await act(async () => { await result.current.call('/api/enforce', { scenario_key: 'test' }) })
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/enforce'),
      expect.objectContaining({ method: 'POST', headers: { 'Content-Type': 'application/json' } }),
    )
    vi.unstubAllGlobals()
  })

  it('calls addAudit when response contains a non-null artifact', async () => {
    const artifact = { enforcement_result: 'PASS', model_provider: 'mock', model_identifier: 'mock-model', role: 'doctor' }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce({ ok: true, json: async () => ({ artifact }) }))

    const { result } = renderHook(() => useApi(), { wrapper: AigcProvider })
    await act(async () => { await result.current.call('/api/enforce', {}) })
    // useAigc audit history should now contain the artifact
    vi.unstubAllGlobals()
  })

  it('ignores a stale response when a newer request finishes first', async () => {
    const slow = deferred<{ ok: boolean; json: () => Promise<{ status: string }> }>()
    const fast = deferred<{ ok: boolean; json: () => Promise<{ status: string }> }>()
    vi.stubGlobal('fetch', vi.fn()
      .mockReturnValueOnce(slow.promise)
      .mockReturnValueOnce(fast.promise))

    const { result } = renderHook(() => useApi<{ status: string }>(), { wrapper: AigcProvider })

    let slowResult: { status: string } | null = null
    let fastResult: { status: string } | null = null
    let slowPromise!: Promise<{ status: string } | null>
    let fastPromise!: Promise<{ status: string } | null>

    await act(async () => {
      slowPromise = result.current.call('/slow')
      fastPromise = result.current.call('/fast')
    })

    fast.resolve({ ok: true, json: async () => ({ status: 'new' }) })
    await act(async () => {
      fastResult = await fastPromise
    })

    slow.resolve({ ok: true, json: async () => ({ status: 'old' }) })
    await act(async () => {
      slowResult = await slowPromise
    })

    expect(fastResult).toEqual({ status: 'new' })
    expect(slowResult).toBeNull()
    expect(result.current.loading).toBe(false)
    expect(result.current.error).toBeNull()
    vi.unstubAllGlobals()
  })

  it('aborts an in-flight request on unmount without surfacing an error', async () => {
    let signal: AbortSignal | undefined
    const mockFetch = vi.fn((_url: string, init?: RequestInit) => {
      signal = init?.signal ?? undefined
      return new Promise((_resolve, reject) => {
        signal?.addEventListener('abort', () => {
          reject(new DOMException('The operation was aborted.', 'AbortError'))
        })
      })
    })
    vi.stubGlobal('fetch', mockFetch)

    const { result, unmount } = renderHook(() => useApi<{ status: string }>(), {
      wrapper: AigcProvider,
    })

    let pending!: Promise<{ status: string } | null>
    await act(async () => {
      pending = result.current.call('/slow')
    })

    unmount()

    let data: { status: string } | null = { status: 'unexpected' }
    await act(async () => {
      data = await pending
    })

    expect(signal?.aborted).toBe(true)
    expect(data).toBeNull()
    vi.unstubAllGlobals()
  })
})
