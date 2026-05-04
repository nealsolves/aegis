import { useState, useCallback, useEffect, useRef } from 'react'
import { useAigc } from '@/context/AigcContext'
import type { Artifact } from '@/types/artifact'

export function useApi<T = unknown>() {
  const { apiUrl, addAudit } = useAigc()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const requestGeneration = useRef(0)
  const isMounted = useRef(true)
  const abortController = useRef<AbortController | null>(null)

  useEffect(() => {
    isMounted.current = true
    return () => {
      isMounted.current = false
      // Cancel any in-flight requests on unmount
      abortController.current?.abort()
    }
  }, [])

  const call = useCallback(async (path: string, body?: unknown): Promise<T | null> => {
    const generation = ++requestGeneration.current

    // Cancel any previous in-flight request
    abortController.current?.abort()
    const controller = new AbortController()
    abortController.current = controller

    setLoading(true)
    setError(null)

    try {
      const isGet = body === undefined
      const res = await fetch(`${apiUrl}${path}`, {
        method: isGet ? 'GET' : 'POST',
        headers: isGet ? {} : { 'Content-Type': 'application/json' },
        body: isGet ? undefined : JSON.stringify(body),
        signal: controller.signal,
      })
      if (!res.ok) throw new Error(`API error: ${res.status} ${res.statusText}`)
      const data = await res.json() as T

      // Only discard if a newer request was made (race condition)
      if (!isMounted.current || generation !== requestGeneration.current) {
        return null
      }

      if (data && typeof data === 'object' && 'artifact' in (data as object)) {
        const artifact = (data as unknown as { artifact: Artifact | null }).artifact
        // Only add invocation audit artifacts (those with enforcement_result).
        // Workflow artifacts from /api/workflow/v090/run have a different shape
        // (status/steps) and must not be mixed into the invocation audit history.
        if (artifact && 'enforcement_result' in artifact) addAudit(artifact)
      }
      return data
    } catch (err) {
      // Don't set error if request was aborted (component unmounted)
      if (err instanceof Error && err.name === 'AbortError') {
        return null
      }
      if (isMounted.current && generation === requestGeneration.current) {
        setError(err instanceof Error ? err.message : String(err))
      }
      return null
    } finally {
      if (isMounted.current && generation === requestGeneration.current) {
        setLoading(false)
      }
    }
  }, [apiUrl, addAudit])

  return { call, loading, error }
}
