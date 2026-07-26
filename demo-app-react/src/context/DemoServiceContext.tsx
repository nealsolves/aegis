import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { useAigc } from '@/context/AigcContext'
import {
  demoRequest,
  DemoApiError,
  parseDemoHealth,
  parseDemoManifest,
} from '@/lib/demoApi'
import type { DemoManifest } from '@/types/demo'

const DEMO_API_CONTRACT_VERSION = '1' as const

const RETRY_DELAYS = [0, 1000, 2000, 4000, 8000, 15000, 30000] as const

export type DemoServiceStatus =
  | 'checking'
  | 'starting'
  | 'ready'
  | 'unavailable'
  | 'mismatch'

export type DemoServiceOperation = '/health' | '/api/demo/manifest'

export interface DemoServiceError {
  operation: DemoServiceOperation
  message: string
  status: number | null
  code: string | null
  frontendContractVersion?: typeof DEMO_API_CONTRACT_VERSION
  backendContractVersion?: string
}

export interface DemoServiceValue {
  status: DemoServiceStatus
  manifest: DemoManifest | null
  error: DemoServiceError | null
  retry: () => void
}

const DemoServiceContext = createContext<DemoServiceValue | null>(null)

const INITIAL_STATE: Omit<DemoServiceValue, 'retry'> = {
  status: 'checking',
  manifest: null,
  error: null,
}

function abortReason(signal: AbortSignal) {
  return signal.reason instanceof Error
    ? signal.reason
    : new DOMException('The operation was aborted.', 'AbortError')
}

function waitForDelay(milliseconds: number, signal: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    const timer = window.setTimeout(() => {
      signal.removeEventListener('abort', handleAbort)
      resolve()
    }, milliseconds)

    function handleAbort() {
      window.clearTimeout(timer)
      reject(abortReason(signal))
    }

    if (signal.aborted) {
      handleAbort()
      return
    }

    signal.addEventListener('abort', handleAbort, { once: true })
  })
}

function isAbortError(error: unknown) {
  return error instanceof DOMException && error.name === 'AbortError'
}

function requestError(
  operation: DemoServiceOperation,
  error: unknown,
): DemoServiceError {
  if (error instanceof DemoApiError) {
    return {
      operation,
      message: error.message,
      status: error.status,
      code: error.code,
    }
  }

  return {
    operation,
    message: error instanceof Error ? error.message : 'The request failed.',
    status: null,
    code: null,
  }
}

function mismatchError(
  operation: DemoServiceOperation,
  backendContractVersion: unknown,
): DemoServiceError {
  const backendVersion = typeof backendContractVersion === 'string'
    ? backendContractVersion
    : 'missing'

  return {
    operation,
    message: 'The frontend and backend API contracts are incompatible.',
    status: null,
    code: 'API_CONTRACT_MISMATCH',
    frontendContractVersion: DEMO_API_CONTRACT_VERSION,
    backendContractVersion: backendVersion,
  }
}

export function DemoServiceProvider({ children }: { children: ReactNode }) {
  const { apiUrl } = useAigc()
  const [state, setState] = useState(INITIAL_STATE)
  const mountedRef = useRef(false)
  const cycleRef = useRef(0)
  const controllerRef = useRef<AbortController | null>(null)

  const startReadinessCheck = useCallback(() => {
    const cycle = cycleRef.current + 1
    cycleRef.current = cycle
    controllerRef.current?.abort()

    const controller = new AbortController()
    controllerRef.current = controller
    setState(INITIAL_STATE)

    const isCurrent = () => (
      mountedRef.current
      && cycleRef.current === cycle
      && !controller.signal.aborted
    )

    void (async () => {
      for (let attempt = 0; attempt < RETRY_DELAYS.length; attempt += 1) {
        let operation: DemoServiceOperation = '/health'

        try {
          await waitForDelay(RETRY_DELAYS[attempt], controller.signal)

          const health = parseDemoHealth(await demoRequest<unknown>(
            apiUrl,
            '/health',
            { signal: controller.signal },
          ))
          if (!isCurrent()) return

          if (health.api_contract_version !== DEMO_API_CONTRACT_VERSION) {
            setState({
              status: 'mismatch',
              manifest: null,
              error: mismatchError('/health', health.api_contract_version),
            })
            return
          }

          if (health.status !== 'ok') {
            throw new Error(`Health check returned status ${health.status}.`)
          }

          operation = '/api/demo/manifest'
          const manifest = parseDemoManifest(await demoRequest<unknown>(
            apiUrl,
            '/api/demo/manifest',
            { signal: controller.signal },
          ))
          if (!isCurrent()) return

          if (manifest.api_contract_version !== DEMO_API_CONTRACT_VERSION) {
            setState({
              status: 'mismatch',
              manifest: null,
              error: mismatchError(
                '/api/demo/manifest',
                manifest.api_contract_version,
              ),
            })
            return
          }

          setState({
            status: 'ready',
            manifest,
            error: null,
          })
          return
        } catch (error) {
          if (isAbortError(error) || !isCurrent()) return

          const nextError = requestError(operation, error)
          const exhausted = attempt === RETRY_DELAYS.length - 1
          setState({
            status: exhausted ? 'unavailable' : 'starting',
            manifest: null,
            error: nextError,
          })
        }
      }
    })()
  }, [apiUrl])

  useEffect(() => {
    mountedRef.current = true
    startReadinessCheck()

    return () => {
      mountedRef.current = false
      cycleRef.current += 1
      controllerRef.current?.abort()
    }
  }, [startReadinessCheck])

  return (
    <DemoServiceContext.Provider
      value={{
        ...state,
        retry: startReadinessCheck,
      }}
    >
      {children}
    </DemoServiceContext.Provider>
  )
}

// Context modules intentionally colocate their provider and consumer hook.
// eslint-disable-next-line react-refresh/only-export-components
export function useDemoService(): DemoServiceValue {
  const context = useContext(DemoServiceContext)
  if (!context) {
    throw new Error('useDemoService must be used within DemoServiceProvider')
  }
  return context
}
