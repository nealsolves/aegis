import { useDemoService } from '@/context/DemoServiceContext'

const STARTING_COPY =
  'Starting the demo API. Render may need about a minute after a period of inactivity.'

export function DemoServiceNotice() {
  const { status, error, retry } = useDemoService()

  if (status === 'checking' || status === 'ready') return null

  if (status === 'starting') {
    return (
      <div role="status" aria-live="polite">
        {STARTING_COPY}
      </div>
    )
  }

  if (status === 'mismatch') {
    return (
      <div role="status" aria-live="polite">
        Demo API contract mismatch. Frontend contract{' '}
        {error?.frontendContractVersion ?? '1'};
        {' '}backend contract {error?.backendContractVersion ?? 'missing'}.
      </div>
    )
  }

  return (
    <div role="status" aria-live="polite">
      <p>
        The governance run did not complete because the{' '}
        {error?.operation ?? 'readiness check'} operation failed.
      </p>
      <button type="button" onClick={retry}>
        Retry
      </button>
    </div>
  )
}
