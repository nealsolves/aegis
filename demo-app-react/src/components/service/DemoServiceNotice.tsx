import { useDemoService } from '@/context/DemoServiceContext'
import { demoServiceNoticeCopy } from '@/content/demoCopy'

export function DemoServiceNotice() {
  const { status, error, retry } = useDemoService()

  if (status === 'checking' || status === 'ready') return null

  if (status === 'starting') {
    return (
      <div className="demo-service-notice" role="status" aria-live="polite">
        <div className="demo-service-notice__content">
          {demoServiceNoticeCopy.starting}
        </div>
      </div>
    )
  }

  if (status === 'mismatch') {
    return (
      <div className="demo-service-notice" role="status" aria-live="polite">
        <div className="demo-service-notice__content">
          {demoServiceNoticeCopy.mismatch(
            error?.frontendContractVersion,
            error?.backendContractVersion,
          )}
        </div>
      </div>
    )
  }

  return (
    <div className="demo-service-notice" role="status" aria-live="polite">
      <div className="demo-service-notice__content">
        <p>{demoServiceNoticeCopy.unavailable(error?.operation)}</p>
        <button type="button" onClick={retry}>
          {demoServiceNoticeCopy.retry}
        </button>
      </div>
    </div>
  )
}
