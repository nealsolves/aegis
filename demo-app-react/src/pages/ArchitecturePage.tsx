import { useRef, useState, type KeyboardEvent } from 'react'
import ArchitectureDetailPanel, {
  type ArchitectureDetail,
} from '@/components/architecture/ArchitectureDetailPanel'
import OwnershipFlow from '@/components/architecture/OwnershipFlow'
import TechnicalMap from '@/components/architecture/TechnicalMap'

type ArchitectureView = 'how-it-works' | 'technical-map'

export default function ArchitecturePage() {
  const [view, setView] = useState<ArchitectureView>('how-it-works')
  const [selectedDetail, setSelectedDetail] = useState<ArchitectureDetail | null>(null)
  const howTabRef = useRef<HTMLButtonElement>(null)
  const technicalTabRef = useRef<HTMLButtonElement>(null)

  const handleTabKeyDown = (
    event: KeyboardEvent<HTMLButtonElement>,
    currentView: ArchitectureView,
  ) => {
    let nextView: ArchitectureView | null = null
    if (event.key === 'Home') {
      nextView = 'how-it-works'
    } else if (event.key === 'End') {
      nextView = 'technical-map'
    } else if (event.key === 'ArrowRight') {
      nextView = currentView === 'how-it-works' ? 'technical-map' : 'how-it-works'
    } else if (event.key === 'ArrowLeft') {
      nextView = currentView === 'how-it-works' ? 'technical-map' : 'how-it-works'
    }

    if (nextView === null) return
    event.preventDefault()
    setView(nextView)
    const nextTab = nextView === 'how-it-works' ? howTabRef : technicalTabRef
    nextTab.current?.focus()
  }

  return (
    <main className="architecture-page">
      <header className="architecture-hero">
        <p className="architecture-kicker">AEGIS v0.9 Beta</p>
        <h1>Architecture is an ownership contract.</h1>
        <p className="architecture-version">aegis-ai-governance==0.9.0b1</p>
        <p className="architecture-lead">
          The public beta is released from main and published on PyPI. The host
          executes. AEGIS governs each call or workflow step before and after
          that action. Separate evidence proves what happened.
        </p>
      </header>

      <div className="architecture-tabs" role="tablist" aria-label="Architecture views">
        <button
          type="button"
          role="tab"
          id="architecture-tab-how"
          aria-controls="architecture-panel-how"
          aria-selected={view === 'how-it-works'}
          tabIndex={view === 'how-it-works' ? 0 : -1}
          ref={howTabRef}
          onClick={() => setView('how-it-works')}
          onKeyDown={(event) => handleTabKeyDown(event, 'how-it-works')}
        >
          How it works
        </button>
        <button
          type="button"
          role="tab"
          id="architecture-tab-technical"
          aria-controls="architecture-panel-technical"
          aria-selected={view === 'technical-map'}
          tabIndex={view === 'technical-map' ? 0 : -1}
          ref={technicalTabRef}
          onClick={() => setView('technical-map')}
          onKeyDown={(event) => handleTabKeyDown(event, 'technical-map')}
        >
          Technical map
        </button>
      </div>

      {view === 'how-it-works' ? (
        <section
          id="architecture-panel-how"
          role="tabpanel"
          aria-labelledby="architecture-tab-how"
          className="architecture-panel"
        >
          <OwnershipFlow
            selectedNodeId={selectedDetail?.id ?? null}
            onSelect={() => undefined}
            onDetail={setSelectedDetail}
          />
        </section>
      ) : (
        <section
          id="architecture-panel-technical"
          role="tabpanel"
          aria-labelledby="architecture-tab-technical"
          className="architecture-panel"
        >
          <div className="architecture-section-heading">
            <p className="architecture-kicker">Generated source of truth</p>
            <h2>Technical map</h2>
            <p>
              Explore the current beta component boundary and the split
              enforcement pipeline. On phones, the same truth is grouped as
              readable semantic cards.
            </p>
          </div>
          <TechnicalMap
            selectedNodeId={selectedDetail?.id ?? null}
            onSelect={setSelectedDetail}
          />
        </section>
      )}

      {selectedDetail && (
        <ArchitectureDetailPanel
          detail={selectedDetail}
          onClose={() => setSelectedDetail(null)}
        />
      )}
    </main>
  )
}
