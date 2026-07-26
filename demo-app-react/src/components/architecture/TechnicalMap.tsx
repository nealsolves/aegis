import { useEffect, useState } from 'react'
import { useTheme } from '@/theme/ThemeContext'
import type { ArchitectureDetail } from './ArchitectureDetailPanel'

type DiagramMode = 'component' | 'pipeline'

const TECHNICAL_GROUPS: readonly {
  title: string
  description: string
  items: readonly ArchitectureDetail[]
}[] = [
  {
    title: 'Host-owned execution',
    description: 'Execution stays in the application, even when AEGIS governs the call or workflow step.',
    items: [
      {
        id: 'host-runtime',
        title: 'Application runtime',
        responsibility: 'Run orchestration, provider and tool calls, transport, retries, and business state.',
        owner: 'Host application',
        publicSurface: 'Host code and provider/tool SDKs',
        nonOwner: 'Orchestration, model/provider calls, credentials, retries, tools, or business state.',
      },
    ],
  },
  {
    title: 'AEGIS governance',
    description: 'Deterministic policy, workflow coordination, and invocation enforcement wrap host actions.',
    items: [
      {
        id: 'policy-loading',
        title: 'Policy and loading',
        responsibility: 'Load, validate, cache, and compose policy contracts.',
        owner: 'AEGIS SDK',
        publicSurface: 'Policy YAML / FilePolicyLoader / PolicyCache',
        nonOwner: 'The host request, model runtime, or business-specific policy authorship.',
      },
      {
        id: 'workflow-governance',
        title: 'Workflow governance',
        responsibility: 'Track sequence, participants, budgets, approvals, lifecycle, and evidence correlation.',
        owner: 'AEGIS SDK',
        publicSurface: 'AEGIS.open_session(...) / GovernanceSession / SessionPreCallResult',
        nonOwner: 'Agent planning, task execution, provider calls, or tool loops.',
      },
      {
        id: 'invocation-kernel',
        title: 'Invocation governance',
        responsibility: 'Apply ordered pre-call and post-call gates around a host-owned action.',
        owner: 'AEGIS SDK',
        publicSurface: 'enforce_invocation(...) / enforce_pre_call(...) / enforce_post_call(...)',
        nonOwner: 'The action between split enforcement phases or the decision to retry it.',
      },
      {
        id: 'normalization-adapters',
        title: 'Optional adapters',
        responsibility: 'Normalize host-supplied Bedrock, A2A, or OpenAI Agents evidence.',
        owner: 'AEGIS SDK optional submodules',
        publicSurface: 'BedrockTraceAdapter / A2AAdapter / OpenAIAgentsAdapter',
        nonOwner: 'Provider clients, authentication, transport, remote sessions, or execution.',
      },
    ],
  },
  {
    title: 'Evidence and operations',
    description: 'Invocation and workflow evidence remain separate and are correlated additively.',
    items: [
      {
        id: 'invocation-artifact',
        title: 'Invocation artifact',
        responsibility: 'Record PASS or FAIL evidence for every governed invocation attempt.',
        owner: 'AEGIS SDK',
        publicSurface: 'Invocation audit artifact',
        nonOwner: 'The provider response, host retry decision, or external retention destination.',
      },
      {
        id: 'workflow-artifact',
        title: 'Workflow artifact',
        responsibility: 'Record separate session lifecycle and step-checksum evidence.',
        owner: 'GovernanceSession',
        publicSurface: 'Workflow artifact',
        nonOwner: 'Invocation evidence, agent execution, or the host workflow engine.',
      },
      {
        id: 'operator-tooling',
        title: 'Operator tooling',
        responsibility: 'Trace and export stored invocation and workflow evidence for operators.',
        owner: 'AEGIS CLI',
        publicSurface: 'aegis workflow trace / aegis workflow export',
        nonOwner: 'Evidence storage access, organizational retention, or audit authorization.',
      },
    ],
  },
] as const

function useMobileTechnicalMap() {
  const query = '(max-width: 47.999rem)'
  const [isMobile, setIsMobile] = useState(() => (
    typeof window !== 'undefined' && typeof window.matchMedia === 'function'
      ? window.matchMedia(query).matches
      : false
  ))

  useEffect(() => {
    if (typeof window.matchMedia !== 'function') return undefined
    const media = window.matchMedia(query)
    const update = () => setIsMobile(media.matches)
    update()
    media.addEventListener('change', update)
    return () => media.removeEventListener('change', update)
  }, [])

  return isMobile
}

function MobileTechnicalCards({
  selectedNodeId,
  onSelect,
}: {
  selectedNodeId: string | null
  onSelect: (detail: ArchitectureDetail) => void
}) {
  return (
    <div className="technical-map__mobile" data-testid="technical-map-mobile">
      {TECHNICAL_GROUPS.map((group) => (
        <section key={group.title} className="technical-group">
          <div>
            <h3>{group.title}</h3>
            <p>{group.description}</p>
          </div>
          <div className="technical-group__cards">
            {group.items.map((item) => (
              <button
                type="button"
                key={item.id}
                aria-pressed={selectedNodeId === item.id}
                onClick={() => onSelect(item)}
              >
                <strong>{item.title}</strong>
                <span>{item.responsibility}</span>
              </button>
            ))}
          </div>
        </section>
      ))}
    </div>
  )
}

export default function TechnicalMap({
  selectedNodeId,
  onSelect,
}: {
  selectedNodeId: string | null
  onSelect: (detail: ArchitectureDetail) => void
}) {
  const { theme } = useTheme()
  const isMobile = useMobileTechnicalMap()
  const [mode, setMode] = useState<DiagramMode>('component')
  const [imageFailed, setImageFailed] = useState(false)
  const base = import.meta.env.BASE_URL

  if (isMobile) {
    return <MobileTechnicalCards selectedNodeId={selectedNodeId} onSelect={onSelect} />
  }

  const isComponent = mode === 'component'
  const src = `${base}diagrams/${
    isComponent
      ? `aegis_architecture_component${theme === 'dark' ? '' : '_light'}.svg`
      : `aegis_architecture_pipeline${theme === 'dark' ? '' : '_light'}.svg`
  }`
  const alt = isComponent
    ? 'AEGIS v0.9 beta component architecture'
    : 'AEGIS v0.9 beta enforcement pipeline'
  const summary = isComponent
    ? 'Host execution remains outside AEGIS. AEGIS governs policy, workflow, and invocations through optional normalization adapters, then emits separate invocation and workflow evidence.'
    : 'Phase A authorizes before the host call. The host performs one model or tool action. Phase B validates output and emits invocation evidence with separate workflow correlation.'

  return (
    <div className="technical-map__desktop" data-testid="technical-map-desktop">
      <div className="technical-map__toolbar" aria-label="Technical diagram">
        <button
          type="button"
          aria-pressed={isComponent}
          onClick={() => {
            setMode('component')
            setImageFailed(false)
          }}
        >
          Component view
        </button>
        <button
          type="button"
          aria-pressed={!isComponent}
          onClick={() => {
            setMode('pipeline')
            setImageFailed(false)
          }}
        >
          Enforcement pipeline
        </button>
      </div>
      <p id="technical-map-summary" className="sr-only">{summary}</p>
      <div className="technical-map__diagram">
        {imageFailed ? (
          <p role="status">{alt} unavailable</p>
        ) : (
          <img
            src={src}
            alt={alt}
            aria-describedby="technical-map-summary"
            onError={() => setImageFailed(true)}
          />
        )}
      </div>
      <section className="technical-map__index" aria-labelledby="technical-map-index-heading">
        <div>
          <p className="architecture-kicker">Inspect a boundary</p>
          <h3 id="technical-map-index-heading">Technical responsibilities</h3>
        </div>
        <div>
          {TECHNICAL_GROUPS.flatMap((group) => group.items).map((item) => (
            <button
              type="button"
              key={item.id}
              aria-pressed={selectedNodeId === item.id}
              onClick={() => onSelect(item)}
            >
              {item.title}
            </button>
          ))}
        </div>
      </section>
    </div>
  )
}
