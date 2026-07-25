import { useState, type ReactNode } from 'react'
import { useTheme } from '@/theme/ThemeContext'

export default function ArchitecturePage() {
  const { theme } = useTheme()

  const base = import.meta.env.BASE_URL
  const componentSvg = theme === 'dark'
    ? `${base}diagrams/aegis_architecture_component.svg`
    : `${base}diagrams/aegis_architecture_component_light.svg`

  const pipelineSvg = theme === 'dark'
    ? `${base}diagrams/aegis_architecture_pipeline.svg`
    : `${base}diagrams/aegis_architecture_pipeline_light.svg`

  return (
    <div className="px-5 py-10 sm:px-10 sm:py-12" style={{ maxWidth: 1200, margin: '0 auto' }}>
      <div
        className="font-mono font-semibold text-xs tracking-widest mb-2"
        style={{ color: 'var(--ibm-cyan-30)', textTransform: 'uppercase' }}
      >
        AEGIS v0.9 Beta
      </div>
      <div
        className="font-mono text-sm sm:text-base mb-3"
        style={{ color: 'var(--text-primary)' }}
      >
        aegis-ai-governance==0.9.0b1
      </div>
      <p className="text-sm leading-relaxed mb-7" style={{ color: 'var(--text-secondary)', maxWidth: 760 }}>
        The public beta is released from main and published on PyPI.
        Read the architecture as an ownership contract: the host executes,
        AEGIS governs, and separate evidence proves what happened.
      </p>

      <div
        className="grid grid-cols-1 sm:grid-cols-3 mb-14"
        style={{
          border: '1px solid var(--border-ui)',
          borderRadius: 10,
          overflow: 'hidden',
          background: 'var(--bg-surface)',
        }}
        aria-label="Architecture ownership rail"
      >
        <OwnershipStep label="Host executes" detail="orchestration · provider · tools" />
        <OwnershipStep label="AEGIS governs" detail="policy · workflow · invocation" />
        <OwnershipStep label="Evidence proves" detail="invocation · workflow · export" last />
      </div>

      <DiagramSection
        num="01"
        title="Component View"
        description="The current public beta boundary: host-owned execution, workflow and invocation governance, optional normalization adapters, and separate evidence outputs."
        summary="Host-controlled execution remains outside AEGIS. AEGIS governs policy, workflow, and invocations through optional Bedrock, A2A, and OpenAI Agents adapters, then emits separate invocation and workflow evidence."
        src={componentSvg}
        alt="AEGIS v0.9 beta component architecture"
      />

      <DiagramSection
        num="02"
        title="Enforcement Pipeline"
        description="Phase A authorizes before the host call. Phase B validates output, emits an invocation artifact, and lets the owning GovernanceSession correlate separate workflow evidence."
        summary="Phase A authorizes before the host model call. Phase B applies ordered output gates, emits an invocation artifact, and records workflow correlation."
        src={pipelineSvg}
        alt="AEGIS v0.9 beta enforcement pipeline"
      />

      <div>
        <SectionHeader num="03" title="Key Boundaries" />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-5">
          <NoteCard label="Host Ownership">
            The host owns orchestration, provider SDKs, credentials, transport,
            retries, model calls, tool execution, and business state. AEGIS
            does not become a hosted runtime or agent orchestrator.
          </NoteCard>
          <NoteCard label="Workflow Governance">
            <Code>AEGIS.open_session(...)</Code> creates a
            <Code>GovernanceSession</Code> for step sequence, participants,
            budgets, approvals, handoffs, lifecycle, and correlation.
          </NoteCard>
          <NoteCard label="Invocation Enforcement">
            Since v0.3.3, <Code>@governed</Code> defaults to split enforcement.
            The host call sits between <Code>post_authorization</Code> and
            <Code>pre_output</Code>. Use <Code>pre_call_enforcement=False</Code>
            only for the deprecated unified opt-out.
          </NoteCard>
          <NoteCard label="Optional Adapters">
            Bedrock, A2A, and OpenAI Agents are optional normalization
            submodules. They validate host-supplied evidence; they do not own
            provider clients, transports, credentials, or execution.
          </NoteCard>
          <NoteCard label="Evidence Separation">
            Every governed attempt emits an invocation artifact. A session emits
            a separate workflow artifact with step checksums and lifecycle
            evidence. Correlation is additive; one artifact never replaces the
            other.
          </NoteCard>
          <NoteCard label="Public API Boundary">
            Packaged beta surfaces include <Code>GovernanceSession</Code>,
            <Code>SessionPreCallResult</Code>, workflow CLI commands, and adapter
            submodules. <Code>ValidatorHook</Code> is internal;
            <Code>AgentIdentity</Code> and <Code>AgentCapabilityManifest</Code>
            are not current public types.
          </NoteCard>
          <NoteCard label="Signing and AuditChain">
            Signing is opt-in and occurs before sink emission.
            <Code>AuditChain</Code> is also opt-in and host-applied after
            enforcement; neither changes the governance decision or gate order.
          </NoteCard>
          <NoteCard label="Operator Tooling">
            <Code>aegis workflow trace</Code> reconstructs timelines and evidence
            gaps. <Code>aegis workflow export</Code> creates operator or
            audit-focused projections from stored invocation and workflow
            artifacts.
          </NoteCard>
        </div>
      </div>
    </div>
  )
}

function OwnershipStep({ label, detail, last = false }: {
  label: string
  detail: string
  last?: boolean
}) {
  return (
    <div
      className={`px-5 py-4 ${last ? '' : 'border-b sm:border-b-0 sm:border-r'}`}
      style={{ borderColor: 'var(--border-ui)', minWidth: 0 }}
    >
      <div
        className="font-mono text-[11px] font-bold tracking-widest uppercase mb-1"
        style={{ color: 'var(--ibm-cyan-30)' }}
      >
        {label}
      </div>
      <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>
        {detail}
      </div>
    </div>
  )
}

function DiagramSection({ num, title, description, summary, src, alt }: {
  num: string
  title: string
  description: string
  summary: string
  src: string
  alt: string
}) {
  const [imgError, setImgError] = useState(false)
  const summaryId = `diagram-${num}-summary`

  return (
    <div className="mb-16">
      <SectionHeader num={num} title={title} />
      <p
        className="text-xs mb-5"
        style={{ color: 'var(--text-secondary)', marginLeft: 40 }}
      >
        {description}
      </p>
      <p id={summaryId} className="sr-only">
        {summary}
      </p>
      <div
        style={{
          background: 'var(--bg-base)',
          border: '1px solid var(--border-ui)',
          borderRadius: 12,
          padding: 16,
          overflowX: 'auto',
        }}
      >
        {imgError ? (
          <div
            style={{
              padding: 32,
              textAlign: 'center',
              color: 'var(--text-secondary)',
              fontFamily: '"IBM Plex Mono", monospace',
              fontSize: 12,
              border: '1px dashed var(--border-ui)',
              borderRadius: 8,
            }}
          >
            {alt} unavailable
          </div>
        ) : (
          <img
            src={src}
            alt={alt}
            aria-describedby={summaryId}
            style={{ width: '100%', height: 'auto', display: 'block' }}
            onError={() => setImgError(true)}
          />
        )}
      </div>
    </div>
  )
}

function SectionHeader({ num, title }: { num: string; title: string }) {
  return (
    <div
      className="flex items-baseline gap-4 mb-6 pb-4"
      style={{ borderBottom: '1px solid var(--border-ui)' }}
    >
      <span
        className="font-mono font-bold text-[11px] tracking-widest"
        style={{ color: 'var(--ibm-cyan-30)', minWidth: 24 }}
      >
        {num}
      </span>
      <span className="text-xl font-semibold" style={{ color: 'var(--text-primary)' }}>
        {title}
      </span>
    </div>
  )
}

function NoteCard({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div
      style={{
        background: 'var(--bg-surface)',
        border: '1px solid var(--border-ui)',
        borderRadius: 8,
        padding: '20px 24px',
      }}
    >
      <div
        className="font-mono font-bold text-[11px] tracking-widest uppercase mb-2"
        style={{ color: 'var(--ibm-cyan-30)' }}
      >
        {label}
      </div>
      <p className="text-[13px] leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
        {children}
      </p>
    </div>
  )
}

function Code({ children }: { children: ReactNode }) {
  return (
    <code
      className="font-mono text-[12px]"
      style={{
        color: 'var(--ibm-cyan-30)',
        background: 'rgba(130,207,255,0.1)',
        padding: '1px 5px',
        borderRadius: 3,
      }}
    >
      {children}
    </code>
  )
}
