import {
  ARCHITECTURE_DETAIL_PANEL_ID,
  type ArchitectureDetail,
} from './ArchitectureDetailPanel'

const OWNERSHIP_NODES: readonly ArchitectureDetail[] = [
  {
    id: 'host-request',
    title: 'Host request',
    responsibility: 'Provide the input, context, policy reference, and workflow-step intent.',
    owner: 'Host application',
    publicSurface: 'Invocation input / GovernanceSession step input',
    nonOwner: 'Request creation, business intent, transport, or orchestration.',
  },
  {
    id: 'pre-call-policy',
    title: 'AEGIS pre-call policy',
    responsibility: 'Load policy and authorize the invocation or workflow step before execution.',
    owner: 'AEGIS SDK',
    publicSurface: 'enforce_pre_call(...) / GovernanceSession.enforce_pre_call(...)',
    nonOwner: 'Provider clients, credentials, retries, model execution, or tool execution.',
  },
  {
    id: 'host-action',
    title: 'One model call or workflow step',
    responsibility: 'Execute the approved provider call, tool action, or host workflow step.',
    owner: 'Host application',
    publicSurface: 'Host provider SDK / tool runtime / orchestration code',
    nonOwner: 'The model call, agent loop, transport, retry behavior, tools, or business state.',
  },
  {
    id: 'post-call-policy',
    title: 'AEGIS post-call policy',
    responsibility: 'Validate the host-supplied output through ordered output and risk gates.',
    owner: 'AEGIS SDK',
    publicSurface: 'enforce_post_call(...) / GovernanceSession.enforce_post_call(...)',
    nonOwner: 'Output generation, provider response transport, or retry decisions.',
  },
  {
    id: 'result',
    title: 'Result',
    responsibility: 'Return the governed outcome to the application for host-controlled use.',
    owner: 'Host application',
    publicSurface: 'Host response / governed step result',
    nonOwner: 'Application rendering, downstream business logic, or result storage.',
  },
  {
    id: 'evidence',
    title: 'Evidence',
    responsibility: 'Emit invocation evidence and, when a session is used, separate workflow evidence.',
    owner: 'AEGIS SDK',
    publicSurface: 'Invocation artifact / workflow artifact / AuditSink',
    nonOwner: 'The host audit destination, retention policy, or operator access controls.',
  },
] as const

interface OwnershipFlowProps {
  selectedNodeId: string | null
  onSelect: (nodeId: string) => void
  onDetail?: (
    detail: ArchitectureDetail,
    trigger: HTMLButtonElement,
  ) => void
}

function FlowNode({
  node,
  selected,
  onSelect,
}: {
  node: ArchitectureDetail
  selected: boolean
  onSelect: (nodeId: string, trigger: HTMLButtonElement) => void
}) {
  const owner = node.owner === 'AEGIS SDK' ? 'AEGIS governs' : 'Host owns'
  return (
    <button
      type="button"
      className={`ownership-flow__node ownership-flow__node--${node.owner === 'AEGIS SDK' ? 'aegis' : 'host'}`}
      data-flow-node={node.id}
      aria-pressed={selected}
      aria-controls={ARCHITECTURE_DETAIL_PANEL_ID}
      aria-expanded={selected}
      onClick={(event) => onSelect(node.id, event.currentTarget)}
    >
      <span>{owner}</span>
      <strong>{node.title}</strong>
    </button>
  )
}

function ConnectorLane({ from, to }: { from: string; to: string }) {
  return (
    <div
      className="ownership-flow__lane"
      data-connector-lane=""
      data-from={from}
      data-to={to}
      aria-hidden="true"
    >
      <span />
    </div>
  )
}

function VerticalConnectorLane({ from, to }: { from: string; to: string }) {
  return (
    <div
      className="ownership-flow__lane ownership-flow__lane--vertical"
      data-vertical-connector-lane=""
      data-orientation="vertical"
      data-from={from}
      data-to={to}
      aria-hidden="true"
    >
      <span />
    </div>
  )
}

function FlowSequence({
  mobile,
  selectedNodeId,
  onSelect,
  onDetail,
}: OwnershipFlowProps & { mobile: boolean }) {
  const children = OWNERSHIP_NODES.flatMap((node, index) => {
    const flowNode = (
      <FlowNode
        key={node.id}
        node={node}
        selected={selectedNodeId === node.id}
        onSelect={(nodeId, trigger) => {
          onSelect(nodeId)
          onDetail?.(node, trigger)
        }}
      />
    )
    const next = OWNERSHIP_NODES[index + 1]
    if (!next) return [flowNode]
    const connector = mobile ? (
      <VerticalConnectorLane key={`${node.id}-${next.id}`} from={node.id} to={next.id} />
    ) : (
      <ConnectorLane key={`${node.id}-${next.id}`} from={node.id} to={next.id} />
    )
    return [flowNode, connector]
  })

  return (
    <div
      className={mobile ? 'ownership-flow__mobile' : 'ownership-flow__desktop'}
      data-testid={mobile ? 'ownership-flow-mobile' : 'ownership-flow-desktop'}
    >
      {children}
    </div>
  )
}

export default function OwnershipFlow({
  selectedNodeId,
  onSelect,
  onDetail,
}: OwnershipFlowProps) {
  return (
    <section className="ownership-flow" aria-labelledby="ownership-flow-heading">
      <div className="architecture-section-heading">
        <p className="architecture-kicker">Ownership sequence</p>
        <h2 id="ownership-flow-heading">One governed call, clearly owned</h2>
        <p>
          AEGIS brackets host execution with policy. It can govern an individual
          call or a step in an agentic workflow without becoming the agent runtime.
        </p>
      </div>
      <p id="ownership-flow-summary" data-testid="ownership-flow-summary" className="sr-only">
        A host request enters AEGIS pre-call policy. The host executes one model call
        or workflow step. AEGIS applies post-call policy. The host receives the result,
        and AEGIS emits evidence.
      </p>
      <div aria-describedby="ownership-flow-summary">
        <FlowSequence
          mobile={false}
          selectedNodeId={selectedNodeId}
          onSelect={onSelect}
          onDetail={onDetail}
        />
        <FlowSequence
          mobile
          selectedNodeId={selectedNodeId}
          onSelect={onSelect}
          onDetail={onDetail}
        />
      </div>
    </section>
  )
}
