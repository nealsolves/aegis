import {
  Check,
  CircleMinus,
  Download,
  FileJson,
  Link as LinkIcon,
  Pause,
  X,
} from 'lucide-react'
import type {
  DemoGateResult,
  DemoOutcome,
  ScenarioRunResponse,
} from '@/types/demo'
import type { ScenarioId } from './scenarioContent'

interface ScenarioTimelineProps {
  response: ScenarioRunResponse | null
  scenarioId: ScenarioId
}

interface ChecksumRelationship {
  stepId: string
  checksum: string
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function humanize(value: string) {
  return value.replace(/_/g, ' ')
}

function outcomePresentation(outcome: DemoOutcome | null) {
  switch (outcome) {
    case 'PASS':
      return {
        className: 'scenario-state--pass',
        icon: Check,
        label: 'Pass',
        text: 'The returned evaluation passed.',
      }
    case 'FAIL':
      return {
        className: 'scenario-state--fail',
        icon: X,
        label: 'Fail',
        text: 'The returned evaluation failed.',
      }
    case 'PAUSED':
      return {
        className: 'scenario-state--paused',
        icon: Pause,
        label: 'Paused',
        text: 'The returned evaluation paused the workflow.',
      }
    default:
      return {
        className: 'scenario-state--unevaluated',
        icon: CircleMinus,
        label: 'Not evaluated',
        text: 'This gate was not evaluated in the returned run.',
      }
  }
}

function OutcomeState({
  outcome,
}: {
  outcome: DemoOutcome | null
}) {
  const state = outcomePresentation(outcome)
  const Icon = state.icon

  return (
    <div className={`scenario-state ${state.className}`}>
      <Icon aria-hidden="true" />
      <span>
        <strong>{state.label}</strong>
        <span>{state.text}</span>
      </span>
    </div>
  )
}

function GateStep({ gate, index }: { gate: DemoGateResult; index: number }) {
  return (
    <li className="scenario-gate">
      <div className="scenario-gate__marker" aria-hidden="true">
        {index + 1}
      </div>
      <div className="scenario-gate__body">
        <div className="scenario-gate__heading">
          <div>
            <span className="scenario-gate__phase">{humanize(gate.phase)}</span>
            <strong data-testid="gate-name">{humanize(gate.name)}</strong>
          </div>
          <OutcomeState outcome={gate.evaluated ? gate.outcome : null} />
        </div>
        {gate.reason_code && (
          <p className="scenario-reason">
            <span>Reason code</span>
            <code>{gate.reason_code}</code>
          </p>
        )}
      </div>
    </li>
  )
}

function checksumRelationships(
  artifact: Record<string, unknown> | null,
  workflowArtifact: Record<string, unknown> | null,
): ChecksumRelationship[] {
  if (!artifact || !workflowArtifact || !Array.isArray(workflowArtifact.steps)) {
    return []
  }

  if (
    Array.isArray(artifact.invocation_artifacts)
    && isRecord(artifact.trace)
    && Array.isArray(artifact.trace.steps)
  ) {
    const resolvedTraceReferences = new Set(
      artifact.trace.steps.flatMap((step) => {
        if (
          !isRecord(step)
          || step.resolved !== true
          || typeof step.step_id !== 'string'
          || typeof step.invocation_artifact_checksum !== 'string'
        ) {
          return []
        }

        return [`${step.step_id}:${step.invocation_artifact_checksum}`]
      }),
    )

    return workflowArtifact.steps.flatMap((step) => {
      if (
        !isRecord(step)
        || typeof step.step_id !== 'string'
        || typeof step.invocation_artifact_checksum !== 'string'
      ) {
        return []
      }

      if (
        !resolvedTraceReferences.has(
          `${step.step_id}:${step.invocation_artifact_checksum}`,
        )
      ) {
        return []
      }

      return [{
        stepId: step.step_id,
        checksum: step.invocation_artifact_checksum,
      }]
    })
  }

  if (!isRecord(artifact.context) || typeof artifact.context.step_id !== 'string') {
    return []
  }
  const invocationStepId = artifact.context.step_id

  return workflowArtifact.steps.flatMap((step) => {
    if (
      !isRecord(step)
      || typeof step.step_id !== 'string'
      || step.step_id !== invocationStepId
      || typeof step.invocation_artifact_checksum !== 'string'
    ) {
      return []
    }

    return [{
      stepId: step.step_id,
      checksum: step.invocation_artifact_checksum,
    }]
  })
}

function ArtifactCard({
  artifact,
  title,
  description,
  downloadLabel = 'Download invocation artifact',
  onDownload,
}: {
  artifact: Record<string, unknown>
  title: string
  description: string
  downloadLabel?: string
  onDownload?: () => void
}) {
  return (
    <article className="scenario-artifact">
      <div className="scenario-artifact__heading">
        <FileJson aria-hidden="true" />
        <div>
          <h3>{title}</h3>
          <p>{description}</p>
        </div>
      </div>
      {onDownload && (
        <button type="button" onClick={onDownload}>
          <Download aria-hidden="true" />
          {downloadLabel}
        </button>
      )}
      <details>
        <summary>Inspect returned JSON</summary>
        <pre>{JSON.stringify(artifact, null, 2)}</pre>
      </details>
    </article>
  )
}

function downloadArtifact(response: ScenarioRunResponse) {
  if (!response.artifact) return

  const blob = new Blob([JSON.stringify(response.artifact, null, 2)], {
    type: 'application/json',
  })
  const objectUrl = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = objectUrl
  anchor.download = `${response.scenario_id}-${response.variant}-artifact.json`

  try {
    anchor.click()
  } finally {
    URL.revokeObjectURL(objectUrl)
  }
}

export default function ScenarioTimeline({
  response,
  scenarioId,
}: ScenarioTimelineProps) {
  const announcedReason = response
    ? response.error?.code
      ?? response.gates.find(gate => gate.reason_code)?.reason_code
      ?? 'no reason code returned'
    : null
  const announcement = response
    ? `Scenario run complete. Decision: ${response.decision}. Reason: ${announcedReason}.`
    : 'No scenario run has completed.'

  if (!response) {
    return (
      <>
        <p
          className="sr-only"
          role="status"
          aria-live="polite"
          aria-atomic="true"
          data-testid="scenario-result-announcement"
        >
          {announcement}
        </p>
        <section
          className="scenario-region scenario-region--empty"
          aria-labelledby="scenario-evaluation-title"
        >
          <div className="scenario-region__label">03</div>
          <div>
            <h2 id="scenario-evaluation-title">AEGIS evaluation</h2>
            <p>Run your judgment to request an evaluation from the demo service.</p>
          </div>
        </section>
        <section
          className="scenario-region scenario-region--empty"
          aria-labelledby="scenario-evidence-title"
        >
          <div className="scenario-region__label">04</div>
          <div>
            <h2 id="scenario-evidence-title">Evidence</h2>
            <p>Returned evidence will appear here after the run finishes.</p>
          </div>
        </section>
      </>
    )
  }

  const relationships = scenarioId === 'meridian'
    ? checksumRelationships(response.artifact, response.workflow_artifact)
    : []
  const hasInvocationBundle = (
    scenarioId === 'meridian'
    && response.artifact
    && Array.isArray(response.artifact.invocation_artifacts)
  )
  const invocationCopy = hasInvocationBundle
    ? {
        title: 'Invocation evidence bundle',
        description: 'Invocation artifacts, trace, and export returned together by the service.',
        downloadLabel: 'Download invocation evidence bundle',
      }
    : {
        title: 'Invocation artifact',
        description: 'Evidence for the governed invocation returned by the service.',
        downloadLabel: undefined,
      }

  return (
    <>
      <p
        className="sr-only"
        role="status"
        aria-live="polite"
        aria-atomic="true"
        data-testid="scenario-result-announcement"
      >
        {announcement}
      </p>
      <section
        className="scenario-region"
        aria-labelledby="scenario-evaluation-title"
      >
        <div className="scenario-region__label">03</div>
        <div>
          <h2 id="scenario-evaluation-title">AEGIS evaluation</h2>
          <p className="scenario-returned-label">
            Returned run · {humanize(response.variant)}
          </p>

          <div className="scenario-decision">
            <span>Overall decision</span>
            <OutcomeState outcome={response.decision} />
          </div>

          {response.error && (
            <div className="scenario-returned-error">
              <strong>{response.error.message}</strong>
              <p className="scenario-reason">
                <span>Reason code</span>
                <code>{response.error.code}</code>
              </p>
            </div>
          )}

          <div className="scenario-transcript">
            <h3>Returned transcript</h3>
            <ol>
              {response.transcript.map((entry, index) => (
                <li key={`${entry.speaker}-${index}`}>
                  <strong>{entry.speaker}</strong>
                  <p>{entry.text}</p>
                </li>
              ))}
            </ol>
          </div>

          <div className="scenario-gates">
            <h3>Gate timeline</h3>
            <ol>
              {response.gates.map((gate, index) => (
                <GateStep
                  gate={gate}
                  index={index}
                  key={`${gate.phase}-${gate.name}-${index}`}
                />
              ))}
            </ol>
          </div>
        </div>
      </section>

      <section
        className="scenario-region"
        aria-labelledby="scenario-evidence-title"
      >
        <div className="scenario-region__label">04</div>
        <div>
          <h2 id="scenario-evidence-title">Evidence</h2>
          <p className="scenario-returned-label">
            Evidence returned by the current run
          </p>

          {!response.artifact && !response.workflow_artifact && (
            <p className="scenario-evidence-empty">
              This response did not include an evidence artifact.
            </p>
          )}

          <div className="scenario-evidence-grid">
            {response.artifact && (
              <ArtifactCard
                artifact={response.artifact}
                title={invocationCopy.title}
                description={invocationCopy.description}
                downloadLabel={invocationCopy.downloadLabel}
                onDownload={() => downloadArtifact(response)}
              />
            )}
            {response.workflow_artifact && (
              <ArtifactCard
                artifact={response.workflow_artifact}
                title="Workflow artifact"
                description="Workflow-level evidence returned separately by the service."
              />
            )}
          </div>

          {relationships.length > 0 && (
            <div className="scenario-checksum-links">
              <div className="scenario-checksum-links__heading">
                <LinkIcon aria-hidden="true" />
                <div>
                  <h3>Returned artifact relationships</h3>
                  <p>
                    {hasInvocationBundle
                      ? 'The returned trace resolves each workflow reference to invocation evidence by the same returned checksum.'
                      : 'The returned workflow links this invocation evidence by its matching returned step ID and supplies its checksum.'}
                  </p>
                </div>
              </div>
              <ol>
                {relationships.map((relationship, index) => (
                  <li key={`${relationship.stepId}-${index}`}>
                    <span>{humanize(relationship.stepId)}</span>
                    <code>{relationship.checksum}</code>
                  </li>
                ))}
              </ol>
            </div>
          )}
        </div>
      </section>
    </>
  )
}
